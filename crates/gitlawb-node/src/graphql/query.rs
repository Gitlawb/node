use async_graphql::{Context, Object, Result};
use std::sync::Arc;

use crate::db::Db;

use super::types::{AgentTaskType, RefUpdateType, RepoType};

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn repos(&self, ctx: &Context<'_>) -> Result<Vec<RepoType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();
        let repos = db
            .list_all_repos_deduped()
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;

        // Apply the same "/" visibility gate the REST/per-repo endpoints use so
        // this surface does not enumerate private repos (#97). The caller DID is
        // threaded onto the context by optional_signature; absent = anonymous.
        let caller = ctx
            .data::<crate::auth::AuthenticatedDid>()
            .ok()
            .map(|d| d.0.as_str());
        let ids: Vec<String> = repos.iter().map(|r| r.id.clone()).collect();
        let rules_by_repo = db
            .list_visibility_rules_for_repos(&ids)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;

        Ok(repos
            .into_iter()
            .filter(|r| {
                let rules = rules_by_repo.get(&r.id).map(Vec::as_slice).unwrap_or(&[]);
                crate::visibility::listable_at_root(rules, r.is_public, &r.owner_did, caller)
            })
            .map(|r| RepoType {
                name: r.name,
                owner_did: r.owner_did,
                description: r.description,
                default_branch: r.default_branch,
                created_at: r.created_at.to_rfc3339(),
            })
            .collect())
    }

    async fn ref_updates(
        &self,
        ctx: &Context<'_>,
        repo: Option<String>,
        #[graphql(default = 20)] limit: i64,
    ) -> Result<Vec<RefUpdateType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();
        let updates = db
            .list_ref_updates_filtered(repo.as_deref(), limit)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(updates
            .into_iter()
            .map(|u| RefUpdateType {
                repo: u.repo,
                ref_name: u.ref_name,
                old_sha: u.old_sha,
                new_sha: u.new_sha,
                pusher_did: u.pusher_did,
                node_did: u.node_did,
                timestamp: u.timestamp,
            })
            .collect())
    }

    async fn tasks(
        &self,
        ctx: &Context<'_>,
        status: Option<String>,
        assignee_did: Option<String>,
        #[graphql(default = 50)] limit: i64,
    ) -> Result<Vec<AgentTaskType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();
        let tasks = db
            .list_tasks(status.as_deref(), assignee_did.as_deref(), limit)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(tasks.into_iter().map(AgentTaskType::from).collect())
    }

    async fn task(&self, ctx: &Context<'_>, id: String) -> Result<Option<AgentTaskType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();
        let t = db
            .get_task(&id)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(t.map(AgentTaskType::from))
    }
}

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
        let mut updates = db
            .list_ref_updates_filtered(repo.as_deref(), limit)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;

        // Gate each row on the same "/" visibility decision the repos resolver
        // uses, so anonymous callers get no row for a local repo they can't read
        // (#112). Load the deduped local set + rules once; any DB error aborts
        // (fail closed, never serve). The row slug is peer-supplied, so the pure
        // filter treats it as untrusted input, not a lookup key. Applies to both
        // the repo:Some and repo:None branches — the filter runs on whatever
        // list_ref_updates_filtered returned. Remote (no local match) rows pass.
        let caller = ctx
            .data::<crate::auth::AuthenticatedDid>()
            .ok()
            .map(|d| d.0.as_str());
        let deduped = db
            .list_all_repos_deduped()
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        let ids: Vec<String> = deduped.iter().map(|r| r.id.clone()).collect();
        let rules = db
            .list_visibility_rules_for_repos(&ids)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        updates.retain(|u| {
            crate::visibility::ref_update_row_visible(&deduped, &rules, caller, &u.repo)
        });

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

#[cfg(test)]
mod tests {
    use crate::db::{Db, ReceivedRefUpdate, RepoRecord};
    use chrono::Utc;
    use sqlx::PgPool;
    use std::sync::Arc;

    const OWNER: &str = "did:key:z6MkOwner";

    async fn db(pool: PgPool) -> Arc<Db> {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        Arc::new(db)
    }

    fn schema(db: Arc<Db>) -> super::super::GitlawbSchema {
        let (ref_tx, _) = tokio::sync::broadcast::channel(16);
        let (task_tx, _) = tokio::sync::broadcast::channel(16);
        super::super::build_schema(db, ref_tx, task_tx)
    }

    fn repo(id: &str, owner_did: &str, name: &str, is_public: bool) -> RepoRecord {
        RepoRecord {
            id: id.into(),
            name: name.into(),
            owner_did: owner_did.into(),
            description: None,
            is_public,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: format!("/srv/{id}"),
            forked_from: None,
            machine_id: None,
        }
    }

    fn ref_row(id: &str, slug: &str) -> ReceivedRefUpdate {
        ReceivedRefUpdate {
            id: id.into(),
            node_did: "did:key:z6MkNode".into(),
            pusher_did: "did:key:z6MkPusher".into(),
            repo: slug.into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "a".repeat(40),
            timestamp: Utc::now().to_rfc3339(),
            cert_id: None,
            received_at: Utc::now().to_rfc3339(),
            from_peer: "peer1".into(),
        }
    }

    /// Count `refUpdates` rows in a GraphQL response.
    fn count(resp: &async_graphql::Response) -> usize {
        assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
        let async_graphql::Value::Object(obj) = &resp.data else {
            panic!("data not an object: {:?}", resp.data);
        };
        let async_graphql::Value::List(rows) = obj.get("refUpdates").expect("refUpdates key")
        else {
            panic!("refUpdates not a list");
        };
        rows.len()
    }

    async fn anon(schema: &super::super::GitlawbSchema, query: &str) -> async_graphql::Response {
        schema.execute(async_graphql::Request::new(query)).await
    }

    async fn authed(
        schema: &super::super::GitlawbSchema,
        query: &str,
        did: &str,
    ) -> async_graphql::Response {
        schema
            .execute(
                async_graphql::Request::new(query)
                    .data(crate::auth::AuthenticatedDid(did.to_string())),
            )
            .await
    }

    // Scenario 1 — anon must not get a private local repo's row on the
    // repo:Some branch. This is the load-bearing RED→GREEN case.
    #[sqlx::test]
    async fn ref_updates_private_repo_dropped_for_anon(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&repo("r1", OWNER, "widget", false))
            .await
            .unwrap();
        db.insert_ref_update(&ref_row("u1", "z6MkOwner/widget"))
            .await
            .unwrap();
        let schema = schema(db);
        // The GraphQL `repo` arg is the raw slug DB filter, so it must equal the
        // stored slug to select the row at all — this is the exact leak path.
        let q = r#"{ refUpdates(repo: "z6MkOwner/widget") { refName newSha pusherDid } }"#;
        assert_eq!(count(&anon(&schema, q).await), 0);
    }

    // Scenario 2 — owner still sees their own private repo's row.
    #[sqlx::test]
    async fn ref_updates_private_repo_kept_for_owner(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&repo("r1", OWNER, "widget", false))
            .await
            .unwrap();
        db.insert_ref_update(&ref_row("u1", "z6MkOwner/widget"))
            .await
            .unwrap();
        let schema = schema(db);
        let q = r#"{ refUpdates(repo: "z6MkOwner/widget") { refName } }"#;
        assert_eq!(count(&authed(&schema, q, OWNER).await), 1);
    }

    // Scenario 3 — unfiltered (repo:None): anon gets only the public row.
    #[sqlx::test]
    async fn ref_updates_unfiltered_anon_gets_only_public(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        db.create_repo(&repo("priv", OWNER, "secret", false))
            .await
            .unwrap();
        db.insert_ref_update(&ref_row("u_pub", "z6MkOwner/openrepo"))
            .await
            .unwrap();
        db.insert_ref_update(&ref_row("u_priv", "z6MkOwner/secret"))
            .await
            .unwrap();
        let schema = schema(db);
        let q = r#"{ refUpdates { repo refName } }"#;
        let resp = anon(&schema, q).await;
        assert_eq!(count(&resp), 1);
        // The one row returned must be the public repo's.
        let async_graphql::Value::Object(obj) = &resp.data else {
            unreachable!()
        };
        let async_graphql::Value::List(rows) = obj.get("refUpdates").unwrap() else {
            unreachable!()
        };
        let async_graphql::Value::Object(row) = &rows[0] else {
            unreachable!()
        };
        assert_eq!(
            row.get("repo").unwrap(),
            &async_graphql::Value::from("z6MkOwner/openrepo")
        );
    }

    // Scenario 4 — alias fail-closed: private repo's row stored full-DID form.
    #[sqlx::test]
    async fn ref_updates_full_did_slug_dropped_for_anon(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&repo("r1", "did:key:zABC", "widget", false))
            .await
            .unwrap();
        db.insert_ref_update(&ref_row("u1", "did:key:zABC/widget"))
            .await
            .unwrap();
        let schema = schema(db);
        // repo:None so the slug is not the DB filter key (which is verbatim);
        // the gate must still drop it.
        let q = r#"{ refUpdates { repo } }"#;
        assert_eq!(count(&anon(&schema, q).await), 0);
    }

    // Scenario 5 — truncated-key fail-closed: 8-char-prefix owner form.
    #[sqlx::test]
    async fn ref_updates_truncated_key_slug_dropped_for_anon(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&repo("r1", "did:key:zABCDEFGH", "widget", false))
            .await
            .unwrap();
        db.insert_ref_update(&ref_row("u1", "zABCDEF/widget"))
            .await
            .unwrap();
        let schema = schema(db);
        let q = r#"{ refUpdates { repo } }"#;
        assert_eq!(count(&anon(&schema, q).await), 0);
    }

    // Scenario 6 — remote slug (no local match) is returned to anon.
    #[sqlx::test]
    async fn ref_updates_remote_slug_kept_for_anon(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&repo("r1", OWNER, "widget", false))
            .await
            .unwrap();
        // Row whose slug matches no local repo (different owner + name).
        db.insert_ref_update(&ref_row("u1", "zZZZOTHER/gadget"))
            .await
            .unwrap();
        let schema = schema(db);
        let q = r#"{ refUpdates { repo } }"#;
        assert_eq!(count(&anon(&schema, q).await), 1);
    }
}

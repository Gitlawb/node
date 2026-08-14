use async_graphql::{Context, Object, Result};
use std::sync::Arc;

use crate::db::Db;

use super::types::{AgentTaskReadType, RefUpdateType, RepoType};

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn repos(&self, ctx: &Context<'_>) -> Result<Vec<RepoType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();
        let repos = db
            .list_all_repos_deduped()
            .await
            .map_err(crate::graphql::graphql_db_err)?;

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
            .map_err(crate::graphql::graphql_db_err)?;

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
        #[graphql(
            default = 20,
            desc = "Max 200; larger requests return the newest 200 rows (no continuation cursor)."
        )]
        limit: i64,
    ) -> Result<Vec<RefUpdateType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();

        // Gate each row on the same "/" visibility decision the repos resolver
        // uses, so anonymous callers get no row for a local repo they can't read
        // (#112). The shared collector applies the fail-closed gate *before* the
        // limit (paging past dropped private rows) so a small limit still returns
        // the latest visible events, and keeps this surface byte-identical to the
        // REST feed (#114). The row slug is peer-supplied, so the pure filter
        // treats it as untrusted input; remote (no local match) rows pass.
        let caller = ctx
            .data::<crate::auth::AuthenticatedDid>()
            .ok()
            .map(|d| d.0.as_str());
        let updates =
            crate::api::events::collect_visible_ref_updates(db, repo.as_deref(), limit, caller)
                .await
                .map_err(crate::graphql::graphql_app_err)?;

        // Resolve the trusted display owner_did per row, identical to the REST
        // feed: the stored wire value is untrusted, so it is echoed only when it
        // matches the canonical owner of the local repo the slug names (#P1);
        // legacy None rows are attributed via an exact unique local match (#P3).
        // The batch resolver issues at most one query per distinct local repo
        // rather than one per event row (#P2).
        let pairs: Vec<(&str, Option<&str>)> = updates
            .iter()
            .map(|u| (u.repo.as_str(), u.owner_did.as_deref()))
            .collect();
        let owner_dids = db
            .resolve_ref_update_owner_dids(&pairs)
            .await
            .map_err(crate::graphql::graphql_db_err)?;

        let resolved: Vec<RefUpdateType> = updates
            .into_iter()
            .zip(owner_dids)
            .map(|(u, owner_did)| RefUpdateType {
                repo: u.repo,
                ref_name: u.ref_name,
                old_sha: u.old_sha,
                new_sha: u.new_sha,
                pusher_did: u.pusher_did,
                node_did: u.node_did,
                timestamp: u.timestamp,
                owner_did,
            })
            .collect();
        Ok(resolved)
    }

    async fn tasks(
        &self,
        ctx: &Context<'_>,
        status: Option<String>,
        assignee_did: Option<String>,
        #[graphql(
            default = 50,
            desc = "Max 200; larger requests are clamped to 200 (no error). Negative values clamp to 0."
        )]
        limit: i64,
        after_created_at: Option<String>,
        after_id: Option<String>,
    ) -> Result<Vec<AgentTaskReadType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();
        // #268: gate rows via the same collector the REST list route uses (like
        // `ref_updates` shares `collect_visible_ref_updates` with its REST feed),
        // so the two surfaces cannot drift. The collector clamps `limit` itself,
        // including the negative-LIMIT case #250 called out for this resolver.
        let caller = ctx
            .data::<crate::auth::AuthenticatedDid>()
            .ok()
            .map(|d| d.0.as_str());
        let after = after_created_at.as_deref().zip(after_id.as_deref());
        let result = crate::api::tasks::collect_visible_tasks(
            db,
            status.as_deref(),
            assignee_did.as_deref(),
            limit,
            after,
            caller,
        )
        .await
        .map_err(crate::graphql::graphql_app_err)?;
        Ok(result
            .tasks
            .into_iter()
            .map(AgentTaskReadType::from)
            .collect())
    }

    async fn task(&self, ctx: &Context<'_>, id: String) -> Result<Option<AgentTaskReadType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();
        // #268: same gate as the REST get route, via the shared helper.
        let caller = ctx
            .data::<crate::auth::AuthenticatedDid>()
            .ok()
            .map(|d| d.0.as_str());
        let t = crate::api::tasks::get_visible_task(db, &id, caller)
            .await
            .map_err(crate::graphql::graphql_app_err)?;
        Ok(t.map(AgentTaskReadType::from))
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
            owner_did: None,
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
        let q = r#"{ refUpdates { repo refName ownerDid } }"#;
        let resp = anon(&schema, q).await;
        assert_eq!(count(&resp), 1);
        // The one row returned must be the public repo's with owner_did echoed.
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
        assert_eq!(
            row.get("ownerDid").unwrap(),
            &async_graphql::Value::from(OWNER),
            "ownerDid must fall back to the local record's owner for legacy rows"
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

    // Scenario 7 (#114 P2) — a small limit must page past the newest rows when
    // they are private, so the older public rows are still returned. Before the
    // gate moved ahead of the limit this returned 0 (the newest `limit` rows were
    // all private and got filtered after the SQL LIMIT). RED→GREEN.
    #[sqlx::test]
    async fn ref_updates_small_limit_pages_past_newest_private(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        db.create_repo(&repo("priv", OWNER, "secret", false))
            .await
            .unwrap();
        // 3 older PUBLIC rows …
        for i in 0..3 {
            let mut r = ref_row(&format!("pub{i}"), "z6MkOwner/openrepo");
            r.timestamp = format!("2026-07-01T10:00:0{i}+00:00");
            db.insert_ref_update(&r).await.unwrap();
        }
        // … then 5 NEWER PRIVATE rows (the newest in the feed).
        for i in 0..5 {
            let mut r = ref_row(&format!("priv{i}"), "z6MkOwner/secret");
            r.timestamp = format!("2026-07-01T10:00:1{i}+00:00");
            db.insert_ref_update(&r).await.unwrap();
        }
        let schema = schema(db);
        // limit 3 < the 5 newest (all private): anon must still get 3 public rows.
        let q = r#"{ refUpdates(limit: 3) { repo } }"#;
        let resp = anon(&schema, q).await;
        assert_eq!(count(&resp), 3, "paging must reach the older public rows");
        let async_graphql::Value::Object(obj) = &resp.data else {
            unreachable!()
        };
        let async_graphql::Value::List(rows) = obj.get("refUpdates").unwrap() else {
            unreachable!()
        };
        for row in rows {
            let async_graphql::Value::Object(r) = row else {
                unreachable!()
            };
            assert_eq!(
                r.get("repo").unwrap(),
                &async_graphql::Value::from("z6MkOwner/openrepo"),
                "every returned row must be the public repo's"
            );
        }
    }

    // Scenario 8 — a quarantined mirror is withheld on the GraphQL surface too.
    // Guards that the resolver keeps delegating to the shared collector (where the
    // quarantine fold lives); a REST-only test would miss a resolver that stopped.
    #[sqlx::test]
    async fn ref_updates_quarantined_mirror_dropped_for_anon(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6MkQuar", "secret", "/tmp/q", None, true)
            .await
            .unwrap();
        db.insert_ref_update(&ref_row("u1", "z6MkQuar/secret"))
            .await
            .unwrap();
        let schema = schema(db);
        let q = r#"{ refUpdates { repo } }"#;
        assert_eq!(count(&anon(&schema, q).await), 0);
    }

    // Scenario 8b — the GraphQL surface also withholds a quarantined repo from an
    // authenticated OWNER, not just anon. Without the collector's quarantine drop
    // the owner short-circuit in visibility_check keeps the row on this surface
    // too, so the REST owner test alone would not guard the resolver.
    #[sqlx::test]
    async fn ref_updates_quarantined_repo_dropped_for_owner(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&repo("q1", "did:key:z6MkQuar", "secret", false))
            .await
            .unwrap();
        db.set_repo_quarantine("q1", true).await.unwrap();
        db.insert_ref_update(&ref_row("u1", "z6MkQuar/secret"))
            .await
            .unwrap();
        let schema = schema(db);
        let q = r#"{ refUpdates { repo } }"#;
        assert_eq!(count(&authed(&schema, q, "did:key:z6MkQuar").await), 0);
    }

    /// #250: anonymous GraphQL query DB failures must not leak sqlx/schema text.
    #[sqlx::test]
    async fn repos_query_db_error_message_is_opaque(pool: PgPool) {
        let db = db(pool.clone()).await;
        db.create_repo(&repo("r1", OWNER, "widget", true))
            .await
            .unwrap();
        sqlx::query("ALTER TABLE repos DROP COLUMN is_public")
            .execute(&pool)
            .await
            .unwrap();

        let schema = schema(db);
        let resp = anon(&schema, "{ repos { name ownerDid } }").await;
        assert!(
            !resp.errors.is_empty(),
            "DB failure must surface as a GraphQL error"
        );
        for err in &resp.errors {
            assert_eq!(
                err.message,
                crate::graphql::GRAPHQL_DB_ERROR_MESSAGE,
                "raw DB detail leaked into GraphQL error: {}",
                err.message
            );
            assert!(
                !err.message.contains("is_public") && !err.message.contains("column"),
                "schema text leaked: {}",
                err.message
            );
        }
    }

    /// #250: negative tasks(limit) must not hit Postgres (and must not 500-log).
    #[sqlx::test]
    async fn tasks_negative_limit_clamped(pool: PgPool) {
        let db = db(pool).await;
        let schema = schema(db);
        let resp = anon(&schema, "{ tasks(limit: -1) { id } }").await;
        assert!(
            resp.errors.is_empty(),
            "negative limit must clamp, not fail: {:?}",
            resp.errors
        );
        assert_eq!(count_tasks(&resp), 0);
    }

    /// #255: ceiling of the tasks(limit) clamp must be held (schema promises Max 200).
    #[sqlx::test]
    async fn tasks_limit_ceiling_clamped_to_200(pool: PgPool) {
        let db = db(pool).await;
        let now = Utc::now().to_rfc3339();
        for i in 0..201 {
            db.create_task(&crate::db::AgentTask {
                id: format!("task-ceil-{i}"),
                repo_id: None,
                kind: "build".into(),
                status: "pending".into(),
                delegator_did: OWNER.into(),
                assignee_did: None,
                capability: "repo:write".into(),
                ucan_token: None,
                payload: None,
                result: None,
                created_at: now.clone(),
                updated_at: now.clone(),
                deadline: None,
            })
            .await
            .unwrap();
        }
        let schema = schema(db);
        // Queried as the delegator, not anonymously: since #268 the task read
        // surface is visibility-gated, and an anonymous caller sees none of
        // these repo-less tasks at all. The clamp is what this test pins, so it
        // needs a caller who can legitimately see all 201 rows.
        let resp = authed(&schema, "{ tasks(limit: 5000) { id } }", OWNER).await;
        assert_eq!(count_tasks(&resp), 200, "limit above 200 must clamp to 200");
    }

    /// Seed one repo-less task carrying a `ucan_token`, so a leak on any read
    /// surface is visible in the response body.
    async fn seed_task(db: &Db, id: &str, delegator: &str) {
        let now = Utc::now().to_rfc3339();
        db.create_task(&crate::db::AgentTask {
            id: id.into(),
            repo_id: None,
            kind: "build".into(),
            status: "pending".into(),
            delegator_did: delegator.into(),
            assignee_did: None,
            capability: "repo:write".into(),
            ucan_token: Some("SECRET-UCAN-TOKEN".into()),
            payload: None,
            result: None,
            created_at: now.clone(),
            updated_at: now,
            deadline: None,
        })
        .await
        .unwrap();
    }

    /// #268: the `tasks` resolver must delegate to the gated collector, not
    /// query the DB directly. A repo-less task belonging to someone else is
    /// invisible to an anonymous caller. `tasks_negative_limit_clamped` cannot
    /// catch a resolver that stops calling `collect_visible_tasks` because it
    /// seeds no rows — this seeds one, so the gate is load-bearing here.
    #[sqlx::test]
    async fn tasks_repo_less_task_hidden_from_anon(pool: PgPool) {
        let db = db(pool).await;
        seed_task(&db, "t1", OWNER).await;
        let schema = schema(db);
        let resp = anon(&schema, "{ tasks { id } }").await;
        assert_eq!(
            count_tasks(&resp),
            0,
            "anon must not enumerate another party's repo-less task"
        );
        assert!(
            !format!("{:?}", resp.data).contains("SECRET-UCAN-TOKEN"),
            "no ucan token may reach an anonymous caller"
        );
    }

    /// #268 sibling for the single-task resolver: an invisible task reads as
    /// `null`, indistinguishable from one that does not exist.
    #[sqlx::test]
    async fn task_by_id_is_null_for_anon(pool: PgPool) {
        let db = db(pool).await;
        seed_task(&db, "t1", OWNER).await;
        let schema = schema(db);
        let resp = anon(&schema, r#"{ task(id: "t1") { id } }"#).await;
        assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
        let async_graphql::Value::Object(obj) = &resp.data else {
            panic!("data not an object: {:?}", resp.data);
        };
        assert_eq!(
            obj.get("task"),
            Some(&async_graphql::Value::Null),
            "an invisible task must read as null, got {:?}",
            obj.get("task")
        );
    }

    /// #268: `ucanToken` is absent from the read type's schema entirely, so the
    /// delegator cannot request it either. Asking for it is a validation error,
    /// which pins the redaction at the schema level rather than per-resolver.
    #[sqlx::test]
    async fn task_read_schema_has_no_ucan_token_field(pool: PgPool) {
        let db = db(pool).await;
        seed_task(&db, "t1", OWNER).await;
        let schema = schema(db);
        let resp = authed(&schema, r#"{ task(id: "t1") { id ucanToken } }"#, OWNER).await;
        assert!(
            !resp.errors.is_empty(),
            "ucanToken must not exist on the task read type"
        );
    }

    #[sqlx::test]
    async fn tasks_find_older_visible_row_behind_denied_window(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&repo("public-repo", OWNER, "public", true))
            .await
            .unwrap();
        let visible = crate::db::AgentTask {
            id: "visible".into(),
            repo_id: Some("public-repo".into()),
            kind: "build".into(),
            status: "pending".into(),
            delegator_did: OWNER.into(),
            assignee_did: None,
            capability: "repo:write".into(),
            ucan_token: None,
            payload: None,
            result: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            deadline: None,
        };
        db.create_task(&visible).await.unwrap();
        for i in 0..200 {
            let mut hidden = visible.clone();
            hidden.id = format!("hidden-{i:03}");
            hidden.repo_id = None;
            hidden.created_at = "2026-01-02T00:00:00Z".into();
            hidden.updated_at = hidden.created_at.clone();
            db.create_task(&hidden).await.unwrap();
        }

        let schema = schema(db);
        let resp = anon(&schema, "{ tasks(limit: 1) { id } }").await;
        assert_eq!(count_tasks(&resp), 1);
        assert!(format!("{:?}", resp.data).contains("visible"));
    }

    #[sqlx::test]
    async fn tasks_continuation_past_candidate_ceiling(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&repo("public-repo", OWNER, "public", true))
            .await
            .unwrap();
        let visible = crate::db::AgentTask {
            id: "past-ceiling".into(),
            repo_id: Some("public-repo".into()),
            kind: "build".into(),
            status: "pending".into(),
            delegator_did: OWNER.into(),
            assignee_did: None,
            capability: "repo:write".into(),
            ucan_token: None,
            payload: None,
            result: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            deadline: None,
        };
        db.create_task(&visible).await.unwrap();
        for i in 0..1000 {
            let mut hidden = visible.clone();
            hidden.id = format!("hidden-{i:04}");
            hidden.repo_id = None;
            hidden.created_at = "2026-01-02T00:00:00Z".into();
            hidden.updated_at = hidden.created_at.clone();
            db.create_task(&hidden).await.unwrap();
        }

        let schema = schema(db);
        let resp = anon(&schema, "{ tasks(limit: 1) { id } }").await;
        assert_eq!(count_tasks(&resp), 0);

        let resp = anon(
            &schema,
            r#"{ tasks(limit: 1, afterCreatedAt: "2026-01-02T00:00:00Z", afterId: "hidden-0999") { id } }"#,
        )
        .await;
        assert_eq!(count_tasks(&resp), 1);
        assert!(format!("{:?}", resp.data).contains("past-ceiling"));
    }

    fn count_tasks(resp: &async_graphql::Response) -> usize {
        assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
        let async_graphql::Value::Object(obj) = &resp.data else {
            panic!("data not an object: {:?}", resp.data);
        };
        let async_graphql::Value::List(rows) = obj.get("tasks").expect("tasks key") else {
            panic!("tasks not a list");
        };
        rows.len()
    }
}

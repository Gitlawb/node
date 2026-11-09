use async_graphql::{Context, Object, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::sync::Arc;

use crate::api::events::MAX_VISIBLE_REF_UPDATES;
use crate::db::{Db, RepoRecord, MAX_VISIBLE_REPO_PAGE_SIZE, MAX_VISIBLE_TASK_PAGE_SIZE};

use super::types::{AgentTaskType, RefUpdateType, RepoPageType, RepoType};

fn repo_type(repo: RepoRecord) -> RepoType {
    RepoType {
        name: repo.name,
        owner_did: repo.owner_did,
        description: repo.description,
        default_branch: repo.default_branch,
        created_at: repo.created_at.to_rfc3339(),
    }
}

fn repo_cursor(repo: &RepoRecord) -> String {
    URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&(&repo.owner_did, &repo.name))
            .expect("a pair of strings is JSON serializable"),
    )
}

fn parse_repo_cursor(cursor: &str) -> Result<(String, String)> {
    // A position contains only public response fields, not a database id or
    // authority. Every page re-evaluates visibility for the current caller.
    if cursor.len() > 4096 {
        return Err(async_graphql::Error::new("invalid repository cursor"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| async_graphql::Error::new("invalid repository cursor"))?;
    let position: (String, String) = serde_json::from_slice(&bytes)
        .map_err(|_| async_graphql::Error::new("invalid repository cursor"))?;
    // PostgreSQL text cannot contain NUL. Reject it as malformed input before
    // binding either cursor component, rather than reporting a database error.
    if position.0.contains('\0') || position.1.contains('\0') {
        return Err(async_graphql::Error::new("invalid repository cursor"));
    }
    Ok(position)
}

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    // DB-backed roots carry a base cost so aliases consume the request budget
    // even when each alias selects only one inexpensive response field.
    // `repos` performs the same full corpus scan as a max-size `reposPage`
    // (list_visible_repos_page with MAX_VISIBLE_REPO_PAGE_SIZE + 1), so it
    // is priced as the full page it is, not as a cheap alias.
    #[graphql(complexity = "50 + MAX_VISIBLE_REPO_PAGE_SIZE + child_complexity")]
    /// Complete visible repository list, up to the documented maximum number
    /// of entries. Larger lists must use reposPage; this field returns an
    /// error instead of truncating silently.
    async fn repos(&self, ctx: &Context<'_>) -> Result<Vec<RepoType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();
        let caller = ctx
            .data::<crate::auth::AuthenticatedDid>()
            .ok()
            .map(|d| d.0.as_str());
        let mut repos = db
            .list_visible_repos_page(caller, None, MAX_VISIBLE_REPO_PAGE_SIZE + 1)
            .await
            .map_err(crate::graphql::graphql_db_err)?;
        if repos.len() > MAX_VISIBLE_REPO_PAGE_SIZE {
            return Err(async_graphql::Error::new(format!(
                "repository list exceeds {} entries; use reposPage with limit and after",
                MAX_VISIBLE_REPO_PAGE_SIZE
            )));
        }
        // Preserve the legacy activity ordering for complete, small lists.
        repos.sort_by_key(|repo| std::cmp::Reverse(repo.updated_at));
        Ok(repos.into_iter().map(repo_type).collect())
    }

    /// Bounded visible repositories ordered by owner and name. Continue with
    /// endCursor while hasNextPage is true. Pages are not a database snapshot.
    // Every page sorts the full deduplicated corpus under COLLATE "C"
    // (list_visible_repos_page documents the accepted O(total repos) bound),
    // so the price charges the scan, not the emitted rows: a limit:1 page
    // costs the same as a max-size page, the way `repos` is priced.
    #[graphql(complexity = "50 + MAX_VISIBLE_REPO_PAGE_SIZE + child_complexity")]
    async fn repos_page(
        &self,
        ctx: &Context<'_>,
        #[graphql(
            default = 50,
            desc = "Page size from 1 to the documented maximum; other values are rejected."
        )]
        limit: i64,
        after: Option<String>,
    ) -> Result<RepoPageType> {
        if !(1..=MAX_VISIBLE_REPO_PAGE_SIZE as i64).contains(&limit) {
            return Err(async_graphql::Error::new(format!(
                "limit must be between 1 and {}",
                MAX_VISIBLE_REPO_PAGE_SIZE
            )));
        }
        let after = after.as_deref().map(parse_repo_cursor).transpose()?;
        let caller = ctx
            .data::<crate::auth::AuthenticatedDid>()
            .ok()
            .map(|d| d.0.as_str());
        let db = ctx.data_unchecked::<Arc<Db>>();
        let mut repos = db
            .list_visible_repos_page(
                caller,
                after
                    .as_ref()
                    .map(|(owner, name)| (owner.as_str(), name.as_str())),
                limit as usize + 1,
            )
            .await
            .map_err(crate::graphql::graphql_db_err)?;
        let has_next_page = repos.len() > limit as usize;
        repos.truncate(limit as usize);
        let end_cursor = repos.last().map(repo_cursor);
        Ok(RepoPageType {
            nodes: repos.into_iter().map(repo_type).collect(),
            has_next_page,
            end_cursor,
        })
    }

    // Complexity is additive with a base reflecting the collector's fixed scan:
    // every request loads the full deduped repo set, the quarantined set, and
    // the visibility rules, then walks up to max(limit, 2048) event rows past
    // withheld ones, regardless of `limit`. A multiplicative price both
    // undercharged limit:1 (51 for that fixed work) and made a request at the
    // documented maximum unreachable (two fields at max limit cost 450 > 400).
    //
    // Decision on the collector floor (review #465, 3rd round): the up-to-2048
    // walk is bounded constant overhead that does not scale with `limit`, so
    // it is priced in the fixed base, not the limit term; the limit term
    // prices only the emitted rows. Pricing the walk at face value in the base
    // would put every refUpdates query over the 400 budget and make the field
    // unusable, so the base prices that fixed scan as a lump sum instead.
    #[graphql(
        complexity = "100 + (limit.clamp(0, MAX_VISIBLE_REF_UPDATES) as usize) + child_complexity"
    )]
    async fn ref_updates(
        &self,
        ctx: &Context<'_>,
        repo: Option<String>,
        #[graphql(
            default = 20,
            desc = "Requests above the documented maximum return the newest rows up to that maximum (no continuation cursor)."
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

    // Complexity is additive: list_tasks is a single LIMIT-bounded query whose
    // cost does not scale with the selected fields, so the price is the base
    // plus the clamped limit plus the child fields. A multiplicative price
    // made a request at the documented maximum unreachable (two fields at max
    // limit cost 450 > 400).
    #[graphql(
        complexity = "50 + (limit.clamp(0, MAX_VISIBLE_TASK_PAGE_SIZE) as usize) + child_complexity"
    )]
    async fn tasks(
        &self,
        ctx: &Context<'_>,
        status: Option<String>,
        assignee_did: Option<String>,
        #[graphql(
            default = 50,
            desc = "Requests above the documented maximum are clamped to it (no error). Negative values clamp to 0."
        )]
        limit: i64,
    ) -> Result<Vec<AgentTaskType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();
        // Clamp before SQL: a negative LIMIT is a client fault that Postgres
        // rejects with 2201W, which would otherwise trip the opaque DB path
        // and write an error-level log on every probe (#250 review).
        let limit = limit.clamp(0, MAX_VISIBLE_TASK_PAGE_SIZE);
        let tasks = db
            .list_tasks(status.as_deref(), assignee_did.as_deref(), limit)
            .await
            .map_err(crate::graphql::graphql_db_err)?;
        Ok(tasks.into_iter().map(AgentTaskType::from).collect())
    }

    #[graphql(complexity = "50 + child_complexity")]
    async fn task(&self, ctx: &Context<'_>, id: String) -> Result<Option<AgentTaskType>> {
        let db = ctx.data_unchecked::<Arc<Db>>();
        let t = db
            .get_task(&id)
            .await
            .map_err(crate::graphql::graphql_db_err)?;
        Ok(t.map(AgentTaskType::from))
    }
}

#[cfg(test)]
mod tests {
    use crate::db::{Db, ReceivedRefUpdate, RepoRecord};
    use base64::Engine;
    use chrono::Utc;
    use sqlx::PgPool;
    use std::sync::Arc;

    const OWNER: &str = "did:key:z6MkOwner";

    #[sqlx::test]
    async fn repos_legacy_rejects_overflow_and_pages_reach_every_visible_repo(pool: PgPool) {
        let db = db(pool).await;
        let total = crate::db::MAX_VISIBLE_REPO_PAGE_SIZE + 5;
        for index in 0..total {
            let name = format!("repo-{index:03}");
            db.create_repo(&repo(&name, OWNER, &name, true))
                .await
                .unwrap();
        }
        // The SQL helper itself must bound materialization, even for a caller
        // accidentally requesting an unlimited page.
        assert_eq!(
            db.list_visible_repos_page(None, None, usize::MAX)
                .await
                .unwrap()
                .len(),
            crate::db::MAX_VISIBLE_REPO_PAGE_SIZE + 1
        );
        let schema = schema(db);
        let legacy = anon(&schema, "{ repos { name } }").await;
        assert_eq!(legacy.errors.len(), 1);
        assert!(legacy.errors[0].message.contains("use reposPage"));
        assert_eq!(legacy.data, async_graphql::Value::Null);

        let mut cursor = None;
        let mut names = Vec::new();
        loop {
            let response = schema.execute(
                async_graphql::Request::new(
                    "query($after: String) { reposPage(limit: 50, after: $after) { nodes { name } hasNextPage endCursor } }",
                ).variables(async_graphql::Variables::from_json(serde_json::json!({"after": cursor}))),
            ).await;
            assert!(response.errors.is_empty(), "{:?}", response.errors);
            let json = response.data.into_json().unwrap();
            let page = &json["reposPage"];
            let rows = page["nodes"].as_array().unwrap();
            assert!(rows.len() <= 50);
            names.extend(
                rows.iter()
                    .map(|row| row["name"].as_str().unwrap().to_owned()),
            );
            if !page["hasNextPage"].as_bool().unwrap() {
                break;
            }
            let next = page["endCursor"].as_str().unwrap().to_owned();
            assert_ne!(cursor.as_ref(), Some(&next));
            cursor = Some(next);
            assert!(names.len() <= crate::db::MAX_VISIBLE_REPO_PAGE_SIZE);
        }
        assert_eq!(
            names,
            (0..total)
                .map(|index| format!("repo-{index:03}"))
                .collect::<Vec<_>>()
        );
    }

    #[sqlx::test]
    async fn repos_legacy_accepts_exactly_the_visible_bound(pool: PgPool) {
        let db = db(pool).await;
        let base_time = Utc::now();
        let total = crate::db::MAX_VISIBLE_REPO_PAGE_SIZE;
        for index in 0..total {
            let name = format!("repo-{index:03}");
            let mut r = repo(&name, OWNER, &name, true);
            // Anti-correlate updated_at with name, creation order, and index
            // so only ordering by updated_at DESC can satisfy the expectation.
            let offset = (index * 37) % total;
            r.updated_at = base_time + chrono::Duration::seconds(offset as i64);
            db.create_repo(&r).await.unwrap();
        }
        db.create_repo(&repo("hidden", OWNER, "hidden", false))
            .await
            .unwrap();
        let response = anon(&schema(db), "{ repos { name } }").await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let repos = response.data.into_json().unwrap()["repos"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(repos.len(), total);
        let names: Vec<_> = repos.iter().filter_map(|r| r["name"].as_str()).collect();
        assert!(
            !names.contains(&"hidden"),
            "hidden repo must be excluded from legacy repos response"
        );
        let mut expected_indices = (0..total).collect::<Vec<_>>();
        expected_indices.sort_by_key(|&idx| std::cmp::Reverse((idx * 37) % total));
        let expected_names: Vec<String> = expected_indices
            .into_iter()
            .map(|index| format!("repo-{index:03}"))
            .collect();
        assert_eq!(
            names,
            expected_names
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
            "legacy repos must retain activity ordering (most recently updated first)"
        );
    }

    #[sqlx::test]
    async fn repos_page_pagination_crosses_owner_boundary(pool: PgPool) {
        let db = db(pool).await;
        let owner1 = "did:key:z6MkaOwner1";
        let owner2 = "did:key:z6MkbOwner2";
        let earlier_owner = "did:web:example.com";
        // This owner sorts first only after did:key normalization. Its name
        // sorts past the first cursor, so an unqualified OR name predicate
        // would incorrectly serve it again on the next page.
        //
        // Rows are inserted out of order and not in reverse asserted order.
        // Assigned IDs do not track name order, and owner2 contains both
        // "B-repo" and "a-repo" whose byte order (B < a) differs from their
        // case-folded order (a < b), ensuring lower(d.name) cannot satisfy
        // the keyset query. Sized to 6 entries so the last page is full-sized
        // (limit 2), proving hasNextPage distinguishes a full terminal page.
        db.create_repo(&repo("r5", owner2, "c-repo", true))
            .await
            .unwrap();
        db.create_repo(&repo("r9", earlier_owner, "zz-repo", true))
            .await
            .unwrap();
        db.create_repo(&repo("r3", owner2, "B-repo", true))
            .await
            .unwrap();
        db.create_repo(&repo("r8", owner1, "z-repo", true))
            .await
            .unwrap();
        db.create_repo(&repo("r2", owner1, "b-repo", true))
            .await
            .unwrap();
        db.create_repo(&repo("r1", owner2, "a-repo", true))
            .await
            .unwrap();

        let schema = schema(db);
        let page1_resp = anon(
            &schema,
            "{ reposPage(limit: 2) { nodes { name ownerDid } hasNextPage endCursor } }",
        )
        .await;
        assert!(page1_resp.errors.is_empty(), "{:?}", page1_resp.errors);
        let p1 = page1_resp.data.into_json().unwrap()["reposPage"].clone();
        assert_eq!(p1["hasNextPage"], true);
        assert_eq!(
            p1["nodes"],
            serde_json::json!([
                {"name": "zz-repo", "ownerDid": earlier_owner},
                {"name": "b-repo", "ownerDid": owner1},
            ])
        );
        let cursor = p1["endCursor"].as_str().unwrap();

        let page2_query = format!(
            "{{ reposPage(limit: 2, after: \"{cursor}\") {{ nodes {{ name ownerDid }} hasNextPage endCursor }} }}"
        );
        let page2_resp = anon(&schema, &page2_query).await;
        assert!(page2_resp.errors.is_empty(), "{:?}", page2_resp.errors);
        let p2 = page2_resp.data.into_json().unwrap()["reposPage"].clone();
        assert_eq!(p2["hasNextPage"], true);
        assert_eq!(
            p2["nodes"],
            serde_json::json!([
                {"name": "z-repo", "ownerDid": owner1},
                {"name": "B-repo", "ownerDid": owner2},
            ])
        );
        let cursor = p2["endCursor"].as_str().unwrap();
        let page3_query = format!(
            "{{ reposPage(limit: 2, after: \"{cursor}\") {{ nodes {{ name ownerDid }} hasNextPage endCursor }} }}"
        );
        let page3_resp = anon(&schema, &page3_query).await;
        assert!(page3_resp.errors.is_empty(), "{:?}", page3_resp.errors);
        let p3 = page3_resp.data.into_json().unwrap()["reposPage"].clone();
        assert_eq!(p3["hasNextPage"], false);
        assert_eq!(
            p3["nodes"],
            serde_json::json!([
                {"name": "a-repo", "ownerDid": owner2},
                {"name": "c-repo", "ownerDid": owner2},
            ])
        );
    }

    #[sqlx::test]
    async fn repos_page_at_documented_maximum_distinguishes_terminal_page(pool: PgPool) {
        let db = db(pool).await;
        let total = crate::db::MAX_VISIBLE_REPO_PAGE_SIZE;
        for index in 0..total {
            let name = format!("repo-{index:03}");
            db.create_repo(&repo(&name, OWNER, &name, true))
                .await
                .unwrap();
        }
        let schema = schema(db.clone());
        let query =
            format!("{{ reposPage(limit: {total}) {{ nodes {{ name }} hasNextPage endCursor }} }}");
        let resp200 = anon(&schema, &query).await;
        assert!(resp200.errors.is_empty(), "{:?}", resp200.errors);
        let p200 = resp200.data.into_json().unwrap()["reposPage"].clone();
        assert_eq!(p200["hasNextPage"], false);
        let nodes200 = p200["nodes"].as_array().unwrap().clone();
        assert_eq!(nodes200.len(), total);

        // Adding row 201 keeps page 1 content identical while flipping hasNextPage to true.
        let name201 = format!("repo-{total:03}");
        db.create_repo(&repo(&name201, OWNER, &name201, true))
            .await
            .unwrap();
        let resp201 = anon(&schema, &query).await;
        assert!(resp201.errors.is_empty(), "{:?}", resp201.errors);
        let p201 = resp201.data.into_json().unwrap()["reposPage"].clone();
        assert_eq!(p201["hasNextPage"], true);
        assert_eq!(p201["nodes"], p200["nodes"]);
        assert_eq!(p201["endCursor"], p200["endCursor"]);
    }

    #[sqlx::test]
    async fn repos_page_visibility_matches_the_shared_gate(pool: PgPool) {
        use crate::db::VisibilityMode;
        let db = db(pool).await;
        let reader = "did:key:zReader";
        for (id, public) in [
            ("open", true),
            ("private", false),
            ("root-deny", true),
            ("root-reader", false),
            ("subtree", true),
            ("root-tie", true),
            ("odd-star", true),
            ("malformed-readers", true),
            ("non-array-readers", true),
            ("non-string-reader", true),
            ("quarantined", true),
        ] {
            db.create_repo(&repo(id, OWNER, id, public)).await.unwrap();
        }
        // Canonical and mirror copies must still collapse before pagination.
        db.create_repo(&repo("z6MkOwner/open", "z6MkOwner", "open", true))
            .await
            .unwrap();
        db.create_repo(&repo(
            "other-method",
            "did:web:z6MkOwner",
            "other-method",
            false,
        ))
        .await
        .unwrap();
        db.set_repo_quarantine("quarantined", true).await.unwrap();
        for (id, glob, readers) in [
            ("root-deny", "/", vec![]),
            ("root-reader", "/**", vec![reader.to_owned()]),
            ("subtree", "/secret/**", vec![]),
            ("root-tie", "/", vec![reader.to_owned()]),
            ("root-tie", "/**", vec![]),
            ("odd-star", "/*", vec![]),
            ("malformed-readers", "/", vec![]),
            ("non-array-readers", "/", vec![]),
            ("non-string-reader", "/", vec![]),
        ] {
            db.set_visibility_rule(id, glob, VisibilityMode::B, &readers, OWNER)
                .await
                .unwrap();
        }
        // The typed setter cannot create malformed JSON, but existing TEXT rows
        // can contain it. Such a rule must deny this repo, not abort the page.
        // All three deny arms of the reader_dids predicate are pinned here:
        // (a) invalid JSON, (b) valid JSON that is not an array, (c) an array
        // containing a non-string member. The Rust gate parses reader_dids as
        // Vec<String> with unwrap_or_default(), so (b) and (c) also fail to
        // parse and deny; the SQL CASE must agree on every shape.
        let rows = sqlx::query("UPDATE visibility_rules SET reader_dids = $1 WHERE repo_id = $2")
            .bind("not JSON")
            .bind("malformed-readers")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(rows.rows_affected(), 1);
        let rows = sqlx::query("UPDATE visibility_rules SET reader_dids = $1 WHERE repo_id = $2")
            .bind("\"just-a-string\"")
            .bind("non-array-readers")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(rows.rows_affected(), 1);
        // The named reader is listed, but the non-string member poisons the
        // whole list: both sides must still deny them.
        let rows = sqlx::query("UPDATE visibility_rules SET reader_dids = $1 WHERE repo_id = $2")
            .bind("[\"did:key:zReader\", 42]")
            .bind("non-string-reader")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(rows.rows_affected(), 1);
        let all = db.list_all_repos_deduped().await.unwrap();
        for caller in [
            None,
            Some(OWNER),
            Some("z6MkOwner"),
            Some(reader),
            Some("zReader"),
            Some("did:web:z6MkOwner"),
        ] {
            let mut expected = Vec::new();
            for record in &all {
                let rules = db.list_visibility_rules(&record.id).await.unwrap();
                if crate::visibility::listable_at_root(
                    &rules,
                    record.is_public,
                    &record.owner_did,
                    caller,
                ) {
                    expected.push(record.id.clone());
                }
            }
            expected.sort();
            let mut actual = db
                .list_visible_repos_page(caller, None, usize::MAX)
                .await
                .unwrap()
                .into_iter()
                .map(|record| record.id)
                .collect::<Vec<_>>();
            actual.sort();
            assert_eq!(actual, expected, "caller {caller:?}");
        }
        let schema = schema(db);
        for caller in [None, Some("did:key:zUnauthorized")] {
            let query = "{ repos { name } }";
            let response = match caller {
                None => anon(&schema, query).await,
                Some(caller) => authed(&schema, query, caller).await,
            };
            assert!(response.errors.is_empty(), "{:?}", response.errors);
            let mut names: Vec<String> = response.data.into_json().unwrap()["repos"]
                .as_array()
                .unwrap()
                .iter()
                .map(|repo| repo["name"].as_str().unwrap().to_owned())
                .collect();
            names.sort();
            assert_eq!(names, ["odd-star", "open", "subtree"]);
        }
        let query = "{ reposPage(limit: 1) { nodes { name ownerDid } hasNextPage endCursor } }";
        let response = anon(&schema, query).await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let json = response.data.into_json().unwrap();
        let page = &json["reposPage"];
        assert_eq!(
            page["nodes"],
            serde_json::json!([{"name": "odd-star", "ownerDid": OWNER}])
        );
        assert_eq!(page["hasNextPage"], true);
        let cursor = super::parse_repo_cursor(page["endCursor"].as_str().unwrap()).unwrap();
        assert_eq!(cursor, (OWNER.to_owned(), "odd-star".to_owned()));
        assert!(!json.to_string().contains("private"));
        assert!(!json.to_string().contains("quarantined"));

        // Route-level check with unauthorized authenticated caller:
        // Excludes private, quarantined, and root-deny repos, matching anonymous behavior.
        let all_query = "{ reposPage(limit: 50) { nodes { name } hasNextPage } }";
        let unauth_response = authed(&schema, all_query, "did:key:zUnauthorized").await;
        assert!(
            unauth_response.errors.is_empty(),
            "{:?}",
            unauth_response.errors
        );
        let unauth_json = unauth_response.data.into_json().unwrap();
        let unauth_names: Vec<&str> = unauth_json["reposPage"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|n| n["name"].as_str())
            .collect();
        assert_eq!(unauth_names, vec!["odd-star", "open", "subtree"]);
        let unauth_str = unauth_json.to_string();
        assert!(!unauth_str.contains("private"));
        assert!(!unauth_str.contains("quarantined"));
        assert!(!unauth_str.contains("root-deny"));
        assert!(!unauth_str.contains("root-reader"));
        assert!(!unauth_str.contains("root-tie"));

        // Reader caller gets root-reader and root-tie, but still excludes private, quarantined, root-deny.
        let reader_response = authed(&schema, all_query, reader).await;
        assert!(
            reader_response.errors.is_empty(),
            "{:?}",
            reader_response.errors
        );
        let reader_json = reader_response.data.into_json().unwrap();
        let reader_names: Vec<&str> = reader_json["reposPage"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|n| n["name"].as_str())
            .collect();
        assert_eq!(
            reader_names,
            vec!["odd-star", "open", "root-reader", "subtree"]
        );
        let reader_str = reader_json.to_string();
        assert!(!reader_str.contains("private"));
        assert!(!reader_str.contains("quarantined"));
        assert!(!reader_str.contains("root-deny"));
        assert!(!reader_str.contains("root-tie"));
    }

    #[sqlx::test]
    async fn repos_page_rechecks_cursor_authority_and_exact_boundary(pool: PgPool) {
        let db = db(pool).await;
        let visible = repo("visible", OWNER, "a-visible", true);
        db.create_repo(&visible).await.unwrap();
        db.create_repo(&repo("hidden", OWNER, "z-private", false))
            .await
            .unwrap();
        let schema = schema(db);
        let first = anon(
            &schema,
            "{ reposPage(limit: 1) { nodes { name } hasNextPage endCursor } }",
        )
        .await;
        assert!(first.errors.is_empty());
        let first = first.data.into_json().unwrap();
        assert_eq!(first["reposPage"]["hasNextPage"], false);
        let query = format!(
            "{{ reposPage(limit: 1, after: \"{}\") {{ nodes {{ name }} hasNextPage endCursor }} }}",
            super::repo_cursor(&visible)
        );
        let owner = authed(&schema, &query, OWNER).await;
        assert!(owner.errors.is_empty());
        assert_eq!(
            owner.data.into_json().unwrap()["reposPage"]["nodes"][0]["name"],
            "z-private"
        );
        let anon = anon(&schema, &query).await;
        assert!(anon.errors.is_empty());
        assert_eq!(
            anon.data.into_json().unwrap()["reposPage"],
            serde_json::json!({
                "nodes": [], "hasNextPage": false, "endCursor": null
            })
        );
        let unauth = authed(&schema, &query, "did:key:zUnauthorized").await;
        assert!(unauth.errors.is_empty());
        assert_eq!(
            unauth.data.into_json().unwrap()["reposPage"],
            serde_json::json!({
                "nodes": [], "hasNextPage": false, "endCursor": null
            })
        );
    }

    #[tokio::test]
    async fn repos_page_rejects_nul_cursors_before_database_access() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let schema = schema(Arc::new(Db::for_testing(pool)));
        for position in [("did:key:zOwner\0", "repo"), ("did:key:zOwner", "repo\0")] {
            let cursor = super::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&position).unwrap());
            let query = format!("{{ reposPage(after: \"{cursor}\") {{ hasNextPage }} }}");
            let response =
                tokio::time::timeout(std::time::Duration::from_secs(1), anon(&schema, &query))
                    .await
                    .expect("invalid cursors must be rejected without accessing the database");
            assert_eq!(response.errors.len(), 1);
            assert_eq!(response.errors[0].message, "invalid repository cursor");
            assert_eq!(response.data, async_graphql::Value::Null);
        }
        let position = ("did:key:zOwner", "repo");
        let cursor = super::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&position).unwrap());
        assert_eq!(
            super::parse_repo_cursor(&cursor).unwrap(),
            (position.0.to_owned(), position.1.to_owned())
        );
    }

    #[tokio::test]
    async fn repos_page_rejects_invalid_inputs_before_database_access() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let schema = schema(Arc::new(Db::for_testing(pool)));
        let over_max = crate::db::MAX_VISIBLE_REPO_PAGE_SIZE + 1;
        let expected_limit_message = format!(
            "limit must be between 1 and {}",
            crate::db::MAX_VISIBLE_REPO_PAGE_SIZE
        );
        // Each input pins its own rejection message: the loop must not accept
        // either message for every query, or a misattributed message (e.g. the
        // limit arm returning "invalid repository cursor") stays invisible.
        for (query, expected_message) in [
            (
                "{ reposPage(limit: 0) { hasNextPage } }".to_owned(),
                expected_limit_message.clone(),
            ),
            (
                "{ reposPage(limit: -1) { hasNextPage } }".to_owned(),
                expected_limit_message.clone(),
            ),
            (
                format!("{{ reposPage(limit: {over_max}) {{ hasNextPage }} }}"),
                expected_limit_message.clone(),
            ),
            (
                "{ reposPage(after: \"invalid!\") { hasNextPage } }".to_owned(),
                "invalid repository cursor".to_owned(),
            ),
        ] {
            let response =
                tokio::time::timeout(std::time::Duration::from_secs(1), anon(&schema, &query))
                    .await
                    .unwrap();
            assert_eq!(response.errors.len(), 1);
            assert_eq!(
                response.errors[0].message, expected_message,
                "wrong rejection message for query: {query}"
            );
        }
        // Valid base64 and valid cursor JSON: only the length guard rejects it.
        let oversized = super::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&("did:key:reader", "a".repeat(3100))).unwrap());
        assert!(oversized.len() > 4096);
        assert!(serde_json::from_slice::<(String, String)>(
            &super::URL_SAFE_NO_PAD.decode(&oversized).unwrap()
        )
        .is_ok());
        assert!(super::parse_repo_cursor(&oversized).is_err());
    }

    #[tokio::test]
    async fn parse_repo_cursor_rejects_wrong_shape_json() {
        // Valid base64 and valid JSON, but not a (String, String) pair: the
        // wrong-shape arm must report "invalid repository cursor", exactly,
        // before any database access.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let schema = schema(Arc::new(Db::for_testing(pool)));
        for payload in [
            serde_json::json!(["only-one"]),
            serde_json::json!(["a", "b", "c"]),
            serde_json::json!({"owner": "x", "name": "y"}),
            serde_json::json!(42),
            serde_json::json!(["a", 1]),
        ] {
            let cursor = super::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
            let err = super::parse_repo_cursor(&cursor).unwrap_err();
            assert_eq!(err.message, "invalid repository cursor");
            let query = format!("{{ reposPage(after: \"{cursor}\") {{ hasNextPage }} }}");
            let response =
                tokio::time::timeout(std::time::Duration::from_secs(1), anon(&schema, &query))
                    .await
                    .expect("wrong-shape cursors must be rejected without accessing the database");
            assert_eq!(response.errors.len(), 1);
            assert_eq!(response.errors[0].message, "invalid repository cursor");
            assert_eq!(response.data, async_graphql::Value::Null);
        }
    }

    #[tokio::test]
    async fn longest_repo_name_cursor_round_trips() {
        // #465 4th round: a cursor the server emits must always parse back.
        // Repo names are bounded at the create/fork/mirror write paths, so the
        // longest admissible name must produce a cursor under the 4096-byte
        // parse limit.
        let name = "a".repeat(crate::db::MAX_REPO_NAME_LEN);
        let record = repo("long", OWNER, &name, true);
        let cursor = super::repo_cursor(&record);
        assert!(
            cursor.len() <= 4096,
            "emitted cursor must stay under the parse limit: {}",
            cursor.len()
        );
        assert_eq!(
            super::parse_repo_cursor(&cursor).unwrap(),
            (OWNER.to_owned(), name)
        );
    }

    /// A negative refUpdates(limit) must be accepted and clamped to zero rows,
    /// like tasks(limit: -1): the complexity formula's `limit.clamp(0, ...)`
    /// prices it at the floor and the shared collector returns before any
    /// database access. Mirrors tasks_negative_limit_clamped.
    #[tokio::test]
    async fn ref_updates_negative_limit_clamped() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let schema = schema(Arc::new(Db::for_testing(pool)));
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            anon(&schema, "{ refUpdates(limit: -1) { repo } }"),
        )
        .await
        .expect("negative limit must clamp without accessing the database");
        assert!(
            resp.errors.is_empty(),
            "negative limit must clamp, not fail: {:?}",
            resp.errors
        );
        assert_eq!(count(&resp), 0);
    }

    /// The mirror write path binds peer-supplied names verbatim, so it must
    /// enforce the same bound as the local write paths: an overlong peer name
    /// would otherwise make reposPage emit an unparseable cursor. The
    /// rejection happens before any database access.
    #[tokio::test]
    async fn mirror_repo_rejects_overlong_name() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let db = Db::for_testing(pool);
        let name = "b".repeat(crate::db::MAX_REPO_NAME_LEN + 1);
        let err = db
            .upsert_mirror_repo("z6MkLong", &name, "/tmp/long", None, false)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err}"
        );
    }

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

    /// #255: ceiling of the tasks(limit) clamp must be held (schema promises the
    /// documented maximum).
    #[sqlx::test]
    async fn tasks_limit_ceiling_clamped_to_max(pool: PgPool) {
        let db = db(pool).await;
        let now = Utc::now().to_rfc3339();
        for i in 0..crate::db::MAX_VISIBLE_TASK_PAGE_SIZE + 1 {
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
        let resp = anon(&schema, "{ tasks(limit: 5000) { id } }").await;
        assert_eq!(
            count_tasks(&resp),
            crate::db::MAX_VISIBLE_TASK_PAGE_SIZE as usize,
            "limit above the maximum must clamp to MAX_VISIBLE_TASK_PAGE_SIZE"
        );
    }

    /// A limit above MAX_VISIBLE_REF_UPDATES must reach the resolver clamped,
    /// not be rejected: the complexity formula clamps the priced limit (so the
    /// document passes validation) and the shared collector clamps the rows
    /// (so at most MAX_VISIBLE_REF_UPDATES come back). Removing the formula
    /// clamp prices the raw limit and rejects the document; removing the
    /// collector clamp returns unbounded rows. Mirrors
    /// tasks_limit_ceiling_clamped_to_max.
    #[sqlx::test]
    async fn ref_updates_limit_ceiling_clamped_to_max(pool: PgPool) {
        use crate::api::events::MAX_VISIBLE_REF_UPDATES;
        let db = db(pool).await;
        db.create_repo(&repo("r1", OWNER, "widget", true))
            .await
            .unwrap();
        let total = MAX_VISIBLE_REF_UPDATES as usize + 1;
        for i in 0..total {
            let mut row = ref_row(&format!("ceil{i}"), "z6MkOwner/widget");
            row.timestamp = format!("2026-07-01T10:{:02}:{:02}+00:00", i / 60, i % 60);
            db.insert_ref_update(&row).await.unwrap();
        }
        let schema = schema(db);
        let query = format!(
            "{{ refUpdates(limit: {}) {{ repo }} }}",
            MAX_VISIBLE_REF_UPDATES + 4800
        );
        let resp = anon(&schema, &query).await;
        assert!(
            resp.errors.is_empty(),
            "limit above the maximum must clamp, not fail: {:?}",
            resp.errors
        );
        assert_eq!(
            count(&resp),
            MAX_VISIBLE_REF_UPDATES as usize,
            "limit above the maximum must clamp to MAX_VISIBLE_REF_UPDATES"
        );
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

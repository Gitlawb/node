//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.
//!
//! Requires authentication (RFC 9421 HTTP Signature).  When `?repo=...` is
//! specified the caller must also be authorized to read that repo, and the
//! query uses the normalized slug.  Without `?repo=` the endpoint returns
//! anchors scoped to repos the caller can read, or an empty list for
//! anonymous callers.

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use serde::Deserialize;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ListAnchorsQuery {
    pub repo: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    50
}

/// Compute the set of (repo_slug, owner_did) pairs the caller can read.
/// Used when `?repo=` is absent and the caller is authenticated (P1).
fn readable_repo_pairs(
    repos: &[crate::db::RepoRecord],
    rules_by_repo: &std::collections::HashMap<String, Vec<crate::db::VisibilityRule>>,
    caller: &str,
) -> (Vec<String>, Vec<String>) {
    let mut slugs = Vec::new();
    let mut dids = Vec::new();
    for r in repos {
        let rules = rules_by_repo.get(&r.id).map(Vec::as_slice).unwrap_or(&[]);
        if crate::visibility::listable_at_root(rules, r.is_public, &r.owner_did, Some(caller)) {
            let owner_short = crate::db::normalize_owner_key(&r.owner_did);
            slugs.push(format!("{owner_short}/{}", r.name));
            dids.push(r.owner_did.clone());
        }
    }
    (slugs, dids)
}

/// GET /api/v1/arweave/anchors
pub async fn list_anchors(
    State(state): State<AppState>,
    Query(q): Query<ListAnchorsQuery>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let limit = q.limit.clamp(0, 200);

    // Reject missing authentication before any branch — the ?repo= path also
    // needs a caller so that public repos are gated by the same auth contract (P1).
    if caller.is_none() {
        return Err(AppError::Unauthorized(
            "authentication required for anchor listing".into(),
        ));
    }

    if let Some(slug) = &q.repo {
        let Some((owner_key, name)) = slug.split_once('/') else {
            return Err(AppError::BadRequest(format!("invalid repo slug: {slug}")));
        };
        let (record, _rules) =
            crate::api::authorize_repo_read(&state, owner_key, name, Some(caller.unwrap()), "/")
                .await?;

        // Use the normalized slug so full-DID queries match persisted values (P2)
        let owner_short = crate::db::normalize_owner_key(&record.owner_did);
        let normalized_slug = format!("{owner_short}/{}", record.name);
        let anchors = state
            .db
            .list_arweave_anchors(Some(&normalized_slug), limit)
            .await
            .map_err(AppError::Internal)?;

        return Ok(Json(serde_json::json!({
            "anchors": anchors,
            "count": anchors.len(),
        })));
    }

    // Authenticated caller without ?repo=: scope to readable repos (P1).
    // Use the deduped, quarantine-filtered view (same as the pin listing).
    let repos = state
        .db
        .list_all_repos_deduped()
        .await
        .map_err(AppError::Internal)?;
    let ids: Vec<String> = repos.iter().map(|r| r.id.clone()).collect();
    let rules_by_repo = state
        .db
        .list_visibility_rules_for_repos(&ids)
        .await
        .map_err(AppError::Internal)?;
    let (repos, owner_dids) = readable_repo_pairs(&repos, &rules_by_repo, caller.unwrap());
    let anchors = state
        .db
        .list_arweave_anchors_for_repos(&repos, &owner_dids, limit)
        .await
        .map_err(AppError::Internal)?;

    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "count": anchors.len(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_state;
    use axum::extract::{Extension, Query, State};
    use sqlx::PgPool;

    fn alice_did() -> String {
        "did:key:z6MkwAlice".into()
    }

    fn bob_did() -> String {
        "did:key:z6MkwBob".into()
    }

    fn auth_ext(did: &str) -> Option<Extension<AuthenticatedDid>> {
        Some(Extension(AuthenticatedDid(did.to_string())))
    }

    #[sqlx::test]
    async fn anonymous_is_401_before_any_db_work(pool: PgPool) {
        let state = test_state(pool).await;
        let q = Query(ListAnchorsQuery {
            repo: None,
            limit: 50,
        });
        let result = list_anchors(State(state), q, None).await;
        assert!(
            matches!(result, Err(AppError::Unauthorized(_))),
            "expected 401 for anonymous, got {result:?}"
        );
    }

    #[sqlx::test]
    async fn anonymous_with_repo_is_401(pool: PgPool) {
        let state = test_state(pool).await;
        let q = Query(ListAnchorsQuery {
            repo: Some("z6MkwAlice/public-repo".into()),
            limit: 50,
        });
        let result = list_anchors(State(state), q, None).await;
        assert!(
            matches!(result, Err(AppError::Unauthorized(_))),
            "expected 401 for anonymous with ?repo=, got {result:?}"
        );
    }

    #[sqlx::test]
    async fn stranger_repo_on_private_is_denied(pool: PgPool) {
        let state = test_state(pool).await;

        // Seed a private repo.
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch, created_at, updated_at, disk_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("arw-test-private")
        .bind("priv-repo")
        .bind(alice_did())
        .bind("desc")
        .bind(false)
        .bind("main")
        .bind("2026-07-19T00:00:00Z")
        .bind("2026-07-19T00:00:00Z")
        .bind("/srv/priv-repo")
        .execute(state.db.pool())
        .await
        .unwrap();

        // Seed an anchor for the private repo.
        sqlx::query(
            "INSERT INTO arweave_anchors (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind("anchor-1")
        .bind("z6MkwAlice/priv-repo")
        .bind(alice_did())
        .bind("refs/heads/main")
        .bind("0000")
        .bind("aaaa")
        .bind("QmAnchor")
        .bind("irys-tx-1")
        .bind("https://arweave.net/tx1")
        .bind("did:key:z6MkwNode")
        .bind("2026-07-19T00:00:00Z")
        .execute(state.db.pool())
        .await
        .unwrap();

        // Bob (stranger) tries ?repo= on private repo — denied.
        let q = Query(ListAnchorsQuery {
            repo: Some("z6MkwAlice/priv-repo".into()),
            limit: 50,
        });
        let result = list_anchors(State(state), q, auth_ext(&bob_did())).await;
        assert!(
            matches!(result, Err(AppError::RepoNotFound(_))),
            "stranger should get RepoNotFound for private repo, got {result:?}"
        );
    }

    #[sqlx::test]
    async fn global_path_scopes_to_readable_repos(pool: PgPool) {
        let state = test_state(pool).await;

        // Seed two repos: one public (readable by all) and one private (readable
        // only by Alice).  Bob should only see the public repo's anchors.
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch, created_at, updated_at, disk_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("arw-pub")
        .bind("pub-repo")
        .bind(alice_did())
        .bind("desc")
        .bind(true)
        .bind("main")
        .bind("2026-07-19T00:00:00Z")
        .bind("2026-07-19T00:00:00Z")
        .bind("/srv/pub")
        .execute(state.db.pool())
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch, created_at, updated_at, disk_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("arw-priv")
        .bind("priv-repo")
        .bind(alice_did())
        .bind("desc")
        .bind(false)
        .bind("main")
        .bind("2026-07-19T00:00:00Z")
        .bind("2026-07-19T00:00:00Z")
        .bind("/srv/priv")
        .execute(state.db.pool())
        .await
        .unwrap();

        // Seed anchors for both repos.
        sqlx::query(
            "INSERT INTO arweave_anchors (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind("anchor-pub")
        .bind("z6MkwAlice/pub-repo")
        .bind(alice_did())
        .bind("refs/heads/main")
        .bind("0000")
        .bind("aaaa")
        .bind("QmPub")
        .bind("irys-tx-pub")
        .bind("https://arweave.net/pub")
        .bind("did:key:z6MkwNode")
        .bind("2026-07-19T00:00:00Z")
        .execute(state.db.pool())
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO arweave_anchors (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind("anchor-priv")
        .bind("z6MkwAlice/priv-repo")
        .bind(alice_did())
        .bind("refs/heads/main")
        .bind("0000")
        .bind("bbbb")
        .bind("QmPriv")
        .bind("irys-tx-priv")
        .bind("https://arweave.net/priv")
        .bind("did:key:z6MkwNode")
        .bind("2026-07-19T00:00:00Z")
        .execute(state.db.pool())
        .await
        .unwrap();

        // Bob (stranger) without ?repo=: only public repo anchors returned.
        let q = Query(ListAnchorsQuery {
            repo: None,
            limit: 200,
        });
        let Json(body) = list_anchors(State(state), q, auth_ext(&bob_did()))
            .await
            .unwrap();
        let anchors = body["anchors"].as_array().unwrap();
        let count = body["count"].as_u64().unwrap();
        assert_eq!(count, 1, "bob should see only 1 anchor (public repo)");
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0]["cid"].as_str(), Some("QmPub"));
    }
}

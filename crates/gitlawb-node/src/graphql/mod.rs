pub mod mutation;
pub mod query;
pub mod subscription;
pub mod types;

use async_graphql::Schema;
use std::sync::Arc;

use crate::db::Db;
use crate::state::{RefUpdateBroadcast, TaskEventBroadcast};
use mutation::MutationRoot;
use query::QueryRoot;
use subscription::SubscriptionRoot;

pub type GitlawbSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

/// Client-facing message for GraphQL resolver failures that wrap a real
/// `sqlx::Error`. The real error is logged server-side; never put sqlx/Postgres
/// detail in the GraphQL `errors` array (#250).
///
/// Kept as its own constant on this PR's base (main still renders
/// `AppError::Db` with `e.to_string()`). If/when #247's `DB_ERROR_MESSAGE`
/// lands, fold this into that shared constant.
pub const GRAPHQL_DB_ERROR_MESSAGE: &str = "a database error occurred";

fn anyhow_has_sqlx(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<sqlx::Error>().is_some())
}

/// Map an `anyhow` failure from the db layer to a GraphQL error.
///
/// - Real DB faults (`sqlx::Error` anywhere in the chain) → opaque client
///   message + `error!` log with the full `{e:#}` cause chain.
/// - Application/business errors (e.g. claim race, not-in-claimed-state) →
///   keep the actionable message; log at `warn!` so they are not mistaken for
///   infrastructure failures (#250 review).
pub(crate) fn graphql_db_err(e: anyhow::Error) -> async_graphql::Error {
    if anyhow_has_sqlx(&e) {
        tracing::error!(error = %format!("{e:#}"), "graphql database error");
        async_graphql::Error::new(GRAPHQL_DB_ERROR_MESSAGE)
    } else {
        tracing::warn!(error = %format!("{e:#}"), "graphql application error");
        async_graphql::Error::new(e.to_string())
    }
}

/// Map an `AppError` from a shared collector (e.g. ref-update feed) to a
/// GraphQL error.
///
/// Fail closed: only explicitly curated variants surface their `Display`
/// text. Unnamed variants (including `Git`, which may embed on-disk paths)
/// render opaque so a future addition cannot leak by default (#255 review).
pub(crate) fn graphql_app_err(e: crate::error::AppError) -> async_graphql::Error {
    match e {
        crate::error::AppError::Db(sql) => graphql_db_err(sql.into()),
        crate::error::AppError::Internal(err) => {
            tracing::error!(error = %format!("{err:#}"), "graphql internal error");
            async_graphql::Error::new(GRAPHQL_DB_ERROR_MESSAGE)
        }
        // Curated client-safe variants — `Display` is intentional API text.
        safe @ (crate::error::AppError::RepoNotFound(_)
        | crate::error::AppError::RepoExists(_)
        | crate::error::AppError::Conflict(_)
        | crate::error::AppError::NotFound(_)
        | crate::error::AppError::Unauthorized(_)
        | crate::error::AppError::Forbidden(_)
        | crate::error::AppError::BadRequest(_)
        | crate::error::AppError::TooManyRequests(_)
        | crate::error::AppError::Incomplete(_)) => {
            tracing::warn!(error = %safe, "graphql application error");
            async_graphql::Error::new(safe.to_string())
        }
        other => {
            tracing::error!(error = %other, "graphql unclassified AppError (opaque)");
            async_graphql::Error::new(GRAPHQL_DB_ERROR_MESSAGE)
        }
    }
}

pub fn build_schema(
    db: Arc<Db>,
    ref_update_tx: tokio::sync::broadcast::Sender<RefUpdateBroadcast>,
    task_event_tx: tokio::sync::broadcast::Sender<TaskEventBroadcast>,
) -> GitlawbSchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .data(db)
        .data(ref_update_tx)
        .data(task_event_tx)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphql_db_err_opaques_sqlx_chain() {
        let leak = "error returned from database: column \"is_public\" does not exist";
        // Context layer must not hide sqlx from the chain walk (db helpers
        // wrap with `.context(...)` in several places).
        let err = graphql_db_err(
            anyhow::Error::from(sqlx::Error::Protocol(leak.into())).context("loading repos"),
        );
        assert_eq!(err.message, GRAPHQL_DB_ERROR_MESSAGE);
        assert!(!err.message.contains("is_public"));
        assert!(!err.message.contains(leak));
        assert!(!err.message.contains("loading repos"));
    }

    #[test]
    fn graphql_db_err_keeps_business_message() {
        let msg = "task not claimable: not found or already claimed";
        let err = graphql_db_err(anyhow::anyhow!("{msg}"));
        assert_eq!(err.message, msg);
    }

    #[test]
    fn graphql_app_err_opaques_db_and_internal() {
        let leak = "column \"is_public\" does not exist";
        let db_err = graphql_app_err(crate::error::AppError::Db(sqlx::Error::Protocol(
            leak.into(),
        )));
        assert_eq!(db_err.message, GRAPHQL_DB_ERROR_MESSAGE);
        assert!(!db_err.message.contains("is_public"));

        let internal = graphql_app_err(crate::error::AppError::Internal(anyhow::anyhow!(
            "loading repo: {leak}"
        )));
        assert_eq!(internal.message, GRAPHQL_DB_ERROR_MESSAGE);
        assert!(!internal.message.contains("is_public"));
    }

    #[test]
    fn graphql_app_err_keeps_safe_variant_messages() {
        let err = graphql_app_err(crate::error::AppError::NotFound("widget".into()));
        assert!(
            err.message.contains("widget"),
            "safe NotFound message must reach the client: {}",
            err.message
        );
        assert_ne!(err.message, GRAPHQL_DB_ERROR_MESSAGE);

        let err = graphql_app_err(crate::error::AppError::BadRequest("bad cid".into()));
        assert!(
            err.message.contains("bad cid"),
            "safe BadRequest message must reach the client: {}",
            err.message
        );
        assert_ne!(err.message, GRAPHQL_DB_ERROR_MESSAGE);
    }

    #[test]
    fn graphql_app_err_opaques_unclassified_variants() {
        // `Git` may embed on-disk paths from libgit2; fail closed.
        let path = "/var/lib/gitlawb/repos/owner/secret.git";
        let err = graphql_app_err(crate::error::AppError::Git(format!(
            "failed to open '{path}'"
        )));
        assert_eq!(err.message, GRAPHQL_DB_ERROR_MESSAGE);
        assert!(!err.message.contains(path));
        assert!(!err.message.contains("failed to open"));
    }

    /// Every `.map_err(` in the GraphQL query/mutation resolvers must route
    /// through the opaque helpers, or discard the error (`|_|`). Same source-
    /// scrape pattern as `api::authz_guard` (#255 review).
    #[test]
    fn every_graphql_map_err_uses_opaque_helpers() {
        for (file, src) in [
            ("query.rs", include_str!("query.rs")),
            ("mutation.rs", include_str!("mutation.rs")),
        ] {
            for (lineno, line) in src.lines().enumerate() {
                let code = line.split("//").next().unwrap_or(line);
                let Some(idx) = code.find(".map_err(") else {
                    continue;
                };
                let after = code[idx + ".map_err(".len()..].trim_start();
                let ok = after.starts_with("crate::graphql::graphql_db_err")
                    || after.starts_with("crate::graphql::graphql_app_err")
                    || after.starts_with("|_|")
                    || after.starts_with("|_ ");
                assert!(
                    ok,
                    "{file}:{}: `.map_err(` must use graphql_db_err / graphql_app_err \
                     or discard (`|_|`): {line}",
                    lineno + 1
                );
            }
        }
    }
}

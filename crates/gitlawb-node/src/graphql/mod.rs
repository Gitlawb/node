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

/// Classify a failed `claim_task` for GraphQL exactly as REST's claim handler
/// classifies it: a lost race is a client-safe conflict, a real sqlx fault
/// stays opaque. Lives here rather than at the three call sites so the
/// classification cannot drift between transports (#327 review), and so
/// `every_graphql_map_err_uses_opaque_helpers` can keep whitelisting by name.
pub(crate) fn graphql_claim_conflict(e: anyhow::Error) -> async_graphql::Error {
    graphql_app_err(crate::api::tasks::task_write_conflict(
        e,
        "task not claimable: not found or already claimed",
    ))
}

/// The `finish_task` half of [`graphql_claim_conflict`], covering both
/// `completeTask` and `failTask`.
pub(crate) fn graphql_finish_conflict(e: anyhow::Error) -> async_graphql::Error {
    graphql_app_err(crate::api::tasks::task_write_conflict(
        e,
        "task not found or not in claimed state",
    ))
}

pub struct TaskReadBrakeExtension;

impl async_graphql::extensions::ExtensionFactory for TaskReadBrakeExtension {
    fn create(&self) -> Arc<dyn async_graphql::extensions::Extension> {
        Arc::new(TaskReadBrakeExtensionImpl)
    }
}

use async_graphql::async_trait::async_trait;

struct TaskReadBrakeExtensionImpl;

#[async_trait]
impl async_graphql::extensions::Extension for TaskReadBrakeExtensionImpl {
    async fn prepare_request(
        &self,
        ctx: &async_graphql::extensions::ExtensionContext<'_>,
        mut request: async_graphql::Request,
        next: async_graphql::extensions::NextPrepareRequest<'_>,
    ) -> async_graphql::ServerResult<async_graphql::Request> {
        if let Some(session_brake) = ctx
            .session_data
            .get(&std::any::TypeId::of::<crate::rate_limit::TaskReadBrake>())
            .and_then(|d| d.downcast_ref::<crate::rate_limit::TaskReadBrake>())
        {
            request = request.data(crate::rate_limit::TaskReadBrake {
                limiter: session_brake.limiter.clone(),
                key: session_brake.key.clone(),
                request_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            });
        }
        if let Some(did) = ctx
            .session_data
            .get(&std::any::TypeId::of::<crate::auth::AuthenticatedDid>())
            .and_then(|d| d.downcast_ref::<crate::auth::AuthenticatedDid>())
        {
            request = request.data(did.clone());
        }
        next.run(ctx, request).await
    }
}

pub fn build_schema(
    db: Arc<Db>,
    ref_update_tx: tokio::sync::broadcast::Sender<RefUpdateBroadcast>,
    task_event_tx: tokio::sync::broadcast::Sender<TaskEventBroadcast>,
    task_cursor_key: crate::api::task_cursor::TaskCursorKey,
) -> GitlawbSchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .data(db)
        .data(ref_update_tx)
        .data(task_event_tx)
        .data(task_cursor_key)
        .extension(TaskReadBrakeExtension)
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
    /// through one of the curated helpers in this module, or discard the error
    /// (`|_|`). Same source-scrape pattern as `api::authz_guard` (#255
    /// review). The list is deliberately a whitelist of names rather than a
    /// prefix match, so adding a new mapper is a decision a reviewer sees.
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
                    || after.starts_with("crate::graphql::graphql_claim_conflict")
                    || after.starts_with("crate::graphql::graphql_finish_conflict")
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

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
/// GraphQL error. DB variants are opaque; other variants stay opaque too
/// because `AppError::Internal` can still carry raw detail on this base.
pub(crate) fn graphql_app_err(e: crate::error::AppError) -> async_graphql::Error {
    match e {
        crate::error::AppError::Db(sql) => graphql_db_err(sql.into()),
        other => {
            tracing::error!(error = %other, "graphql error");
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
        let err = graphql_db_err(anyhow::Error::from(sqlx::Error::Protocol(leak.into())));
        assert_eq!(err.message, GRAPHQL_DB_ERROR_MESSAGE);
        assert!(!err.message.contains("is_public"));
        assert!(!err.message.contains(leak));
    }

    #[test]
    fn graphql_db_err_keeps_business_message() {
        let msg = "task not claimable: not found or already claimed";
        let err = graphql_db_err(anyhow::anyhow!("{msg}"));
        assert_eq!(err.message, msg);
    }
}

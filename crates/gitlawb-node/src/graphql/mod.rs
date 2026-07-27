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

/// Client-facing message for GraphQL resolver DB failures. The real error is
/// logged server-side; never put sqlx/anyhow detail in the GraphQL `errors`
/// array (#250 — sibling of #226, which only covers `AppError`).
pub const GRAPHQL_DB_ERROR_MESSAGE: &str = "a database error occurred";

/// Map a database/`anyhow` failure to an opaque GraphQL error: log the full
/// cause chain (`{e:#}` for anyhow) and return a generic client message.
pub(crate) fn graphql_db_err(e: impl std::fmt::Display) -> async_graphql::Error {
    tracing::error!(error = %format!("{e:#}"), "graphql database error");
    async_graphql::Error::new(GRAPHQL_DB_ERROR_MESSAGE)
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
    fn graphql_db_err_is_opaque() {
        let leak = "error returned from database: column \"is_public\" does not exist";
        let err = graphql_db_err(anyhow::anyhow!("{leak}"));
        assert_eq!(err.message, GRAPHQL_DB_ERROR_MESSAGE);
        assert!(!err.message.contains("is_public"));
        assert!(!err.message.contains(leak));
    }
}

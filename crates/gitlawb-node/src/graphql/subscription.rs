use async_graphql::futures_util::Stream;
use async_graphql::{Context, Subscription};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;

use crate::state::{RefUpdateBroadcast, TaskEventBroadcast};

use super::types::{RefUpdateType, TaskEventType};

pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Live ref-update stream. `/graphql/ws` is mounted outside the
    /// `optional_signature` layer, so this resolver has NO caller identity and
    /// cannot gate per-subscriber — it relays whatever enters the broadcast
    /// channel to any anonymous client. Its visibility safety therefore rests
    /// entirely on the WRITE side: the push handler only sends a
    /// `RefUpdateBroadcast` for repos the anonymous public may read (inside its
    /// `if announce` block, `api/repos.rs`). This is a single-point invariant —
    /// any new sender to `ref_update_tx` MUST be `announce`-gated, or private-repo
    /// ref metadata leaks here to unauthenticated subscribers (#112/#114 class).
    async fn ref_updates(
        &self,
        ctx: &Context<'_>,
        repo: Option<String>,
    ) -> impl Stream<Item = RefUpdateType> {
        let rx = ctx
            .data_unchecked::<tokio::sync::broadcast::Sender<RefUpdateBroadcast>>()
            .subscribe();
        BroadcastStream::new(rx).filter_map(move |r| {
            let rf = repo.clone();
            match r {
                Ok(ev) if rf.as_deref().is_none_or(|r| ev.repo == r) => Some(RefUpdateType {
                    repo: ev.repo,
                    ref_name: ev.ref_name,
                    old_sha: ev.old_sha,
                    new_sha: ev.new_sha,
                    pusher_did: ev.pusher_did,
                    node_did: ev.node_did,
                    timestamp: ev.timestamp,
                    owner_did: Some(ev.owner_did),
                }),
                _ => None,
            }
        })
    }

    async fn task_events(
        &self,
        ctx: &Context<'_>,
        task_id: Option<String>,
    ) -> impl Stream<Item = TaskEventType> {
        let rx = ctx
            .data_unchecked::<tokio::sync::broadcast::Sender<TaskEventBroadcast>>()
            .subscribe();
        BroadcastStream::new(rx).filter_map(move |r| {
            let tf = task_id.clone();
            match r {
                Ok(ev) if tf.as_deref().is_none_or(|id| ev.task_id == id) => Some(TaskEventType {
                    task_id: ev.task_id,
                    old_status: ev.old_status,
                    new_status: ev.new_status,
                    by_did: ev.by_did,
                    at: ev.at,
                }),
                _ => None,
            }
        })
    }
}

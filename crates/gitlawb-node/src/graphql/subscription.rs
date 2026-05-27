use async_graphql::futures_util::Stream;
use async_graphql::{Context, Subscription};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;

use crate::state::{RefUpdateBroadcast, TaskEventBroadcast};

use super::types::{RefUpdateType, TaskEventType};

pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
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
                Ok(ev) if tf.as_deref().is_none_or(|id| ev.task_id == id) => {
                    Some(TaskEventType {
                        task_id: ev.task_id,
                        old_status: ev.old_status,
                        new_status: ev.new_status,
                        by_did: ev.by_did,
                        at: ev.at,
                    })
                }
                _ => None,
            }
        })
    }
}

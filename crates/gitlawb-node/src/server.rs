use async_graphql::http::ALL_WEBSOCKET_PROTOCOLS;
use async_graphql_axum::{GraphQLProtocol, GraphQLRequest, GraphQLResponse, GraphQLWebSocket};
use axum::extract::{DefaultBodyLimit, WebSocketUpgrade};
use axum::{
    extract::State,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::{DefaultOnFailure, DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::api::{
    agents, arweave, bounties, certs, changelog, events, ipfs, issues, labels, peers, profiles,
    protect, pulls, register, replicas, repos, resolve, stars, tasks, visibility, webhooks,
};
use crate::auth;
use crate::rate_limit;
use crate::state::AppState;

async fn graphql_handler(
    State(state): State<AppState>,
    auth: Option<axum::Extension<crate::auth::AuthenticatedDid>>,
    headers: axum::http::HeaderMap,
    rate_limit::PeerAddr(peer): rate_limit::PeerAddr,
    req: GraphQLRequest,
) -> GraphQLResponse {
    // `optional_signature` attaches the verified DID when a signature is present.
    // Thread it into request-scoped GraphQL data; mutations enforce its presence
    // in-resolver (N2) while queries stay open.
    let mut inner = req.into_inner();
    if let Some(axum::Extension(did)) = auth {
        inner = inner.data(did);
    }
    // The anonymous `tasks`/`task` resolvers run the same #268 visibility gate
    // as the REST read routes and cost the node the same queries, so they carry
    // the same per-IP brake. It rides as request data rather than a router layer
    // because /graphql is one endpoint for every operation — see `TaskReadBrake`
    // (#327 review). It debits before the gate runs, but unlike the REST layer
    // it sits inside `optional_signature`, so it brakes the gate's query cost
    // and not signature verification.
    inner = inner.data(rate_limit::TaskReadBrake {
        limiter: state.task_read_rate_limiter.clone(),
        key: rate_limit::client_key(&headers, peer, state.push_limiter_trust),
        request_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    });
    state.graphql_schema.execute(inner).await.into()
}

async fn graphql_ws_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    rate_limit::PeerAddr(peer): rate_limit::PeerAddr,
    auth: Option<axum::Extension<auth::AuthenticatedDid>>,
    protocol: GraphQLProtocol,
    upgrade: WebSocketUpgrade,
) -> axum::response::Response {
    let mut data = async_graphql::Data::default();
    if let Some(axum::Extension(did)) = auth {
        data.insert(did);
    }
    data.insert(rate_limit::TaskReadBrake {
        limiter: state.task_read_rate_limiter.clone(),
        key: rate_limit::client_key(&headers, peer, state.push_limiter_trust),
        request_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    });
    let schema = state.graphql_schema.as_ref().clone();
    upgrade
        .protocols(ALL_WEBSOCKET_PROTOCOLS)
        .on_upgrade(move |stream| {
            GraphQLWebSocket::new(stream, schema, protocol)
                .with_data(data)
                .serve()
        })
        .into_response()
}

async fn graphql_playground() -> impl IntoResponse {
    axum::response::Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql")
            .subscription_endpoint("/graphql/ws"),
    ))
}

/// Pre-auth body-buffer ceiling for every signed route group except the git write
/// routes. Deliberately equal to axum's `DefaultBodyLimit` (2 MB), which is what
/// these groups' `Bytes`/`Json` extractors already enforce: that default works
/// through a request extension the extractors consult, and `require_signature`
/// collects the raw body itself, so it never saw the cap. Matching the number
/// keeps this change behavior-preserving on the response path (nothing that used
/// to be accepted starts failing) and purely a memory fix.
pub const SIGNED_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// Applies the standard auth middleware pair to a router: HTTP Signature verification
/// followed by UCAN chain validation. The two layers run in this order for every
/// matched request: `require_signature` first (sets `AuthenticatedDid`), then
/// `require_ucan_chain` (reads it).
///
/// `body_limit` bounds the request body `require_signature` buffers before it has
/// authenticated anything (see [`auth::SignatureBodyLimit`]): `max_pack_bytes` for
/// the git write group, [`SIGNED_BODY_LIMIT`] for every other group.
fn add_auth_layers(
    router: Router<AppState>,
    state: AppState,
    body_limit: usize,
) -> Router<AppState> {
    router
        .layer(middleware::from_fn_with_state(
            state,
            auth::require_ucan_chain,
        ))
        .layer(middleware::from_fn_with_state(
            auth::SignatureBodyLimit(body_limit),
            auth::require_signature,
        ))
}

/// Attach the shared per-IP write brake to an authenticated write-route group,
/// outermost so a flood is rejected before signature verification. Every
/// authenticated non-creation write group MUST call this or it silently ships
/// unbraked with no compile error. Deliberately a separate call, NOT folded into
/// `add_auth_layers`: the creation routes use a different bucket
/// (`create_ip_rate_limiter`) and the graphql group is not built through
/// `add_auth_layers`, so a helper keyed on auth would attach the wrong limiter.
trait WriteBraked {
    fn write_braked(self, limiter: &rate_limit::IpRateLimiter) -> Self;
}

impl WriteBraked for Router<AppState> {
    fn write_braked(self, limiter: &rate_limit::IpRateLimiter) -> Self {
        self.layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
            .layer(axum::Extension(limiter.clone()))
    }
}

pub fn build_router(state: AppState) -> Router {
    // ── GraphQL routes ─────────────────────────────────────────────────────
    // Per-IP write brake, shared across every authenticated non-creation write
    // group (see `AppState::write_rate_limiter`). Built once here so each group
    // clones the same bucket; attached outermost on each group so a flood is
    // rejected before auth runs. Separate bucket from the creation brake.
    let write_ip_limiter = rate_limit::IpRateLimiter {
        limiter: state.write_rate_limiter.clone(),
        trust: state.push_limiter_trust,
    };

    let graphql_routes = Router::new()
        .route("/graphql", get(graphql_playground).post(graphql_handler))
        .route("/graphql/ws", get(graphql_ws_handler))
        // Attach the verified DID to /graphql and /graphql/ws when a signature is
        // present. The per-IP write brake covers the same /graphql (KTD-5: an
        // HTTP-layer brake cannot tell a query POST from a mutation POST, so it
        // counts every /graphql request — acceptable, both cost work);
        // /graphql/ws subscriptions stay unbraked.
        .layer(middleware::from_fn_with_state(
            auth::SignatureBodyLimit(SIGNED_BODY_LIMIT),
            auth::optional_signature,
        ))
        .write_braked(&write_ip_limiter);

    // ── Task routes (write — require HTTP Signature + per-IP write brake) ──
    let task_write_routes = add_auth_layers(
        Router::new()
            .route("/api/v1/tasks", post(tasks::create_task))
            .route("/api/v1/tasks/{id}/claim", post(tasks::claim_task))
            .route("/api/v1/tasks/{id}/complete", post(tasks::complete_task))
            .route("/api/v1/tasks/{id}/fail", post(tasks::fail_task)),
        state.clone(),
        SIGNED_BODY_LIMIT,
    )
    .write_braked(&write_ip_limiter);

    // ── Task routes (read — open, but scoped) ──────────────────────────────
    // `optional_signature` attaches the verified DID when a signature is present
    // so the handlers can identify the caller; the routes stay anonymous-reachable,
    // but each task/row is gated to its delegator, its assignee, or (for a
    // repo-scoped task) whoever can read that repo (#268 — these routes previously
    // carried no gate and no identity at all).
    // Both routes also carry a per-IP flood brake, mirroring `/ipfs/{cid}`: they are
    // anon-reachable and the gate above costs a task lookup plus deduped-repo and
    // visibility-rule queries *before* the opaque 404, so a prober pays nothing and
    // the node pays per request. The limiter is the outermost layer so a flood is
    // rejected before signature verification and the visibility queries run. The
    // extension MUST be attached or `rate_limit_by_ip` is a silent no-op.
    let task_read_limiter = rate_limit::IpRateLimiter {
        limiter: state.task_read_rate_limiter.clone(),
        trust: state.push_limiter_trust,
    };
    let task_read_routes = Router::new()
        .route("/api/v1/tasks", get(tasks::list_tasks))
        .route("/api/v1/tasks/{id}", get(tasks::get_task))
        .layer(middleware::from_fn_with_state(
            auth::SignatureBodyLimit(SIGNED_BODY_LIMIT),
            auth::optional_signature,
        ))
        .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
        .layer(axum::Extension(task_read_limiter));

    // ── Rate-limited creation routes — require HTTP Signature, plus a per-DID
    // throttle AND a per-IP flood brake. The per-DID limiter (inner) caps a
    // single identity; the per-IP limiter (outer) caps a DID farm that mints a
    // fresh throwaway did:key per repo to slip past both the per-DID limit and
    // the iCaptcha gate — the mechanism behind the recurring spam-repo floods.
    // The per-IP layer wraps the auth layer (outermost = runs first) so flood
    // traffic is rejected before signature verification burns CPU, matching the
    // push path.
    let limiter = state.rate_limiter.clone();
    let create_ip_limiter = rate_limit::IpRateLimiter {
        limiter: state.create_ip_rate_limiter.clone(),
        trust: state.push_limiter_trust,
    };
    let creation_routes = add_auth_layers(
        Router::new()
            .route("/api/v1/repos", post(repos::create_repo))
            .route("/api/register", post(register::register))
            .route("/api/v1/repos/{owner}/{repo}/fork", post(repos::fork_repo))
            .route(
                "/api/v1/repos/{owner}/{repo}/issues",
                post(issues::create_issue),
            )
            .route("/api/v1/repos/{owner}/{repo}/pulls", post(pulls::create_pr))
            .layer(middleware::from_fn(rate_limit::rate_limit_by_did))
            .layer(axum::Extension(limiter)),
        state.clone(),
        SIGNED_BODY_LIMIT,
    )
    .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
    .layer(axum::Extension(create_ip_limiter));

    // ── Write routes — require HTTP Signature + per-IP write brake ────────
    // Same per-IP flood defense as the creation routes, on its own `write`
    // bucket (see `AppState::write_rate_limiter`). Per-DID is deliberately not
    // paired (a DID farm never trips it; busy legitimate agents would false-
    // positive). The bundled visibility GET is a read that also draws from the
    // write bucket — harmless, since the bucket is sized far above any legit
    // per-IP read rate.
    let write_routes = add_auth_layers(
        Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/pulls/{number}/merge",
                post(pulls::merge_pr),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/pulls/{number}/close",
                post(pulls::close_pr),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews",
                post(pulls::create_review),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/pulls/{number}/comments",
                post(pulls::create_comment),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/hooks",
                post(webhooks::create_webhook),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/hooks/{id}",
                axum::routing::delete(webhooks::delete_webhook),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/branches/{branch}/protect",
                post(protect::protect_branch),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/branches/{branch}/protect",
                axum::routing::delete(protect::unprotect_branch),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/star",
                axum::routing::put(stars::star_repo),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/star",
                axum::routing::delete(stars::unstar_repo),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/replicas",
                axum::routing::put(replicas::register_replica),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/replicas",
                axum::routing::delete(replicas::unregister_replica),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/labels",
                post(labels::add_label),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/labels/{label}",
                axum::routing::delete(labels::remove_label),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/visibility",
                axum::routing::put(visibility::set_visibility)
                    .delete(visibility::remove_visibility)
                    .get(visibility::list_visibility),
            )
            .route(
                "/api/v1/agents/{did}",
                axum::routing::delete(agents::deregister_agent),
            ),
        state.clone(),
        SIGNED_BODY_LIMIT,
    )
    .write_braked(&write_ip_limiter);

    // Body limit is raised to GITLAWB_MAX_PACK_BYTES (default 2 GB) for git
    // routes only — all other API routes keep axum's default 2 MB cap.
    // HTTP Signature is enforced on receive-pack (push) — the git-remote-gitlawb
    // helper signs requests with RFC 9421 signatures using the agent's keypair.
    let pack_limit = state.config.max_pack_bytes;
    // Per-IP throttle wraps the auth layer (outermost = runs first): flood
    // traffic is rejected before signature verification burns CPU. Per-DID
    // limiting is deliberately NOT used here — a DID farm (one throwaway
    // identity per repo, as in the June 2026 push flood) never trips it.
    let push_limiter = rate_limit::IpRateLimiter {
        limiter: state.push_rate_limiter.clone(),
        trust: state.push_limiter_trust,
    };
    let git_write_routes = add_auth_layers(
        Router::new()
            .route(
                "/{owner}/{repo}/git-receive-pack",
                post(repos::git_receive_pack),
            )
            .layer(DefaultBodyLimit::disable())
            .layer(RequestBodyLimitLayer::new(pack_limit)),
        state.clone(),
        pack_limit,
    )
    .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
    .layer(axum::Extension(push_limiter));

    // ── IPFS content-addressed retrieval and pin listing ──────────────────
    // Two independent sub-routers, then merged. They share a URL prefix family
    // but have separate rate-limit policies and must not share a bucket.
    //
    // `/ipfs/{cid}` (CID resolver): carries `optional_signature` so `get_by_cid`
    // sees the caller identity and can apply per-repo visibility (#110); anon
    // callers stay anonymous and still read genuinely public content. The
    // per-IP flood brake is layered on because the resolver is anon-reachable
    // and each request can drive a full-history git walk — the brake is the
    // outermost layer (rejects a flood before the walk-admission work), mirroring
    // the push/create routers. The `IpRateLimiter` extension MUST be attached
    // or `rate_limit_by_ip` is a silent no-op.
    //
    // `/api/v1/ipfs/pins` (pin listing): now carries `optional_signature` only
    // (#121). The handler rejects requests without a verified `AuthenticatedDid`
    // with 401. It does NOT carry the CID flood brake — `list_pins` is a single
    // `list_pinned_cids()` call, no walk, and routing pins through the resolver's
    // bucket would let `/ipfs/{cid}` traffic exhaust the bucket and 429 the
    // pins endpoint, or let signed pin polling exhaust the bucket for legitimate
    // CID reads. The two surfaces have separate availability contracts.
    //
    // Both sub-routers are built first with their own layer sets, then merged.
    // This is the structure the prior routing guidance called for and the
    // earlier 429 test for `/ipfs/{cid}` (test_support.rs) assumes.
    let ipfs_limiter = rate_limit::IpRateLimiter {
        limiter: state.ipfs_rate_limiter.clone(),
        trust: state.push_limiter_trust,
    };
    let ipfs_cid_routes = Router::new()
        .route("/ipfs/{cid}", get(ipfs::get_by_cid))
        .layer(middleware::from_fn_with_state(
            auth::SignatureBodyLimit(SIGNED_BODY_LIMIT),
            auth::optional_signature,
        ))
        .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
        .layer(axum::Extension(ipfs_limiter));
    let ipfs_pins_routes = Router::new()
        .route("/api/v1/ipfs/pins", get(ipfs::list_pins))
        .layer(middleware::from_fn_with_state(
            auth::SignatureBodyLimit(SIGNED_BODY_LIMIT),
            auth::optional_signature,
        ));
    let ipfs_routes = ipfs_cid_routes.merge(ipfs_pins_routes);

    // ── Arweave permanent anchors ──────────────────────────────────────────
    // `list_anchors` rejects callers without a verified `AuthenticatedDid`, so
    // unsigned enumeration is denied. The same `optional_signature` layer used
    // on the other read surfaces is applied here, closing the anonymous
    // anchor-listing gap alongside `/api/v1/ipfs/pins`. The verify endpoint
    // and its probe are deferred to the vertical slice with the uploader and
    // a real provider contract.
    let arweave_routes = Router::new()
        .route("/api/v1/arweave/anchors", get(arweave::list_anchors))
        .layer(middleware::from_fn_with_state(
            auth::SignatureBodyLimit(SIGNED_BODY_LIMIT),
            auth::optional_signature,
        ));

    // ── Bounty routes (write — require HTTP Signature) ─────────────────
    let bounty_write_routes = add_auth_layers(
        Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/bounties",
                post(bounties::create_bounty),
            )
            .route("/api/v1/bounties/{id}/claim", post(bounties::claim_bounty))
            .route(
                "/api/v1/bounties/{id}/submit",
                post(bounties::submit_bounty),
            )
            .route(
                "/api/v1/bounties/{id}/approve",
                post(bounties::approve_bounty),
            )
            .route(
                "/api/v1/bounties/{id}/cancel",
                post(bounties::cancel_bounty),
            )
            .route(
                "/api/v1/bounties/{id}/dispute",
                post(bounties::dispute_bounty),
            ),
        state.clone(),
        SIGNED_BODY_LIMIT,
    )
    .write_braked(&write_ip_limiter);

    // ── Bounty routes (read — open) ──────────────────────────────────────
    let bounty_read_routes = Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/bounties",
            get(bounties::list_repo_bounties),
        )
        .route("/api/v1/bounties", get(bounties::list_all_bounties))
        .route("/api/v1/bounties/{id}", get(bounties::get_bounty))
        .route("/api/v1/bounties/stats", get(bounties::bounty_stats))
        .route(
            "/api/v1/agents/{did}/bounties",
            get(bounties::agent_bounty_stats),
        )
        .layer(middleware::from_fn_with_state(
            auth::SignatureBodyLimit(SIGNED_BODY_LIMIT),
            auth::optional_signature,
        ));

    // ── Profile routes (write — require HTTP Signature) ─────────────────
    let profile_write_routes = add_auth_layers(
        Router::new().route("/api/v1/profile", axum::routing::put(profiles::set_profile)),
        state.clone(),
        SIGNED_BODY_LIMIT,
    )
    .write_braked(&write_ip_limiter);

    // ── Issue routes (write — require HTTP Signature + per-IP write brake) ─
    let issue_write_routes = add_auth_layers(
        Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/issues/{id}/close",
                post(issues::close_issue),
            )
            .route(
                "/api/v1/repos/{owner}/{repo}/issues/{id}/comments",
                post(issues::create_issue_comment),
            ),
        state.clone(),
        SIGNED_BODY_LIMIT,
    )
    .write_braked(&write_ip_limiter);

    // ── Peer discovery routes ─────────────────────────────────────────────
    // Peer writes accept signatures when present and can require them after a
    // coordinated live-network upgrade.
    let peer_read_routes = Router::new()
        .route("/api/v1/peers", get(peers::list_peers))
        .route("/api/v1/peers/{did}/ping", get(peers::ping_peer));

    // /sync/trigger drives an O(peers) outbound fan-out + per-repo enqueue, so it
    // ALWAYS requires a signature (both config modes) and carries a tight per-IP
    // brake. A signature alone does not cap cost — a did:key farm self-registers
    // (INV-10) — so the IP brake is a separate, load-bearing half. The brake is
    // outermost (runs before signature verification burns CPU) and is keyed on the
    // client IP before any DID is read, so DID rotation cannot bypass it.
    let sync_trigger_routes = add_auth_layers(
        Router::new().route("/api/v1/sync/trigger", post(peers::trigger_sync)),
        state.clone(),
        SIGNED_BODY_LIMIT,
    )
    .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
    .layer(axum::Extension(rate_limit::IpRateLimiter {
        limiter: state.sync_trigger_rate_limiter.clone(),
        trust: state.push_limiter_trust,
    }));

    // announce + notify keep their rolling-upgrade signature behavior (unsigned
    // accepted until all peers upgrade), but both reach peer-write side effects —
    // notify hits the same enqueue_sync sink as trigger — so they carry a per-IP
    // brake too, on a SEPARATE bucket from trigger's, so an unsigned notify flood
    // cannot drain the signed trigger caller's quota.
    let mut peer_write_routes = Router::new()
        .route("/api/v1/peers/announce", post(peers::announce))
        .route("/api/v1/sync/notify", post(peers::notify_sync));
    peer_write_routes = if state.config.require_signed_peer_writes {
        add_auth_layers(peer_write_routes, state.clone(), SIGNED_BODY_LIMIT)
    } else {
        peer_write_routes.layer(middleware::from_fn_with_state(
            auth::SignatureBodyLimit(SIGNED_BODY_LIMIT),
            auth::optional_signature,
        ))
    };
    let peer_write_routes = peer_write_routes
        .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
        .layer(axum::Extension(rate_limit::IpRateLimiter {
            limiter: state.peer_write_rate_limiter.clone(),
            trust: state.push_limiter_trust,
        }));

    // ── Read routes — open for public repos ───────────────────────────────
    let read_routes = Router::new()
        .route("/api/v1/repos", get(repos::list_repos))
        .route(
            "/api/v1/repos/federated",
            get(repos::list_federated_repos)
                .route_layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
                .route_layer(axum::Extension(rate_limit::IpRateLimiter {
                    limiter: state.federated_rate_limiter.clone(),
                    trust: state.push_limiter_trust,
                })),
        )
        .route("/api/v1/repos/{owner}/{repo}", get(repos::get_repo))
        .route(
            "/api/v1/repos/{owner}/{repo}/commits",
            get(repos::list_commits),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/tree",
            get(repos::get_tree_root),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/tree/{*path}",
            get(repos::get_tree),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/blob/{*path}",
            get(repos::get_blob),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/issues",
            get(issues::list_issues),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/issues/{id}",
            get(issues::get_issue),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/issues/{id}/comments",
            get(issues::list_issue_comments),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/labels",
            get(labels::list_labels),
        )
        .route("/api/v1/repos/{owner}/{repo}/certs", get(certs::list_certs))
        .route(
            "/api/v1/repos/{owner}/{repo}/certs/{id}",
            get(certs::get_cert),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/events",
            get(events::list_repo_events),
        )
        .route("/api/v1/agents", get(agents::list_agents))
        .route("/api/v1/agents/{did}", get(agents::show_agent))
        .route("/api/v1/agents/{did}/trust", get(agents::get_trust))
        .route("/api/v1/agents/{did}/profile", get(profiles::get_profile))
        .route("/api/v1/events/ref-updates", get(events::list_ref_updates))
        .route("/api/v1/resolve/{did}", get(resolve::resolve_did))
        .route("/api/v1/repos/{owner}/{repo}/pulls", get(pulls::list_prs))
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}",
            get(pulls::get_pr),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/diff",
            get(pulls::get_pr_diff),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews",
            get(pulls::list_reviews),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/comments",
            get(pulls::list_comments),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/hooks",
            get(webhooks::list_webhooks),
        )
        .route("/api/v1/repos/{owner}/{repo}/refs", get(repos::list_refs))
        .route(
            "/api/v1/repos/{owner}/{repo}/branches/protected",
            get(protect::list_protected_branches),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/changelog",
            get(changelog::get_changelog),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/star",
            get(stars::get_star_status),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/replicas",
            get(replicas::list_replicas),
        )
        .layer(middleware::from_fn_with_state(
            auth::SignatureBodyLimit(SIGNED_BODY_LIMIT),
            auth::optional_signature,
        ));

    // git-upload-pack (clone/fetch) — same raised body limit as receive-pack so
    // large pack responses from the server don't get truncated on the client side.
    let git_read_routes = Router::new()
        .route("/{owner}/{repo}/info/refs", get(repos::git_info_refs))
        .route(
            "/{owner}/{repo}/git-upload-pack",
            post(repos::git_upload_pack),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/withheld-paths",
            axum::routing::get(visibility::withheld_paths),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/icaptcha-proof",
            axum::routing::get(repos::get_icaptcha_proof),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/encrypted-blobs",
            axum::routing::get(crate::api::encrypted::list_encrypted_blobs),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/encrypted-blob/{oid}",
            axum::routing::get(crate::api::encrypted::get_encrypted_blob),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/encrypted-blobs/replicate",
            axum::routing::get(crate::api::encrypted::replicate_encrypted_blobs),
        )
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(pack_limit))
        // `pack_limit`, not SIGNED_BODY_LIMIT: git-upload-pack POSTs live here and
        // the group has deliberately raised its ceiling, so the pre-auth buffer for
        // a signed fetch negotiation must match rather than narrow it.
        .layer(middleware::from_fn_with_state(
            auth::SignatureBodyLimit(pack_limit),
            auth::optional_signature,
        ));

    // ── Meta ──────────────────────────────────────────────────────────────
    let meta_routes = Router::new()
        .route("/", get(node_info))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/p2p/info", get(p2p_info))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/contracts", get(contracts_info));

    Router::new()
        .merge(graphql_routes)
        .merge(task_write_routes)
        .merge(task_read_routes)
        .merge(bounty_write_routes)
        .merge(bounty_read_routes)
        .merge(profile_write_routes)
        .merge(creation_routes)
        .merge(write_routes)
        .merge(git_write_routes)
        .merge(git_read_routes)
        .merge(issue_write_routes)
        .merge(read_routes)
        .merge(peer_read_routes)
        .merge(peer_write_routes)
        .merge(sync_trigger_routes)
        .merge(ipfs_routes)
        .merge(arweave_routes)
        .merge(meta_routes)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<_>| {
                    tracing::info_span!(
                        "http_request",
                        method = %request.method(),
                        uri = %request.uri(),
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::DEBUG))
                .on_failure(DefaultOnFailure::new().level(Level::ERROR)),
        )
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// Readiness = "this node can serve real traffic", and every real endpoint
/// depends on the database, so probe it rather than reporting a constant.
/// The probe gets its own short bound so a wedged pool can't hang the health
/// check for the full acquire timeout.
async fn ready(State(state): State<AppState>) -> axum::response::Response {
    let probe = tokio::time::timeout(std::time::Duration::from_secs(2), state.db.ping()).await;
    match probe {
        Ok(Ok(())) => Json(json!({ "status": "ready" })).into_response(),
        _ => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "degraded",
                "error": crate::error::DB_UNAVAILABLE_CODE,
                "message": crate::error::DB_UNAVAILABLE_MESSAGE,
            })),
        )
            .into_response(),
    }
}

async fn node_info(State(state): State<AppState>) -> Json<serde_json::Value> {
    let p2p_peer_id = state.p2p.as_ref().map(|h| h.local_peer_id.to_string());
    let mut body = json!({
        "name": "gitlawb-node",
        "version": env!("CARGO_PKG_VERSION"),
        "did": state.node_did.to_string(),
        "network": "alpha",
        "protocols": ["git-smart-http", "mcp", "libp2p"],
        "auth": "http-signature-rfc9421",
        "identity": "ed25519",
        "p2p_peer_id": p2p_peer_id,
    });
    if let Some(web_url) = &state.config.web_url {
        body["web_url"] = json!(web_url);
    }
    Json(body)
}

pub(crate) async fn stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Count only the repos an anonymous caller could list, so the aggregate does
    // not leak the existence of private/mode-A repos (#104 count oracle). Mirror
    // the listing seam (api/repos.rs): over-fetch the deduped set, batch-load the
    // visibility rules, and keep rows that pass listable_at_root. The caller is
    // always None — meta_routes carries no auth layer (see the route group in this
    // file). Fail closed: any DB error collapses the whole count to 0 (an
    // under-count never leaks existence), preserving the prior `.unwrap_or(0)`.
    let repos = async {
        // stats only needs the count, so use the no-stars deduped list (same
        // DEDUP_CTE) and skip the repo_stars aggregation the listing path needs.
        let rows = state.db.list_all_repos_deduped().await?;
        let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
        let rules_by_repo = state.db.list_visibility_rules_for_repos(&ids).await?;
        let count = rows
            .iter()
            .filter(|r| {
                let rules = rules_by_repo.get(&r.id).map(Vec::as_slice).unwrap_or(&[]);
                crate::visibility::listable_at_root(rules, r.is_public, &r.owner_did, None)
            })
            .count() as i64;
        Ok::<i64, anyhow::Error>(count)
    }
    .await
    .unwrap_or(0);
    let agents = state.db.count_agents().await.unwrap_or(0);
    let pushes = state.db.count_pushes().await.unwrap_or(0);
    Json(json!({
        "repos": repos,
        "agents": agents,
        "pushes": pushes,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn contracts_info(State(state): State<AppState>) -> Json<serde_json::Value> {
    let did_registry = &state.config.contract_did_registry;
    let name_registry = &state.config.contract_name_registry;
    let rpc_url = &state.config.chain_rpc_url;
    let chain_id: u64 = if rpc_url.contains("sepolia") {
        84532
    } else {
        8453
    };
    Json(serde_json::json!({
        "chain": if chain_id == 8453 { "base" } else { "base-sepolia" },
        "chain_id": chain_id,
        "rpc_url": rpc_url,
        "contracts": {
            "did_registry": if did_registry.is_empty() { serde_json::Value::Null } else { serde_json::json!(did_registry) },
            "name_registry": if name_registry.is_empty() { serde_json::Value::Null } else { serde_json::json!(name_registry) },
        },
        "arweave": {
            "enabled": !state.config.irys_url.is_empty(),
            "irys_url": if state.config.irys_url.is_empty() { serde_json::Value::Null } else { serde_json::json!(&state.config.irys_url) },
        }
    }))
}

async fn p2p_info(State(state): State<AppState>) -> Json<serde_json::Value> {
    match &state.p2p {
        Some(h) => {
            let status = h.status().await;
            Json(json!({
                "enabled": true,
                "peer_id": h.local_peer_id.to_string(),
                "topics": [crate::p2p::REF_UPDATES_TOPIC],
                "connected_peers": status.as_ref().map(|s| s.connected_peers),
                "gossipsub_mesh_peers": status.as_ref().map(|s| s.gossipsub_mesh_peers),
                "gossipsub_all_peers": status.as_ref().map(|s| s.gossipsub_all_peers),
                "listen_addrs": status.as_ref().map(|s| s.listen_addrs.clone()),
            }))
        }
        None => Json(json!({ "enabled": false })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_state;
    use sqlx::PgPool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn ws_send_text(stream: &mut tokio::net::TcpStream, text: &str) {
        let payload = text.as_bytes();
        let len = payload.len();
        let mut frame = Vec::new();
        frame.push(0x81);
        let mask = [0x12, 0x34, 0x56, 0x78];
        if len <= 125 {
            frame.push(0x80 | (len as u8));
        } else if len <= 65535 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn ws_recv_text(stream: &mut tokio::net::TcpStream) -> String {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        let b1 = header[1];
        let masked = (b1 & 0x80) != 0;
        let mut len = (b1 & 0x7f) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).await.unwrap();
            len = u16::from_be_bytes(ext) as usize;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).await.unwrap();
            len = u64::from_be_bytes(ext) as usize;
        }
        let mask = if masked {
            let mut m = [0u8; 4];
            stream.read_exact(&mut m).await.unwrap();
            Some(m)
        } else {
            None
        };
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }
        String::from_utf8(payload).unwrap()
    }

    async fn ws_recv_op_frames(stream: &mut tokio::net::TcpStream, op_id: &str) -> Vec<String> {
        let mut frames = Vec::new();
        loop {
            let text = ws_recv_text(stream).await;
            frames.push(text.clone());
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if v.get("id").and_then(|id| id.as_str()) == Some(op_id) {
                    let msg_type = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    if msg_type == "complete" || msg_type == "error" {
                        break;
                    }
                }
            }
        }
        frames
    }

    async fn connect_ws(addr: std::net::SocketAddr) -> tokio::net::TcpStream {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET /graphql/ws HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: graphql-transport-ws\r\n\r\n",
            addr
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 101 Switching Protocols"));

        // Init connection
        ws_send_text(&mut stream, r#"{"type":"connection_init"}"#).await;
        let ack = ws_recv_text(&mut stream).await;
        assert!(ack.contains("connection_ack"));

        stream
    }

    #[sqlx::test]
    async fn graphql_ws_task_query_enforces_per_request_field_limit(pool: PgPool) {
        let state = test_state(pool).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_router(state);
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let mut stream = connect_ws(addr).await;

        // Query with 6 aliased task fields (exceeding MAX_GRAPHQL_TASK_READS_PER_REQUEST = 5).
        // limit: 1 keeps the document under GRAPHQL_MAX_COMPLEXITY so the 6th
        // field reaches the brake instead of failing complexity first.
        let query = r#"{"id":"1","type":"subscribe","payload":{"query":"query { f1: tasks(limit: 1) { items { id } } f2: tasks(limit: 1) { items { id } } f3: tasks(limit: 1) { items { id } } f4: tasks(limit: 1) { items { id } } f5: tasks(limit: 1) { items { id } } f6: tasks(limit: 1) { items { id } } }"}}"#;
        ws_send_text(&mut stream, query).await;
        let frames = ws_recv_op_frames(&mut stream, "1").await;
        let resp = frames.join("\n");
        assert!(
            resp.contains("rate limit exceeded"),
            "6th task field over WS must be braked: {resp}"
        );
    }

    #[sqlx::test]
    async fn graphql_ws_task_query_enforces_per_ip_rate_limit(pool: PgPool) {
        let mut state = test_state(pool).await;
        // Restrict task read rate limiter to 1 request per 60s
        state.task_read_rate_limiter =
            crate::rate_limit::RateLimiter::new(1, std::time::Duration::from_secs(60));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_router(state);
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let mut stream = connect_ws(addr).await;

        // First task query succeeds (or returns valid data)
        let query1 = r#"{"id":"1","type":"subscribe","payload":{"query":"query { tasks { items { id } } }"}}"#;
        ws_send_text(&mut stream, query1).await;
        let frames1 = ws_recv_op_frames(&mut stream, "1").await;
        let resp1 = frames1.join("\n");
        assert!(!resp1.contains("rate limit exceeded"));

        // Second task query on the same connection hits per-IP limiter
        let query2 = r#"{"id":"2","type":"subscribe","payload":{"query":"query { tasks { items { id } } }"}}"#;
        ws_send_text(&mut stream, query2).await;
        let frames2 = ws_recv_op_frames(&mut stream, "2").await;
        let resp2 = frames2.join("\n");
        assert!(
            resp2.contains("rate limit exceeded"),
            "exceeded per-IP limiter over WS must return rate limit message: {resp2}"
        );
    }

    #[sqlx::test]
    async fn graphql_ws_task_query_resets_field_budget_per_operation(pool: PgPool) {
        let state = test_state(pool).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_router(state);
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let mut stream = connect_ws(addr).await;

        // Execute 6 sequential 1-field queries on the same connection.
        // Each operation must receive its own 5-field budget, so none are braked by the per-request limit.
        for i in 1..=6 {
            let id = i.to_string();
            let query = format!(
                r#"{{"id":"{id}","type":"subscribe","payload":{{"query":"query {{ tasks {{ items {{ id }} }} }}"}}}}"#
            );
            ws_send_text(&mut stream, &query).await;
            let frames = ws_recv_op_frames(&mut stream, &id).await;
            let resp = frames.join("\n");
            assert!(
                !resp.contains("rate limit exceeded"),
                "operation {id} on the same WS connection must have a fresh field budget: {resp}"
            );
        }
    }

    async fn connect_ws_signed(
        addr: std::net::SocketAddr,
        keypair: &gitlawb_core::identity::Keypair,
    ) -> tokio::net::TcpStream {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let signed = gitlawb_core::http_sig::sign_request(keypair, "GET", "/graphql/ws", b"");
        let req = format!(
            "GET /graphql/ws HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: graphql-transport-ws\r\n\
             content-digest: {}\r\n\
             signature-input: {}\r\n\
             signature: {}\r\n\r\n",
            addr, signed.content_digest, signed.signature_input, signed.signature
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 101 Switching Protocols"));

        // Init connection
        ws_send_text(&mut stream, r#"{"type":"connection_init"}"#).await;
        let ack = ws_recv_text(&mut stream).await;
        assert!(ack.contains("connection_ack"));

        stream
    }

    #[sqlx::test]
    async fn graphql_ws_authenticated_query_accesses_private_task(pool: PgPool) {
        let state = test_state(pool).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_router(state.clone());
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let keypair = gitlawb_core::identity::Keypair::generate();
        let delegator_did = keypair.did().to_string();

        let task = crate::db::AgentTask {
            id: "ws-auth-task-01".into(),
            repo_id: None,
            delegator_did: delegator_did.clone(),
            kind: "test".into(),
            capability: "read".into(),
            status: "pending".into(),
            assignee_did: Some(delegator_did.clone()),
            ucan_token: None,
            payload: None,
            result: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            deadline: None,
        };
        state.db.create_task(&task).await.unwrap();

        // 1. Unauthenticated WS connection cannot see the private task
        let mut unauth_stream = connect_ws(addr).await;
        let query = r#"{"id":"1","type":"subscribe","payload":{"query":"query { tasks { items { id } } }"}}"#;
        ws_send_text(&mut unauth_stream, query).await;
        let unauth_frames = ws_recv_op_frames(&mut unauth_stream, "1").await;
        let unauth_resp = unauth_frames.join("\n");
        assert!(
            !unauth_resp.contains("ws-auth-task-01"),
            "unauthenticated WS must not disclose private task: {unauth_resp}"
        );

        // 2. Forged signature claiming the delegator DID must be rejected at handshake
        let attacker_keypair = gitlawb_core::identity::Keypair::generate();
        let attacker_signed =
            gitlawb_core::http_sig::sign_request(&attacker_keypair, "GET", "/graphql/ws", b"");
        let forged_sig_input = attacker_signed
            .signature_input
            .replace(&attacker_keypair.did().to_string(), &delegator_did);
        let mut forged_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let forged_req = format!(
            "GET /graphql/ws HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: graphql-transport-ws\r\n\
             content-digest: {}\r\n\
             signature-input: {}\r\n\
             signature: {}\r\n\r\n",
            addr, attacker_signed.content_digest, forged_sig_input, attacker_signed.signature
        );
        forged_stream
            .write_all(forged_req.as_bytes())
            .await
            .unwrap();
        forged_stream.flush().await.unwrap();
        let mut forged_bytes = Vec::new();
        let mut chunk = [0u8; 1024];
        while !forged_bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = forged_stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            forged_bytes.extend_from_slice(&chunk[..n]);
        }
        let forged_resp = String::from_utf8_lossy(&forged_bytes);
        assert!(
            forged_resp.starts_with("HTTP/1.1 401 Unauthorized"),
            "forged WS signature must be rejected with 401: {forged_resp}"
        );

        // 3. Signed WS connection authenticates caller and retrieves the private task
        let mut auth_stream = connect_ws_signed(addr, &keypair).await;
        ws_send_text(&mut auth_stream, query).await;
        let auth_frames = ws_recv_op_frames(&mut auth_stream, "1").await;
        let auth_resp = auth_frames.join("\n");
        assert!(
            auth_resp.contains("ws-auth-task-01"),
            "signed WS must authenticate delegator and return private task: {auth_resp}"
        );
    }

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::db::RepoRecord;

    /// Regression: anonymous callers must not see the pin/anchor index (#121, #134).
    #[sqlx::test]
    async fn unsigned_get_pins_and_anchors_is_401_through_build_router(pool: PgPool) {
        let state = test_state(pool).await;

        // Seed identifiable rows so the denial oracle proves the 401 body omits
        // them: a status-only check would stay green if a later change served
        // the listing before the auth layer rejected.
        state
            .db
            .record_pinned_cid("seeded-pin-oid", "bafyPIN-SECRET-DO-NOT-LEAK", None)
            .await
            .expect("seed pin");
        let owner_did = "did:key:zSEEDOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let repo = seed_repo_inline(owner_did, "seeded-repo");
        state.db.create_repo(&repo).await.expect("seed repo");
        state
            .db
            .record_arweave_anchor(&crate::db::RecordAnchorInput {
                repo: "zSEEDOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/seeded-repo",
                owner_did,
                ref_name: "refs/heads/secret",
                old_sha: "0".repeat(64).as_str(),
                new_sha: "1".repeat(64).as_str(),
                cid: Some("bafytest"),
                irys_tx_id: "irys-secret-tx-DO-NOT-LEAK",
                arweave_url: "https://arweave.net/secret-tx",
                node_did: "did:key:zNODE",
            })
            .await
            .expect("seed anchor");

        let router = build_router(state);

        let pins = Request::builder()
            .method("GET")
            .uri("/api/v1/ipfs/pins?limit=50")
            .body(Body::empty())
            .unwrap();
        let pins_resp = router.clone().oneshot(pins).await.unwrap();
        assert_eq!(
            pins_resp.status(),
            StatusCode::UNAUTHORIZED,
            "anonymous pin listing must be rejected"
        );
        let bytes = axum::body::to_bytes(pins_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            !body.contains("bafyPIN-SECRET-DO-NOT-LEAK"),
            "the 401 body must not leak the seeded pin cid; body was: {body}"
        );

        let anchors = Request::builder()
            .method("GET")
            .uri("/api/v1/arweave/anchors?limit=50")
            .body(Body::empty())
            .unwrap();
        let anchors_resp = router.oneshot(anchors).await.unwrap();
        assert_eq!(
            anchors_resp.status(),
            StatusCode::UNAUTHORIZED,
            "anonymous anchors listing must be rejected"
        );
        let bytes = axum::body::to_bytes(anchors_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            !body.contains("irys-secret-tx-DO-NOT-LEAK"),
            "the 401 body must not leak the anchor's irys tx id; body was: {body}"
        );
    }

    /// Regression: a real RFC-9421 signature produced exactly as `gl` does — built
    /// with `gitlawb_core::http_sig::sign_request` over a GET, headers attached,
    /// and sent through the actual `build_router` — is verified by the
    /// `optional_signature` layer that wraps the pin/anchor routes, and the
    /// handler returns 200. Pairs with the anonymous-denial test above; one
    /// proves headers are required, the other proves a valid header is honored.
    /// Without this test the unsigned-denial test would stay green even if the
    /// `optional_signature` layer were never wired onto these routes, because
    /// signed and unsigned requests would fail identically (#134 review).
    #[sqlx::test]
    async fn signed_get_pins_and_anchors_succeeds_through_build_router(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let state = test_state(pool).await;
        let router = build_router(state);

        let kp = Keypair::generate();

        let pins_path = "/api/v1/ipfs/pins";
        let signed = sign_request(&kp, "GET", pins_path, b"");
        let pins = Request::builder()
            .method("GET")
            .uri(pins_path)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::empty())
            .unwrap();
        let pins_resp = router.clone().oneshot(pins).await.unwrap();
        assert_eq!(
            pins_resp.status(),
            StatusCode::OK,
            "a valid signature on /api/v1/ipfs/pins must be honored through build_router"
        );

        let anchors_path = "/api/v1/arweave/anchors";
        let signed = sign_request(&kp, "GET", anchors_path, b"");
        let anchors = Request::builder()
            .method("GET")
            .uri(anchors_path)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::empty())
            .unwrap();
        let anchors_resp = router.oneshot(anchors).await.unwrap();
        assert_eq!(
            anchors_resp.status(),
            StatusCode::OK,
            "a valid signature on /api/v1/arweave/anchors must be honored through build_router"
        );
    }

    /// Companion to the two regressions above: a request that *carries* signature
    /// headers but whose signature does not verify (here, garbled) must be denied
    /// with 401, not silently treated as anonymous and re-checked by the handler.
    /// This pins the failure mode of the `optional_signature` layer: when the
    /// caller claims to be signed, the layer must commit to verifying — there is
    /// no fall-through path that lets a bad signature bypass auth.
    #[sqlx::test]
    async fn malformed_signature_on_pins_is_401_through_build_router(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let state = test_state(pool).await;
        let router = build_router(state);

        let kp = Keypair::generate();
        let path = "/api/v1/ipfs/pins";
        let mut signed = sign_request(&kp, "GET", path, b"");
        // Flip a character well inside the signature value (base64) so the header
        // still parses but does not verify against the key.
        let mut tampered = signed.signature.clone();
        let mid = tampered.len() / 2;
        let flipped = if tampered.as_bytes()[mid] == b'A' {
            'B'
        } else {
            'A'
        };
        tampered.replace_range(mid..mid + 1, &flipped.to_string());
        signed.signature = tampered;

        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a malformed signature must be rejected by the auth layer, not silently accepted"
        );
    }

    /// The same malformed-signature rejection must hold on the anchors route,
    /// which carries its own `optional_signature` layer beside pins: a later
    /// edit that dropped the layer here (but not on pins) would otherwise stay
    /// green.
    #[sqlx::test]
    async fn malformed_signature_on_anchors_is_401_through_build_router(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let state = test_state(pool).await;
        let router = build_router(state);

        let kp = Keypair::generate();
        let path = "/api/v1/arweave/anchors";
        let mut signed = sign_request(&kp, "GET", path, b"");
        let mut tampered = signed.signature.clone();
        let mid = tampered.len() / 2;
        let flipped = if tampered.as_bytes()[mid] == b'A' {
            'B'
        } else {
            'A'
        };
        tampered.replace_range(mid..mid + 1, &flipped.to_string());
        signed.signature = tampered;

        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a malformed signature must be rejected by the auth layer, not silently accepted"
        );
    }

    // ── Scoped anchor contract (P1 follow-up: ?repo= must authorize_repo_read) ──
    //
    // The follow-up review (after the auth-layer wiring landed) found that a
    // signed but unauthorized caller could still obtain scoped anchor metadata
    // because the `?repo=` branch handed the user-supplied string straight to
    // the SQL filter. These tests exercise the full production contract end to
    // end: real RFC-9421 signature → `optional_signature` layer →
    // `authorize_repo_read` → SQL. They fail closed if the authz call is moved
    // after the query or removed entirely.

    /// Inline repo seed for the scoped-anchor tests. Mirrors the shape in
    /// `test_support::tests::seed_repo` without taking a cross-module private
    /// helper as a dependency.
    fn seed_repo_inline(owner_did: &str, name: &str) -> RepoRecord {
        let now = chrono::Utc::now();
        RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/tmp/{name}"),
            forked_from: None,
            machine_id: None,
        }
    }

    /// Unsigned scoped anchor request → 401, identical to the global anchor
    /// 401 test. Proves the auth layer fires before any scope decision (no
    /// existence oracle via the `?repo=` path either).
    #[sqlx::test]
    async fn unsigned_scoped_anchors_is_401_through_build_router(pool: PgPool) {
        let state = test_state(pool).await;

        // Seed an anchor under a repo the request claims to scope to, so the
        // denial oracle proves the 401 body omits it rather than merely
        // returning the right status over an empty table.
        let owner_did = "did:key:zSCOPEDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let repo = seed_repo_inline(owner_did, "priv");
        state.db.create_repo(&repo).await.expect("seed repo");
        state
            .db
            .record_arweave_anchor(&crate::db::RecordAnchorInput {
                repo: "zSCOPEDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/priv",
                owner_did,
                ref_name: "refs/heads/secret",
                old_sha: "0".repeat(64).as_str(),
                new_sha: "1".repeat(64).as_str(),
                cid: Some("bafytest"),
                irys_tx_id: "irys-scoped-secret-DO-NOT-LEAK",
                arweave_url: "https://arweave.net/scoped-secret",
                node_did: "did:key:zNODE",
            })
            .await
            .expect("seed anchor");

        let router = build_router(state);

        let resp = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/arweave/anchors?repo=did:key:zSCOPED%2Fpriv")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned scoped anchor request must be 401, before any scope lookup"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            !body.contains("irys-scoped-secret-DO-NOT-LEAK"),
            "the 401 body must not leak the anchor's irys tx id; body was: {body}"
        );
    }

    /// Signed owner on a private repo → 200, anchor metadata returned. Mirrors
    /// the existing `list_webhooks_accepts_a_real_gl_signature_e2e` shape: real
    /// signature, real middleware, real `authorize_repo_read`.
    #[sqlx::test]
    async fn signed_scoped_anchors_owner_succeeds_through_build_router(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let kp = Keypair::generate();
        let owner_did = kp.did().to_string();
        let state = test_state(pool).await;

        let mut repo = seed_repo_inline(&owner_did, "scoped-priv");
        repo.is_public = false;
        state.db.create_repo(&repo).await.expect("seed repo");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        state
            .db
            .record_arweave_anchor(&crate::db::RecordAnchorInput {
                repo: &format!("{short}/scoped-priv"),
                owner_did: &owner_did,
                ref_name: "refs/heads/main",
                old_sha: "0".repeat(64).as_str(),
                new_sha: "1".repeat(64).as_str(),
                cid: Some("bafytest"),
                irys_tx_id: "irys-owner-tx",
                arweave_url: "https://arweave.net/owner-tx",
                node_did: "did:key:zNODE",
            })
            .await
            .expect("seed anchor");

        let path = format!("/api/v1/arweave/anchors?repo={short}/scoped-priv");
        let signed = sign_request(&kp, "GET", &path, b"");
        let req = Request::builder()
            .method("GET")
            .uri(&path)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::empty())
            .unwrap();

        let router = build_router(state);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the owner of a private repo must see their scoped anchors"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("irys-owner-tx"),
            "owner must see the anchor's irys tx id; body was: {body}"
        );
        // Owner must see the ref name + new SHA so this is not just a count oracle.
        assert!(
            body.contains("refs/heads/main"),
            "owner must see the ref name; body was: {body}"
        );

        // Sanity: a second test would need a different repo name to avoid
        // colliding on `did:key:zSCOPED/scoped-priv` in the anchors table.
        // Distinct repo names per test keep the rows queryable in isolation.
        let _ = repo;
    }

    /// #121 R3: the SQL filter must use the canonical stored slug, not the
    /// user-supplied `?repo=` string. Anchor rows are stored as
    /// `{normalize_owner_key(owner_did)}/{name}` (the short form). Authz
    /// passes for the full-DID form, but a literal `WHERE repo=$1` against
    /// the full DID would match zero rows and return a false empty page,
    /// breaking callers that legitimately use the full `did:key:…/name`
    /// form in `?repo=`. RED before the fix: handler built the filter from
    /// the raw `?repo=` string, so this query returned `anchors: []`.
    #[sqlx::test]
    async fn signed_scoped_anchors_full_did_form_matches_stored_slug_through_build_router(
        pool: PgPool,
    ) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let kp = Keypair::generate();
        let owner_did = kp.did().to_string();
        let state = test_state(pool).await;

        let mut repo = seed_repo_inline(&owner_did, "scoped-did-form");
        repo.is_public = false;
        state.db.create_repo(&repo).await.expect("seed repo");
        // Use the same slug-construction the writer uses
        // (`db::normalize_owner_key`) so the test reader and the production
        // writer can't drift if a future change moves the slug off the
        // short-form. P3 (reviewer-3): the previous `split(':').next_back()`
        // hand-rolled a third convention that agreed with the writer for
        // `did:key` owners and diverged for every other method.
        let short = crate::db::normalize_owner_key(&owner_did).to_string();
        state
            .db
            .record_arweave_anchor(&crate::db::RecordAnchorInput {
                repo: &format!("{short}/scoped-did-form"),
                owner_did: &owner_did,
                ref_name: "refs/heads/main",
                old_sha: "0".repeat(64).as_str(),
                new_sha: "1".repeat(64).as_str(),
                cid: Some("bafytest"),
                irys_tx_id: "irys-did-form-tx",
                arweave_url: "https://arweave.net/did-form-tx",
                node_did: "did:key:zNODE",
            })
            .await
            .expect("seed anchor");

        // P2 (reviewer-3): the previous suite only proved the authorized
        // row is present. A correct filter must ALSO prove that anchors
        // for OTHER repos do not leak into the response — the failure
        // mode of the original bug was a cross-repo leak, not a
        // fail-safe empty page. Seed a second repo (also under the
        // same owner, so the authz test stays scoped) with its own
        // irys_tx_id and assert it is absent from the body.
        let other_owner = {
            let kp2 = Keypair::generate();
            kp2.did().to_string()
        };
        let mut other_repo = seed_repo_inline(&other_owner, "other-repo");
        other_repo.is_public = true;
        state
            .db
            .create_repo(&other_repo)
            .await
            .expect("seed other repo");
        state
            .db
            .record_arweave_anchor(&crate::db::RecordAnchorInput {
                repo: &format!(
                    "{}/other-repo",
                    crate::db::normalize_owner_key(&other_owner)
                ),
                owner_did: &other_owner,
                ref_name: "refs/heads/main",
                old_sha: "0".repeat(64).as_str(),
                new_sha: "2".repeat(64).as_str(),
                cid: Some("bafyother"),
                irys_tx_id: "irys-other-repo-tx",
                arweave_url: "https://arweave.net/other-tx",
                node_did: "did:key:zNODE",
            })
            .await
            .expect("seed other anchor");

        // The caller passes the FULL DID form in ?repo=. validate_repo_slug
        // accepts it, authorize_repo_read resolves it, and the handler MUST
        // then translate to the canonical stored slug (short form) before
        // running the SQL — otherwise this returns 200 with anchors: [].
        let path = format!("/api/v1/arweave/anchors?repo={owner_did}/scoped-did-form");
        let signed = sign_request(&kp, "GET", &path, b"");
        let req = Request::builder()
            .method("GET")
            .uri(&path)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::empty())
            .unwrap();

        let router = build_router(state);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "authz passed via the full DID form, so the response must be 200"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("irys-did-form-tx"),
            "the SQL filter must use the stored short slug, not the full DID — \
             a false-empty page would break callers that pass ?repo=did:key:…/name. \
             body was: {body}"
        );
        assert!(
            !body.contains("irys-other-repo-tx"),
            "the scoped anchor filter must exclude other repos' anchors — \
             a cross-repo leak would expose metadata of repos the caller \
             did not authorize. body was: {body}"
        );

        let _ = repo;
    }

    /// Signed non-reader on a private repo → 404, anchor metadata MUST NOT
    /// leak. This is the test that catches the "auth-but-no-authz" bug if
    /// the gate is moved after the SQL query or removed entirely. The 404
    /// is the standard `repo_not_found` shape — indistinguishable from the
    /// missing-repo case below.
    #[sqlx::test]
    async fn signed_scoped_anchors_non_reader_is_404_no_leak_through_build_router(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let owner_kp = Keypair::generate();
        let stranger_kp = Keypair::generate();
        let owner_did = owner_kp.did().to_string();
        let stranger_did = stranger_kp.did().to_string();
        let state = test_state(pool).await;

        let mut repo = seed_repo_inline(&owner_did, "scoped-priv-nr");
        repo.is_public = false;
        state.db.create_repo(&repo).await.expect("seed repo");
        let short_owner = owner_did.split(':').next_back().unwrap().to_string();
        state
            .db
            .record_arweave_anchor(&crate::db::RecordAnchorInput {
                repo: &format!("{short_owner}/scoped-priv-nr"),
                owner_did: &owner_did,
                ref_name: "refs/heads/secret",
                old_sha: "2".repeat(64).as_str(),
                new_sha: "3".repeat(64).as_str(),
                cid: Some("bafytest"),
                irys_tx_id: "irys-secret-tx-DO-NOT-LEAK",
                arweave_url: "https://arweave.net/secret-tx",
                node_did: "did:key:zNODE",
            })
            .await
            .expect("seed anchor");

        let _ = stranger_did; // signature carries the DID; this is just documentation
        let path = format!("/api/v1/arweave/anchors?repo={short_owner}/scoped-priv-nr");
        let signed = sign_request(&stranger_kp, "GET", &path, b"");
        let req = Request::builder()
            .method("GET")
            .uri(&path)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::empty())
            .unwrap();

        let router = build_router(state);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a signed non-reader must be 404 on a private repo's anchors"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            !body.contains("irys-secret-tx-DO-NOT-LEAK"),
            "the 404 body must not leak the anchor's irys tx id; body was: {body}"
        );
        assert!(
            !body.contains("refs/heads/secret"),
            "the 404 body must not leak the ref name; body was: {body}"
        );
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(
            v["error"], "repo_not_found",
            "non-reader denial must carry the same error code as a missing repo"
        );
    }

    /// Signed caller on a missing repo → 404, same shape as the non-reader
    /// case. This is the indistinguishability half: a probe cannot tell
    /// "private" from "absent" from the response.
    #[sqlx::test]
    async fn signed_scoped_anchors_missing_repo_is_404_through_build_router(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let kp = Keypair::generate();
        let state = test_state(pool).await;

        let short = kp
            .did()
            .to_string()
            .split(':')
            .next_back()
            .unwrap()
            .to_string();
        let path = format!("/api/v1/arweave/anchors?repo={short}/does-not-exist");
        let signed = sign_request(&kp, "GET", &path, b"");
        let req = Request::builder()
            .method("GET")
            .uri(&path)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::empty())
            .unwrap();

        let router = build_router(state);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a missing repo must 404 indistinguishably from a non-readable private repo"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(
            v["error"], "repo_not_found",
            "the 404 body must carry the standard repo_not_found error code"
        );
    }

    /// `?limit=-1` must not crash as `LIMIT -1` (Postgres 500). It clamps to
    /// zero and returns 200 with an empty list — the same shape as a valid
    /// listing that happens to have no rows in the configured range.
    #[sqlx::test]
    async fn signed_anchors_negative_limit_clamps_to_zero_through_build_router(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let kp = Keypair::generate();
        let state = test_state(pool).await;

        let path = "/api/v1/arweave/anchors?limit=-1";
        let signed = sign_request(&kp, "GET", path, b"");
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::empty())
            .unwrap();

        let router = build_router(state);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "?limit=-1 must clamp, not 500"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(v["count"], 0, "clamped limit yields an empty list");
        assert_eq!(v["anchors"].as_array().map(|a| a.len()), Some(0));
    }
}

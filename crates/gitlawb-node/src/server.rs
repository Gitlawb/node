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
    protocol: GraphQLProtocol,
    upgrade: WebSocketUpgrade,
) -> axum::response::Response {
    let mut data = async_graphql::Data::default();
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

/// Applies the standard auth middleware pair to a router: HTTP Signature verification
/// followed by UCAN chain validation. The two layers run in this order for every
/// matched request: `require_signature` first (sets `AuthenticatedDid`), then
/// `require_ucan_chain` (reads it).
fn add_auth_layers(router: Router<AppState>, state: AppState) -> Router<AppState> {
    router
        .layer(middleware::from_fn_with_state(
            state,
            auth::require_ucan_chain,
        ))
        .layer(middleware::from_fn(auth::require_signature))
}

pub fn build_router(state: AppState) -> Router {
    // ── GraphQL routes ─────────────────────────────────────────────────────
    let graphql_routes = Router::new()
        .route("/graphql", get(graphql_playground).post(graphql_handler))
        // Attach the verified DID to /graphql when a signature is present. The
        // layer covers only routes added before it, so /graphql/ws (added after,
        // read-only subscriptions) stays open.
        .layer(middleware::from_fn(auth::optional_signature))
        .route("/graphql/ws", get(graphql_ws_handler));

    // ── Task routes (write — require HTTP Signature) ───────────────────────
    let task_write_routes = add_auth_layers(
        Router::new()
            .route("/api/v1/tasks", post(tasks::create_task))
            .route("/api/v1/tasks/{id}/claim", post(tasks::claim_task))
            .route("/api/v1/tasks/{id}/complete", post(tasks::complete_task))
            .route("/api/v1/tasks/{id}/fail", post(tasks::fail_task)),
        state.clone(),
    );

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
        .layer(middleware::from_fn(auth::optional_signature))
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
    )
    .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
    .layer(axum::Extension(create_ip_limiter));

    // ── Write routes — require HTTP Signature (no rate limit) ─────────────
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
    );

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
    )
    .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
    .layer(axum::Extension(push_limiter));

    // ── IPFS content-addressed retrieval and pin listing ──────────────────
    // `/ipfs/{cid}` carries `optional_signature` so `get_by_cid` sees the caller
    // identity and can apply per-repo visibility (#110); anonymous callers stay
    // anonymous and still read genuinely public content. `/api/v1/ipfs/pins`
    // stays unsigned — gating the pin index is tracked separately (#121).
    // `/ipfs/{cid}` also carries a per-IP flood brake: it is anon-reachable and each
    // request can drive a full-history git walk, so the per-IP rate limiter is the
    // outermost layer (rejects a flood before the walk-admission work), mirroring the
    // push/create routers. The extension MUST be attached or rate_limit_by_ip is a
    // silent no-op. `/api/v1/ipfs/pins` (no walk) is merged in unbraked, as before.
    let ipfs_limiter = rate_limit::IpRateLimiter {
        limiter: state.ipfs_rate_limiter.clone(),
        trust: state.push_limiter_trust,
    };
    let ipfs_routes = Router::new()
        .route("/ipfs/{cid}", get(ipfs::get_by_cid))
        .layer(middleware::from_fn(auth::optional_signature))
        .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
        .layer(axum::Extension(ipfs_limiter))
        .merge(Router::new().route("/api/v1/ipfs/pins", get(ipfs::list_pins)));

    // ── Arweave permanent anchors ──────────────────────────────────────────
    let arweave_routes = Router::new().route("/api/v1/arweave/anchors", get(arweave::list_anchors));

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
    );

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
        .layer(middleware::from_fn(auth::optional_signature));

    // ── Profile routes (write — require HTTP Signature) ─────────────────
    let profile_write_routes = add_auth_layers(
        Router::new().route("/api/v1/profile", axum::routing::put(profiles::set_profile)),
        state.clone(),
    );

    // ── Issue routes (write — require HTTP Signature, no rate limit) ─────
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
    );

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
        add_auth_layers(peer_write_routes, state.clone())
    } else {
        peer_write_routes.layer(middleware::from_fn(auth::optional_signature))
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
        .route("/api/v1/repos/federated", get(repos::list_federated_repos))
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
        .layer(middleware::from_fn(auth::optional_signature));

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
        .layer(middleware::from_fn(auth::optional_signature));

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
    Json(json!({
        "name": "gitlawb-node",
        "version": env!("CARGO_PKG_VERSION"),
        "did": state.node_did.to_string(),
        "network": "alpha",
        "protocols": ["git-smart-http", "mcp", "libp2p"],
        "auth": "http-signature-rfc9421",
        "identity": "ed25519",
        "p2p_peer_id": p2p_peer_id,
    }))
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

        // Query with 6 aliased task fields (exceeding MAX_GRAPHQL_TASK_READS_PER_REQUEST = 5)
        let query = r#"{"id":"1","type":"subscribe","payload":{"query":"query { f1: tasks { items { id } } f2: tasks { items { id } } f3: tasks { items { id } } f4: tasks { items { id } } f5: tasks { items { id } } f6: tasks { items { id } } }"}}"#;
        ws_send_text(&mut stream, query).await;
        let resp = ws_recv_text(&mut stream).await;
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
        let resp1 = ws_recv_text(&mut stream).await;
        assert!(!resp1.contains("rate limit exceeded"));

        // Second task query on the same connection hits per-IP limiter
        let query2 = r#"{"id":"2","type":"subscribe","payload":{"query":"query { tasks { items { id } } }"}}"#;
        ws_send_text(&mut stream, query2).await;
        let resp2 = ws_recv_text(&mut stream).await;
        assert!(
            resp2.contains("rate limit exceeded"),
            "exceeded per-IP limiter over WS must return rate limit message: {resp2}"
        );
    }
}

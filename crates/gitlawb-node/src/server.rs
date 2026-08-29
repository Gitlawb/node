use async_graphql_axum::{GraphQLRequest, GraphQLResponse, GraphQLSubscription};
use axum::extract::DefaultBodyLimit;
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
    req: GraphQLRequest,
) -> GraphQLResponse {
    // `optional_signature` attaches the verified DID when a signature is present.
    // Thread it into request-scoped GraphQL data; mutations enforce its presence
    // in-resolver (N2) while queries stay open.
    let mut inner = req.into_inner();
    if let Some(axum::Extension(did)) = auth {
        inner = inner.data(did);
    }
    state.graphql_schema.execute(inner).await.into()
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
    let schema = state.graphql_schema.as_ref().clone();
    let graphql_routes = Router::new()
        .route("/graphql", get(graphql_playground).post(graphql_handler))
        // Attach the verified DID to /graphql when a signature is present. The
        // layer covers only routes added before it, so /graphql/ws (added after,
        // read-only subscriptions) stays open.
        .layer(middleware::from_fn(auth::optional_signature))
        .route_service("/graphql/ws", GraphQLSubscription::new(schema));

    // ── Task routes (write — require HTTP Signature) ───────────────────────
    let task_write_routes = add_auth_layers(
        Router::new()
            .route("/api/v1/tasks", post(tasks::create_task))
            .route("/api/v1/tasks/{id}/claim", post(tasks::claim_task))
            .route("/api/v1/tasks/{id}/complete", post(tasks::complete_task))
            .route("/api/v1/tasks/{id}/fail", post(tasks::fail_task)),
        state.clone(),
    );

    // ── Task routes (read — open) ──────────────────────────────────────────
    let task_read_routes = Router::new()
        .route("/api/v1/tasks", get(tasks::list_tasks))
        .route("/api/v1/tasks/{id}", get(tasks::get_task));

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
        .layer(middleware::from_fn(auth::optional_signature))
        .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
        .layer(axum::Extension(ipfs_limiter));
    let ipfs_pins_routes = Router::new()
        .route("/api/v1/ipfs/pins", get(ipfs::list_pins))
        .layer(middleware::from_fn(auth::optional_signature));
    let ipfs_routes = ipfs_cid_routes.merge(ipfs_pins_routes);

    // ── Arweave permanent anchors ──────────────────────────────────────────
    // `list_anchors` rejects callers without a verified `AuthenticatedDid`, so
    // unsigned enumeration is denied. The same `optional_signature` layer used
    // on the other read surfaces is applied here — there is no anonymous
    // anchor-listing path on a signed-build node, and this commit closes that
    // gap alongside `/api/v1/ipfs/pins`.
    let arweave_routes = Router::new()
        .route("/api/v1/arweave/anchors", get(arweave::list_anchors))
        .layer(middleware::from_fn(auth::optional_signature));

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
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sqlx::PgPool;
    use tower::ServiceExt;

    use crate::db::RepoRecord;
    use crate::test_support::test_state;

    /// Regression: anonymous callers must not see the pin/anchor index (#121, #134).
    #[sqlx::test]
    async fn unsigned_get_pins_and_anchors_is_401_through_build_router(pool: PgPool) {
        let state = test_state(pool).await;
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

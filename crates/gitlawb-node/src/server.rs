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

    // ── Write routes — require HTTP Signature + per-IP write brake ────────
    // Same per-IP flood defense as the creation routes, on its own `write`
    // bucket (see `AppState::write_rate_limiter`). Per-DID is deliberately not
    // paired (a DID farm never trips it; busy legitimate agents would false-
    // positive). The bundled visibility GET is a read that also draws from the
    // write bucket — harmless, since the bucket is sized far above any legit
    // per-IP read rate.
    let write_ip_limiter = rate_limit::IpRateLimiter {
        limiter: state.write_rate_limiter.clone(),
        trust: state.push_limiter_trust,
    };
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
    )
    .layer(middleware::from_fn(rate_limit::rate_limit_by_ip))
    .layer(axum::Extension(write_ip_limiter.clone()));

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
    let ipfs_routes = Router::new()
        .route("/ipfs/{cid}", get(ipfs::get_by_cid))
        .layer(middleware::from_fn(auth::optional_signature))
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

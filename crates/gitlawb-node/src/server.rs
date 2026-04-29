use async_graphql_axum::{GraphQLRequest, GraphQLResponse, GraphQLSubscription};
use axum::{
    extract::State,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum::extract::DefaultBodyLimit;
use tower_http::limit::RequestBodyLimitLayer;
use serde_json::json;
use tower_http::trace::{DefaultOnResponse, DefaultOnFailure, TraceLayer};
use tracing::Level;

use crate::api::{agents, arweave, bounties, certs, changelog, events, ipfs, issues, labels, peers, protect, pulls, register, repos, resolve, stars, tasks, webhooks};
use crate::auth;
use crate::state::AppState;

async fn graphql_handler(
    State(state): State<AppState>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    state.graphql_schema.execute(req.into_inner()).await.into()
}

async fn graphql_playground() -> impl IntoResponse {
    axum::response::Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql")
            .subscription_endpoint("/graphql/ws"),
    ))
}

pub fn build_router(state: AppState) -> Router {
    // ── GraphQL routes ─────────────────────────────────────────────────────
    let schema = state.graphql_schema.as_ref().clone();
    let graphql_routes = Router::new()
        .route("/graphql", get(graphql_playground).post(graphql_handler))
        .route_service("/graphql/ws", GraphQLSubscription::new(schema));

    // ── Task routes (write — require HTTP Signature) ───────────────────────
    let task_write_routes = Router::new()
        .route("/api/v1/tasks", post(tasks::create_task))
        .route("/api/v1/tasks/{id}/claim", post(tasks::claim_task))
        .route("/api/v1/tasks/{id}/complete", post(tasks::complete_task))
        .route("/api/v1/tasks/{id}/fail", post(tasks::fail_task))
        .layer(middleware::from_fn(auth::require_signature));

    // ── Task routes (read — open) ──────────────────────────────────────────
    let task_read_routes = Router::new()
        .route("/api/v1/tasks", get(tasks::list_tasks))
        .route("/api/v1/tasks/{id}", get(tasks::get_task));

    // ── Write routes — require HTTP Signature ──────────────────────────────
    let write_routes = Router::new()
        .route("/api/v1/repos", post(repos::create_repo))
        .route("/api/register", post(register::register))
        .route("/api/v1/repos/{owner}/{repo}/pulls", post(pulls::create_pr))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}/merge", post(pulls::merge_pr))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}/close", post(pulls::close_pr))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews", post(pulls::create_review))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}/comments", post(pulls::create_comment))
        .route("/api/v1/repos/{owner}/{repo}/hooks", post(webhooks::create_webhook))
        .route("/api/v1/repos/{owner}/{repo}/hooks/{id}", axum::routing::delete(webhooks::delete_webhook))
        .route("/api/v1/repos/{owner}/{repo}/branches/{branch}/protect", post(protect::protect_branch))
        .route("/api/v1/repos/{owner}/{repo}/branches/{branch}/protect", axum::routing::delete(protect::unprotect_branch))
        .route("/api/v1/repos/{owner}/{repo}/star", axum::routing::put(stars::star_repo))
        .route("/api/v1/repos/{owner}/{repo}/star", axum::routing::delete(stars::unstar_repo))
        .route("/api/v1/repos/{owner}/{repo}/fork", post(repos::fork_repo))
        .route("/api/v1/repos/{owner}/{repo}/labels", post(labels::add_label))
        .route("/api/v1/repos/{owner}/{repo}/labels/{label}", axum::routing::delete(labels::remove_label))
        .layer(middleware::from_fn(auth::require_signature));

    // Body limit is raised to GITLAWB_MAX_PACK_BYTES (default 2 GB) for git
    // routes only — all other API routes keep axum's default 2 MB cap.
    // HTTP Signature is enforced on receive-pack (push) — the git-remote-gitlawb
    // helper signs requests with RFC 9421 signatures using the agent's keypair.
    let pack_limit = state.config.max_pack_bytes;
    let git_write_routes = Router::new()
        .route("/{owner}/{repo}/git-receive-pack", post(repos::git_receive_pack))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(pack_limit))
        .layer(middleware::from_fn(auth::require_signature));

    // ── IPFS content-addressed retrieval and pin listing ──────────────────
    let ipfs_routes = Router::new()
        .route("/ipfs/{cid}", get(ipfs::get_by_cid))
        .route("/api/v1/ipfs/pins", get(ipfs::list_pins));

    // ── Arweave permanent anchors ──────────────────────────────────────────
    let arweave_routes = Router::new()
        .route("/api/v1/arweave/anchors", get(arweave::list_anchors));

    // ── Bounty routes (write — require HTTP Signature) ─────────────────
    let bounty_write_routes = Router::new()
        .route("/api/v1/repos/{owner}/{repo}/bounties", post(bounties::create_bounty))
        .route("/api/v1/bounties/{id}/claim", post(bounties::claim_bounty))
        .route("/api/v1/bounties/{id}/submit", post(bounties::submit_bounty))
        .route("/api/v1/bounties/{id}/approve", post(bounties::approve_bounty))
        .route("/api/v1/bounties/{id}/cancel", post(bounties::cancel_bounty))
        .layer(middleware::from_fn(auth::require_signature));

    // ── Bounty routes (read — open) ──────────────────────────────────────
    let bounty_read_routes = Router::new()
        .route("/api/v1/repos/{owner}/{repo}/bounties", get(bounties::list_repo_bounties))
        .route("/api/v1/bounties", get(bounties::list_all_bounties))
        .route("/api/v1/bounties/{id}", get(bounties::get_bounty))
        .route("/api/v1/bounties/{id}/dispute", post(bounties::dispute_bounty))
        .route("/api/v1/bounties/stats", get(bounties::bounty_stats))
        .route("/api/v1/agents/{did}/bounties", get(bounties::agent_bounty_stats));

    // ── Issue routes ──────────────────────────────────────────────────────
    let issue_write_routes = Router::new()
        .route("/api/v1/repos/{owner}/{repo}/issues", post(issues::create_issue))
        .route("/api/v1/repos/{owner}/{repo}/issues/{id}/close", post(issues::close_issue))
        .route("/api/v1/repos/{owner}/{repo}/issues/{id}/comments", post(issues::create_issue_comment))
        .layer(middleware::from_fn(auth::require_signature));

    // ── Peer discovery routes ─────────────────────────────────────────────
    // announce is intentionally unauthenticated — nodes announce by DID which
    // is self-proving; rate-limiting and blocklisting are handled elsewhere.
    let peer_read_routes = Router::new()
        .route("/api/v1/peers", get(peers::list_peers))
        .route("/api/v1/peers/announce", post(peers::announce))
        .route("/api/v1/peers/{did}/ping", get(peers::ping_peer))
        .route("/api/v1/sync/trigger", post(peers::trigger_sync))
        .route("/api/v1/sync/notify", post(peers::notify_sync));

    // ── Read routes — open for public repos ───────────────────────────────
    let read_routes = Router::new()
        .route("/api/v1/repos", get(repos::list_repos))
        .route("/api/v1/repos/federated", get(repos::list_federated_repos))
        .route("/api/v1/repos/{owner}/{repo}", get(repos::get_repo))
        .route("/api/v1/repos/{owner}/{repo}/commits", get(repos::list_commits))
        .route("/api/v1/repos/{owner}/{repo}/tree", get(repos::get_tree_root))
        .route("/api/v1/repos/{owner}/{repo}/tree/{*path}", get(repos::get_tree))
        .route("/api/v1/repos/{owner}/{repo}/blob/{*path}", get(repos::get_blob))
        .route("/api/v1/repos/{owner}/{repo}/issues", get(issues::list_issues))
        .route("/api/v1/repos/{owner}/{repo}/issues/{id}", get(issues::get_issue))
        .route("/api/v1/repos/{owner}/{repo}/issues/{id}/comments", get(issues::list_issue_comments))
        .route("/api/v1/repos/{owner}/{repo}/labels", get(labels::list_labels))
        .route("/api/v1/repos/{owner}/{repo}/certs", get(certs::list_certs))
        .route("/api/v1/repos/{owner}/{repo}/certs/{id}", get(certs::get_cert))
        .route("/api/v1/repos/{owner}/{repo}/events", get(events::list_repo_events))
        .route("/api/v1/agents", get(agents::list_agents))
        .route("/api/v1/agents/{did}", get(agents::show_agent))
        .route("/api/v1/agents/{did}/trust", get(agents::get_trust))
        .route("/api/v1/events/ref-updates", get(events::list_ref_updates))
        .route("/api/v1/resolve/{did}", get(resolve::resolve_did))
        .route("/api/v1/repos/{owner}/{repo}/pulls", get(pulls::list_prs))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}", get(pulls::get_pr))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}/diff", get(pulls::get_pr_diff))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews", get(pulls::list_reviews))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}/comments", get(pulls::list_comments))
        .route("/api/v1/repos/{owner}/{repo}/hooks", get(webhooks::list_webhooks))
        .route("/api/v1/repos/{owner}/{repo}/refs", get(repos::list_refs))
        .route("/api/v1/repos/{owner}/{repo}/branches/protected", get(protect::list_protected_branches))
        .route("/api/v1/repos/{owner}/{repo}/changelog", get(changelog::get_changelog))
        .route("/api/v1/repos/{owner}/{repo}/star", get(stars::get_star_status))
        .route("/{owner}/{repo}/info/refs", get(repos::git_info_refs));

    // git-upload-pack (clone/fetch) — same raised body limit as receive-pack so
    // large pack responses from the server don't get truncated on the client side.
    let git_read_routes = Router::new()
        .route("/{owner}/{repo}/git-upload-pack", post(repos::git_upload_pack))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(pack_limit));

    // ── Meta ──────────────────────────────────────────────────────────────
    let meta_routes = Router::new()
        .route("/", get(node_info))
        .route("/health", get(health))
        .route("/api/v1/p2p/info", get(p2p_info))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/contracts", get(contracts_info));

    Router::new()
        .merge(graphql_routes)
        .merge(task_write_routes)
        .merge(task_read_routes)
        .merge(bounty_write_routes)
        .merge(bounty_read_routes)
        .merge(write_routes)
        .merge(git_write_routes)
        .merge(git_read_routes)
        .merge(issue_write_routes)
        .merge(read_routes)
        .merge(peer_read_routes)
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

async fn stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    let repos = state.db.list_all_repos().await.map(|r| r.len() as i64).unwrap_or(0);
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
    let chain_id: u64 = if rpc_url.contains("sepolia") { 84532 } else { 8453 };
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
        Some(h) => Json(json!({
            "enabled": true,
            "peer_id": h.local_peer_id.to_string(),
            "topics": [crate::p2p::REF_UPDATES_TOPIC],
        })),
        None => Json(json!({ "enabled": false })),
    }
}

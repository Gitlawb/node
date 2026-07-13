//! Test-only spawn surface for the real-node deny harness (see
//! `tests/deny_harness.rs`). Feature-gated behind `test-harness` so it never
//! compiles into the production binary. It exposes a single boot constructor so
//! the out-of-crate integration test can bring up a real node over a bound TCP
//! socket without the integration crate needing access to `graphql`,
//! `rate_limit`, `repo_store`, or the other internals `AppState` is built from.
//!
//! The node is built the same way `test_support::build_state` builds it (p2p
//! disabled, real migrated pool), but bound on `127.0.0.1:0` and served through
//! the real `axum::serve` stack with connect-info, so the middleware order,
//! body limits, and per-IP rate limiters all run exactly as in production.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use clap::Parser;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::sync::watch;
use uuid::Uuid;

use gitlawb_core::identity::Keypair;

use crate::config::Config;
use crate::db::{Db, PullRequest, RepoRecord, VisibilityMode};
use crate::rate_limit::{RateLimiter, TrustedProxy};
use crate::state::AppState;

/// A running node bound to an ephemeral port. Dropping it signals graceful
/// shutdown and removes the temporary repository directory.
pub struct TestNode {
    /// Base URL of the running node, e.g. `http://127.0.0.1:54321`.
    pub base_url: String,
    /// The node's own DID (for building requests that reference it).
    pub node_did: String,
    shutdown_tx: watch::Sender<bool>,
    repos_dir: PathBuf,
    /// Seeding handle over the same pool the node serves from. Kept private so
    /// the integration crate seeds through the methods below rather than
    /// naming `Db`/`RepoRecord` directly.
    db: Arc<Db>,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        // Flip the shared shutdown signal so the serve task exits, then remove
        // the temp repos dir. Both are best-effort: a test that already failed
        // should not panic again in teardown.
        let _ = self.shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&self.repos_dir);
    }
}

/// Allocate a process-unique temp directory for a spawned node's repositories
/// without pulling in the `tempfile` dev-dependency (which is unavailable to
/// the library crate under `--features test-harness`).
fn unique_repos_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("gitlawb-deny-harness-{}-{}", std::process::id(), n))
}

/// Build an [`AppState`] over the given migrated pool, mirroring
/// `test_support::build_state` but with a real on-disk repository directory so
/// git smart-HTTP routes can serve. P2P is always disabled.
fn build_state(db: Arc<crate::db::Db>, pool: PgPool, repos_dir: PathBuf) -> AppState {
    let keypair = Keypair::generate();
    let node_did = keypair.did();
    let (ref_tx, _) = tokio::sync::broadcast::channel(1);
    let (task_tx, _) = tokio::sync::broadcast::channel(1);
    let schema = Arc::new(crate::graphql::build_schema(
        db.clone(),
        ref_tx.clone(),
        task_tx.clone(),
    ));
    AppState {
        config: Arc::new(Config::parse_from(["gitlawb-node"])),
        db,
        node_did,
        node_keypair: Arc::new(keypair),
        p2p: None,
        http_client: Arc::new(reqwest::Client::new()),
        ref_update_tx: ref_tx,
        task_event_tx: task_tx,
        graphql_schema: schema,
        machine_id: None,
        repo_store: crate::git::repo_store::RepoStore::for_testing(repos_dir, pool),
        rate_limiter: RateLimiter::new(100, Duration::from_secs(60)),
        create_ip_rate_limiter: RateLimiter::new(1000, Duration::from_secs(3600)),
        push_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
        push_limiter_trust: TrustedProxy::None,
        sync_trigger_rate_limiter: RateLimiter::new(60, Duration::from_secs(3600)),
        peer_write_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
        shutdown_tx: watch::channel(false).0,
    }
}

/// Spawn a real node bound to `127.0.0.1:0` over the given (already-created,
/// empty) test pool. Runs the schema migrations, builds the router, and serves
/// it on a background task through the production `axum::serve` stack with
/// connect-info so per-IP layers key on the real peer. Returns once the socket
/// is bound and accepting connections.
pub async fn spawn_node(pool: PgPool) -> TestNode {
    let db = Arc::new(crate::db::Db::for_testing(pool.clone()));
    db.run_migrations()
        .await
        .expect("test schema migrations should apply");

    let repos_dir = unique_repos_dir();
    std::fs::create_dir_all(&repos_dir).expect("create temp repos dir");

    let state = build_state(db.clone(), pool, repos_dir.clone());
    let node_did = state.node_did.to_string();
    let shutdown_tx = state.shutdown_tx.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();

    let router = crate::server::build_router(state);

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("read bound addr");

    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
        })
        .await;
    });

    TestNode {
        base_url: format!("http://{addr}"),
        node_did,
        shutdown_tx,
        repos_dir,
        db,
    }
}

impl TestNode {
    /// Insert a repo owned by `owner_did` and return its repo id. Mirrors
    /// `test_support::seed_repo` (the `disk_path` field is unused by the
    /// integration path — `RepoStore` computes the on-disk path from
    /// `repos_dir`/owner/name, see [`Self::seed_bare_repo`]).
    pub async fn seed_repo(&self, owner_did: &str, name: &str, is_public: bool) -> String {
        let now = Utc::now();
        let record = RepoRecord {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/tmp/{name}"),
            forked_from: None,
            machine_id: None,
        };
        self.db.create_repo(&record).await.expect("seed repo");
        record.id
    }

    /// Seed an open PR `number` in `repo_id`, authored by `author_did`. The
    /// author-or-owner close gate (`close_pr`) loads the PR *before* it runs, so a
    /// deny-prober row for `.../pulls/{number}/close` needs the PR to exist or a
    /// stranger gets a 404 (absent entity) instead of the 403 the gate emits.
    pub async fn seed_pr(&self, repo_id: &str, number: i64, author_did: &str) {
        let now = Utc::now().to_rfc3339();
        let pr = PullRequest {
            id: Uuid::new_v4().to_string(),
            repo_id: repo_id.to_string(),
            number,
            title: "seed pr".to_string(),
            body: None,
            author_did: author_did.to_string(),
            source_branch: "feature".to_string(),
            target_branch: "main".to_string(),
            status: "open".to_string(),
            merged_by_did: None,
            merged_at: None,
            created_at: now.clone(),
            updated_at: now,
        };
        self.db.create_pr(&pr).await.expect("seed pr");
    }

    /// Seed issue `issue_id` (a git-ref JSON blob authored by `author_did`) in the
    /// repo's bare on-disk store. Like [`Self::seed_pr`], the `close_issue`
    /// owner-or-author gate loads the issue before it runs, so the deny-prober row
    /// for `.../issues/{id}/close` needs the issue present to reach the 403.
    pub fn seed_issue(&self, owner_did: &str, name: &str, issue_id: &str, author_did: &str) {
        let slug = owner_did.replace([':', '/'], "_");
        let bare = self.repos_dir.join(&slug).join(format!("{name}.git"));
        let json = format!(r#"{{"author":"{author_did}"}}"#);
        crate::git::issues::create_issue(&bare, issue_id, &json).expect("seed issue");
    }

    /// Add a path-scoped visibility rule restricting `path_glob` to
    /// `reader_dids` (empty = only the owner). Mode B keeps object SHAs intact
    /// and withholds blob content, which is what the read/replication gates
    /// enforce.
    pub async fn withhold_path(
        &self,
        repo_id: &str,
        path_glob: &str,
        reader_dids: &[String],
        created_by: &str,
    ) {
        self.db
            .set_visibility_rule(
                repo_id,
                path_glob,
                VisibilityMode::B,
                reader_dids,
                created_by,
            )
            .await
            .expect("set visibility rule");
    }

    /// Create a real bare git repository on disk at the exact path
    /// `RepoStore::acquire` reads (`<repos_dir>/<owner-slug>/<name>.git`), with
    /// one commit on `main` containing `files` (`(path, contents)`). Returns the
    /// blob OID of each path so callers can assert a withheld OID never appears
    /// in served bytes (U8). Shells out to `git`, mirroring
    /// `test_support`'s served-content seam.
    /// `object_format` is `"sha1"` for the git smart-HTTP surfaces and
    /// `"sha256"` for the content-addressed `/ipfs/{cid}` surface (whose CIDs
    /// are the sha2-256 object ids).
    pub fn seed_bare_repo(
        &self,
        owner_did: &str,
        name: &str,
        files: &[(&str, &str)],
        object_format: &str,
    ) -> std::collections::HashMap<String, String> {
        let run = |args: &[&str], cwd: &std::path::Path| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(cwd)
                .output()
                .expect("git runs");
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        // Build a source work tree, then bare-clone it into the served path.
        let src = self.repos_dir.join(format!("src-{name}"));
        std::fs::create_dir_all(&src).expect("create src dir");
        let fmt_arg = format!("--object-format={object_format}");
        run(&["init", "-q", "-b", "main", &fmt_arg], &src);
        run(&["config", "user.email", "t@t"], &src);
        run(&["config", "user.name", "t"], &src);
        for (path, contents) in files {
            let full = src.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).expect("create file parent dir");
            }
            std::fs::write(&full, contents).expect("write seed file");
            run(&["add", path], &src);
        }
        run(&["commit", "-q", "-m", "seed"], &src);

        let mut oids = std::collections::HashMap::new();
        for (path, _) in files {
            let oid = run(&["rev-parse", &format!("HEAD:{path}")], &src);
            oids.insert((*path).to_string(), oid);
        }
        // The HEAD commit oid, used as the `want` when driving upload-pack.
        oids.insert("HEAD".to_string(), run(&["rev-parse", "HEAD"], &src));

        let slug = owner_did.replace([':', '/'], "_");
        let bare = self.repos_dir.join(&slug).join(format!("{name}.git"));
        std::fs::create_dir_all(bare.parent().unwrap()).expect("create bare parent");
        run(
            &[
                "clone",
                "--bare",
                "-q",
                src.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            &self.repos_dir,
        );

        oids
    }
}

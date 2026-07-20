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
use crate::db::{Db, RepoRecord, VisibilityMode};
use crate::rate_limit::{RateLimiter, TrustedProxy};
use crate::state::AppState;

/// A running node bound to an ephemeral port. End every test with
/// [`TestNode::shutdown`]: it joins the serve task and closes the pool, so
/// `#[sqlx::test]`'s `DROP DATABASE` cleanup (which runs the moment the test
/// future returns) never races the server's still-open connections. Dropping
/// without it signals shutdown, aborts any remaining serve task, and removes
/// the temp repository directory, a fallback for tests that return or panic
/// before reaching teardown.
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
    /// The detached `axum::serve` task, joined by [`Self::shutdown`]. `None`
    /// once taken, so the `Drop` fallback never overlaps a completed teardown.
    /// Carries `serve`'s own `io::Result<()>` so `shutdown()` can observe it
    /// rather than discard it (see the coverage note there).
    server: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    /// A clone of the served pool, kept so [`Self::shutdown`] can close it
    /// (sqlx pool clones share one inner, so closing this closes the clones
    /// inside `AppState`/`Db` too).
    pool: PgPool,
    /// Test-only: when set, `Drop` skips the graceful watch signal so ONLY
    /// `handle.abort()` tears the serve task down. Defaults false, so every
    /// other test keeps both redundant teardown mechanisms. Set via
    /// [`Self::force_abort_only_teardown`] to fence that the abort alone
    /// releases the database when the graceful chain is broken.
    suppress_graceful_shutdown_on_drop: bool,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        // Fallback for tests that return or panic before reaching
        // [`TestNode::shutdown`]: flip the shared shutdown signal so the serve
        // task exits gracefully, abort whatever is left of it, and remove the
        // temp repos dir. Drop cannot await, so it cannot join the server or
        // close the pool; a test that already failed should not panic again in
        // teardown. All three actions are idempotent or no-ops after
        // `shutdown()` (which takes the handle), so running afterwards is
        // harmless.
        //
        // The abort matters when the graceful chain does not run to completion
        // before sqlx's `DROP DATABASE` cleanup: `JoinHandle::abort()` is a
        // synchronous cancellation request callable from non-async Drop, and
        // the aborted task's future (with the `PgPool` clones inside its
        // router/state) is dropped on a subsequent scheduler tick, which sqlx
        // cleanup's own awaits provide before the drop statement runs. The
        // race is closed by those scheduling points, not by the abort alone.
        //
        // `suppress_graceful_shutdown_on_drop` (test-only) forces the abort to
        // carry teardown by itself, so a test can fence that the abort line is
        // load-bearing; it is false everywhere else.
        if !self.suppress_graceful_shutdown_on_drop {
            let _ = self.shutdown_tx.send(true);
        }
        if let Some(handle) = self.server.take() {
            handle.abort();
        }
        let _ = std::fs::remove_dir_all(&self.repos_dir);
    }
}

/// Outcome of joining the serve task during teardown, split so the wedged-task
/// path is observable to a test (which injects a short timeout) without waiting
/// the production teardown window.
enum ServeTeardown {
    /// The task returned (carrying `serve`'s `io::Result<()>`) — either within
    /// the timeout, or in the race between the timeout firing and the abort
    /// landing. A task that actually finished is never a wedge.
    Graceful(std::io::Result<()>),
    /// The task did not finish within the timeout and was aborted (cancelled)
    /// and reaped.
    TimedOutAborted,
}

/// Join `handle` within `timeout`; on expiry `abort()` it and await the aborted
/// handle so the serve task (and the `PgPool` clones inside its router/state) is
/// reaped BEFORE the caller returns and `#[sqlx::test]` runs `DROP DATABASE`.
/// Takes `&mut` (a `JoinHandle` is `Unpin`) so ownership is retained across the
/// timeout and the handle can be aborted on expiry — the previous code moved the
/// handle into `timeout` and, on elapse, dropped it, which DETACHES the still
/// running task rather than aborting it, leaking the test database (#194 F2).
async fn join_or_abort(
    handle: &mut tokio::task::JoinHandle<std::io::Result<()>>,
    timeout: Duration,
) -> ServeTeardown {
    match tokio::time::timeout(timeout, &mut *handle).await {
        Ok(join_result) => ServeTeardown::Graceful(join_result.expect("serve task must not panic")),
        Err(_elapsed) => {
            handle.abort();
            match handle.await {
                // The task finished in the race between the timeout firing and
                // the abort landing — honor its result, not a false wedge.
                Ok(result) => ServeTeardown::Graceful(result),
                Err(e) if e.is_cancelled() => ServeTeardown::TimedOutAborted,
                // A genuine panic in the serve task surfaces here, mirroring the
                // in-time arm's `.expect("serve task must not panic")`.
                Err(e) => std::panic::resume_unwind(e.into_panic()),
            }
        }
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

    let state = build_state(db.clone(), pool.clone(), repos_dir.clone());
    let node_did = state.node_did.to_string();
    let shutdown_tx = state.shutdown_tx.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();

    let router = crate::server::build_router(state);

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("read bound addr");

    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
        })
        .await
    });

    TestNode {
        base_url: format!("http://{addr}"),
        node_did,
        shutdown_tx,
        repos_dir,
        db,
        server: Some(server),
        pool,
        suppress_graceful_shutdown_on_drop: false,
    }
}

impl TestNode {
    /// Test-only: make `Drop` tear the serve task down through `handle.abort()`
    /// alone by suppressing the graceful watch signal. Used to prove the abort
    /// is load-bearing (that the database is released even when the graceful
    /// chain is broken); no production or normal-teardown path calls this.
    pub fn force_abort_only_teardown(&mut self) {
        self.suppress_graceful_shutdown_on_drop = true;
    }

    /// Graceful async teardown: signal shutdown, join the serve task, close
    /// the pool, remove the temp repos dir. Call this at the end of every
    /// test. `#[sqlx::test]` issues `DROP DATABASE` as soon as the test
    /// future returns, so the server (which owns pool clones inside
    /// `AppState`/`Db`) must be gone and the pool closed before then, or the
    /// cleanup fails and leaks per-test databases. A serve task that does not
    /// exit within 10s panics loudly: a wedged graceful shutdown must fail
    /// the test, not hang CI.
    ///
    /// When `self` drops on return, `Drop` re-sends the signal and re-removes
    /// the dir; both are idempotent, and the serve handle was already taken,
    /// so the overlap is harmless.
    pub async fn shutdown(self) {
        self.shutdown_with_timeout(Duration::from_secs(10)).await;
    }

    /// Body of [`Self::shutdown`] with an injectable teardown timeout so a test
    /// can drive the wedged-shutdown path without waiting the production 10s.
    /// Production always calls this with 10s.
    async fn shutdown_with_timeout(mut self, timeout: Duration) {
        let _ = self.shutdown_tx.send(true);
        let outcome = match self.server.take() {
            Some(mut handle) => Some(join_or_abort(&mut handle, timeout).await),
            None => None,
        };
        // Release the pool and temp dir on EVERY path before returning OR
        // panicking. A wedged graceful shutdown is exactly when in-flight
        // per-connection tasks still hold `PgPool` clones; aborting the serve
        // future alone does not reliably drop them, so the explicit
        // `pool.close()` (which closes the shared inner) is what frees them
        // before `#[sqlx::test]` runs `DROP DATABASE`. Panicking before this
        // (the previous behavior) skipped the close on the one path that needs
        // it most (#194 F2).
        self.pool.close().await;
        let _ = std::fs::remove_dir_all(&self.repos_dir);
        match outcome {
            // Honest coverage contract: on axum 0.8.8,
            // `WithGracefulShutdown::into_future` always resolves `Ok(())` (the
            // shutdown signal is treated as success and `accept()` errors are
            // retried forever rather than returned), so this `Err` arm is
            // unreachable today - every existing harness test exercises only the
            // `Ok` path here. Forward-compat insurance for a future axum where
            // `serve` can fail: that should surface as a clear panic, not be
            // silently discarded.
            Some(ServeTeardown::Graceful(result)) => {
                result.expect("axum::serve exited with an error");
            }
            Some(ServeTeardown::TimedOutAborted) => {
                panic!(
                    "serve task did not exit within {timeout:?} of the shutdown \
                     signal (wedged graceful shutdown)"
                );
            }
            None => {}
        }
    }

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
            // Test-harness-only fixture seeding, feature-gated out of the production
            // binary; runs local git against a tempdir inside a test's own lifetime.
            // allow-unbounded-git: test-only seeding, never on a request path holding a permit
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

#[cfg(test)]
mod tests {
    use super::{join_or_abort, ServeTeardown};
    use std::time::Duration;

    /// A wedged serve task (never returns within the window) must be ABORTED and
    /// reaped on timeout, not detached. The previous teardown moved the
    /// `JoinHandle` into `timeout` and dropped it on elapse, which detaches the
    /// still-running task and leaks the test DB across `DROP DATABASE` (#194 F2).
    /// Load-bearing: neutralize the abort in `join_or_abort` (return without
    /// abort+await) and this flips RED — `handle.is_finished()` stays false
    /// because the task was left running.
    #[tokio::test]
    async fn join_or_abort_aborts_a_wedged_task_on_timeout() {
        let mut handle: tokio::task::JoinHandle<std::io::Result<()>> = tokio::spawn(async {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
        assert!(
            matches!(
                join_or_abort(&mut handle, Duration::from_millis(50)).await,
                ServeTeardown::TimedOutAborted
            ),
            "a task that never returns must be reported timed-out, not graceful"
        );
        assert!(
            handle.is_finished(),
            "the wedged serve task must be aborted and reaped, not detached"
        );
    }

    /// A task that returns within the window is reported graceful, carrying its
    /// `io::Result` — the normal teardown path.
    #[tokio::test]
    async fn join_or_abort_reports_graceful_when_task_exits_in_time() {
        let mut handle: tokio::task::JoinHandle<std::io::Result<()>> =
            tokio::spawn(async { Ok(()) });
        assert!(
            matches!(
                join_or_abort(&mut handle, Duration::from_secs(5)).await,
                ServeTeardown::Graceful(Ok(()))
            ),
            "a prompt clean exit must be reported graceful"
        );
    }
}

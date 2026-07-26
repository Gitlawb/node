pub mod issues;
pub mod push_delta;
pub mod repo_store;
pub mod smart_http;
pub mod store;
pub mod tigris;
pub mod visibility_pack;

// ── Per-blocking-task subprocess registry (P1 deadline fix) ──────────────────
//
// The reconciliation sweep runs git subprocesses inside `spawn_blocking`
// closures bounded by `tokio::time::timeout`.  A plain timeout stops *awaiting*
// the future but does NOT abort the blocking thread or kill any git children it
// spawned — they keep running until they finish naturally.  On a pathological
// repo that would mean the sweep "skips" the repo but leaves live git processes
// consuming CPU/IO and occupying the blocking pool.
//
// The fix mirrors what smart_http.rs already does for served-git (#174):
//   1. Spawn each git subprocess in its own process group (`process_group(0)`).
//   2. Register the pgid in a thread-local registry shared with the async
//      executor.
//   3. On timeout, the async code SIGTERMs every registered pgid, killing the
//      whole git tree (including pack-objects / cat-file grandchildren).
//
// Usage pattern inside a `spawn_blocking` closure:
//   let _guard = crate::git::set_scan_context(ctx.clone());
//   // ... then call list_all_objects / replicable_blob_set / etc. ...
//   // Each of those uses GitCommand::output() which honours the ctx.
//
// The _guard resets the thread-local on drop so the thread is clean if reused.

use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Shared state between the async timeout handler and the blocking git scan.
pub struct ScanContext {
    /// Process-group ids of active git subprocesses, registered by
    /// `spawn_registered` and deregistered by `PgidGuard`.
    pub registry: Mutex<HashSet<i32>>,
    /// Set to `true` by the async side when the per-repo deadline fires.
    /// `spawn_registered` checks this before and after spawning so a child
    /// started just as the timeout fires is killed on the spot.
    pub canceled: AtomicBool,
}

impl ScanContext {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(HashSet::new()),
            canceled: AtomicBool::new(false),
        })
    }
}

thread_local! {
    /// Shared scan context for the currently executing blocking git scan.
    /// `None` when no scan is active (i.e. outside a reconciliation closure).
    static SCAN_CTX: std::cell::RefCell<Option<Arc<ScanContext>>> =
        const { std::cell::RefCell::new(None) };
}

/// RAII guard that clears the thread-local scan context on drop.
pub struct ScanGuard;

impl Drop for ScanGuard {
    fn drop(&mut self) {
        SCAN_CTX.with(|ctx| {
            *ctx.borrow_mut() = None;
        });
    }
}

/// Arm the per-thread scan context so subsequent `GitCommand` calls on this
/// thread register their pgids into `ctx.registry` and respect `ctx.canceled`.
/// Returns a guard that clears the thread-local on drop.
pub fn set_scan_context(ctx: Arc<ScanContext>) -> ScanGuard {
    SCAN_CTX.with(|c| {
        *c.borrow_mut() = Some(ctx);
    });
    ScanGuard
}

// ── GitCommand: std::process::Command wrapper that auto-registers pgids ───────

/// A thin wrapper around `std::process::Command` that:
/// * Sets `process_group(0)` on Unix when a registry is active, placing the
///   git subprocess in its own process group.
/// * Registers the pgid into the active thread-local registry before `output()`
///   returns, and deregisters it on completion.
///
/// This is intentionally only used from functions called inside
/// `spawn_blocking` closures that have called `set_scan_context`.
pub struct GitCommand {
    inner: Command,
}

impl GitCommand {
    pub fn new(repo_path: &Path) -> Self {
        let mut inner = Command::new("git");
        inner.current_dir(repo_path);
        Self { inner }
    }

    #[allow(dead_code)]
    pub fn arg<S: AsRef<std::ffi::OsStr>>(mut self, arg: S) -> Self {
        self.inner.arg(arg);
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.inner.args(args);
        self
    }

    pub fn stdin(mut self, cfg: impl Into<Stdio>) -> Self {
        self.inner.stdin(cfg);
        self
    }

    pub fn stdout(mut self, cfg: impl Into<Stdio>) -> Self {
        self.inner.stdout(cfg);
        self
    }

    pub fn stderr(mut self, cfg: impl Into<Stdio>) -> Self {
        self.inner.stderr(cfg);
        self
    }

    /// Execute the command, collecting all output.  stdout and stderr are
    /// piped so `wait_with_output` captures them.  On Unix, if a registry is
    /// active on this thread, the child is started in its own process group and
    /// the pgid is registered for the duration of the call.
    pub fn output(mut self) -> io::Result<Output> {
        self.inner.stdout(Stdio::piped());
        self.inner.stderr(Stdio::piped());
        let (child, _guard) = self.spawn_registered()?;
        child.wait_with_output()
    }

    /// Spawn the child and return it together with a deregistration guard.
    /// The caller is responsible for waiting on the child.
    pub fn spawn(self) -> io::Result<(Child, impl Drop)> {
        self.spawn_registered()
    }

    fn spawn_registered(mut self) -> io::Result<(Child, PgidGuard)> {
        let ctx = SCAN_CTX.with(|c| c.borrow().clone());

        // If the deadline has already fired, refuse to spawn.
        if let Some(ref ctx) = ctx {
            if ctx.canceled.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "scan canceled before spawn",
                ));
            }
        }

        #[cfg(unix)]
        if ctx.is_some() {
            use std::os::unix::process::CommandExt as _;
            self.inner.process_group(0);
        }

        let child = self.inner.spawn()?;

        let pgid = {
            #[cfg(unix)]
            {
                Some(child.id() as i32)
            }
            #[cfg(not(unix))]
            {
                let _: Option<i32> = None;
                None::<i32>
            }
        };

        // Atomically (under the registry lock) check cancellation and
        // register the pgid.  This prevents the timeout sweep from
        // interleaving between the check and the insert — if canceled
        // is set while we hold the lock, the sweep cannot drain the
        // registry until we release it.
        if let Some(ref ctx) = ctx {
            let mut registry = ctx.registry.lock().unwrap();
            if ctx.canceled.load(Ordering::SeqCst) {
                // Canceled after spawn: kill the whole process group (not
                // just the immediate child) and wait to avoid zombies.
                if let Some(pgid) = pgid {
                    #[cfg(unix)]
                    unsafe {
                        let _ = libc::kill(-pgid, libc::SIGTERM);
                    }
                }
                let _ = child.wait_with_output();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "scan canceled after spawn",
                ));
            }
            if let Some(pgid) = pgid {
                registry.insert(pgid);
            }
        }

        let guard = PgidGuard { pgid, ctx };
        Ok((child, guard))
    }
}

/// Deregisters a pgid from the active scan context when dropped.
struct PgidGuard {
    pgid: Option<i32>,
    ctx: Option<Arc<ScanContext>>,
}

impl Drop for PgidGuard {
    fn drop(&mut self) {
        if let (Some(pgid), Some(ref ctx)) = (self.pgid, &self.ctx) {
            ctx.registry.lock().unwrap().remove(&pgid);
        }
    }
}

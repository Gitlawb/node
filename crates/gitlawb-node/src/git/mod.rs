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
//   let _guard = crate::git::set_active_registry(registry.clone());
//   // ... then call list_all_objects / replicable_blob_set / etc. ...
//   // Each of those uses GitCommand::output() which honours the registry.
//
// The _guard resets the thread-local on drop so the thread is clean if reused.

use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};

thread_local! {
    /// Registry of active process-group ids for the currently executing
    /// blocking git scan.  `None` when no registry is active (i.e. outside a
    /// reconciliation scan closure).
    static ACTIVE_REGISTRY: std::cell::RefCell<Option<Arc<Mutex<HashSet<i32>>>>> =
        std::cell::RefCell::new(None);
}

/// RAII guard that clears the thread-local registry on drop.
pub struct RegistryGuard;

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        ACTIVE_REGISTRY.with(|reg| {
            *reg.borrow_mut() = None;
        });
    }
}

/// Arm the per-thread process registry so that subsequent `GitCommand` calls
/// on this thread register their pgids into `registry`.  Returns a guard that
/// clears the thread-local on drop.
pub fn set_active_registry(registry: Arc<Mutex<HashSet<i32>>>) -> RegistryGuard {
    ACTIVE_REGISTRY.with(|reg| {
        *reg.borrow_mut() = Some(registry);
    });
    RegistryGuard
}

// ── GitCommand: std::process::Command wrapper that auto-registers pgids ───────

/// A thin wrapper around `std::process::Command` that:
/// * Sets `process_group(0)` on Unix when a registry is active, placing the
///   git subprocess in its own process group.
/// * Registers the pgid into the active thread-local registry before `output()`
///   returns, and deregisters it on completion.
///
/// This is intentionally only used from functions called inside
/// `spawn_blocking` closures that have called `set_active_registry`.
pub struct GitCommand {
    inner: Command,
}

impl GitCommand {
    pub fn new(repo_path: &Path) -> Self {
        let mut inner = Command::new("git");
        inner.current_dir(repo_path);
        Self { inner }
    }

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

    /// Execute the command, collecting all output.  On Unix, if a registry is
    /// active on this thread, the child is started in its own process group and
    /// the pgid is registered for the duration of the call.
    pub fn output(self) -> io::Result<Output> {
        let (child, _guard) = self.spawn_registered()?;
        child.wait_with_output()
    }

    /// Spawn the child and return it together with a deregistration guard.
    /// The caller is responsible for waiting on the child.
    pub fn spawn(self) -> io::Result<(Child, impl Drop)> {
        self.spawn_registered()
    }

    fn spawn_registered(mut self) -> io::Result<(Child, PgidGuard)> {
        let registry = ACTIVE_REGISTRY.with(|reg| reg.borrow().clone());

        #[cfg(unix)]
        if registry.is_some() {
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

        if let (Some(pgid), Some(ref reg)) = (pgid, &registry) {
            reg.lock().unwrap().insert(pgid);
        }

        let guard = PgidGuard { pgid, registry };
        Ok((child, guard))
    }
}

/// Deregisters a pgid from the active registry when dropped.
struct PgidGuard {
    pgid: Option<i32>,
    registry: Option<Arc<Mutex<HashSet<i32>>>>,
}

impl Drop for PgidGuard {
    fn drop(&mut self) {
        if let (Some(pgid), Some(ref reg)) = (self.pgid, &self.registry) {
            reg.lock().unwrap().remove(&pgid);
        }
    }
}

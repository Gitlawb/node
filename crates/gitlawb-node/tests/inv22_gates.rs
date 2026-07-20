//! #174 U6 — INV-22 completeness guard (rung-raising).
//!
//! INV-22: a permit held per op recovers only if every path that holds it is also
//! duration-bounded and reaps the process group before releasing admission, and every
//! detached git/blocking task carries its own admission. PR #174 fixed five paths
//! (U1-U5) that violated this. Each fix has a per-unit RED/GREEN regression; together
//! those form the five-revert matrix. This guard adds the missing piece: a source-scan
//! tripwire that fails when a NEW site reintroduces the class, or when one of the five
//! gates is removed.
//!
//! It lives in `tests/` (a separate crate) on purpose: a guard that scanned the same
//! file it lives in would match its own identifier literals and pass vacuously. Here
//! the scanned `src/` files never contain this file's literals, so each check is
//! load-bearing — reverting the named gate turns the assertion red.
//!
//! These are deliberately coarse structural checks, not a parser. They cannot prove a
//! gate is *correct* (the per-unit tests do that); they prove a gate is *present and
//! not bypassed*, which is what stops the class from silently regressing.

use std::path::Path;

fn src(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn inv22_concurrency_gates_present_and_not_bypassed() {
    let repos = src("api/repos.rs");
    let smart_http = src("git/smart_http.rs");
    let vis = src("git/visibility_pack.rs");

    // U1 / P1-a: run_bounded_git stands the watchdog down only after confirming the
    // child actually terminated (WNOWAIT), not on the raw stdout-drain EOF — otherwise
    // a child that closes stdout then hangs pins the permit past the deadline. The
    // probe is defined and called, so >= 2 occurrences; reverting the fix removes both.
    assert!(
        vis.matches("child_terminated_without_reaping").count() >= 2,
        "U1/P1-a gate missing: run_bounded_git must confirm child exit via \
         child_terminated_without_reaping before signalling the watchdog"
    );

    // U2 / P1-c: on client disconnect KillGroupOnDrop must launch a detached reaper
    // that runs the full TERM/grace/KILL/reap, not a lone SIGTERM. The reaper is spawned
    // via a runtime handle in Drop; `Handle::try_current` is unique to that launch (the
    // timeout path already has an async context and never calls it).
    assert!(
        smart_http.contains("Handle::try_current"),
        "U2/P1-c gate missing: KillGroupOnDrop::drop must launch the full \
         TERM/grace/KILL reaper on disconnect (Handle::try_current), not a lone SIGTERM"
    );

    // U4 / P1-d: git_receive_pack must acquire the per-source write sub-cap before the
    // global write permit. The acquire reads `state.git_write_per_caller`; comments name
    // the field without the `state.` prefix, so this targets the real acquire site.
    assert!(
        repos.contains("state.git_write_per_caller"),
        "U4/P1-d gate missing: git_receive_pack must acquire the per-source write cap \
         (state.git_write_per_caller) before the global write permit"
    );

    // U5 / P1-e: the detached post-push encryption walk must run through the
    // admission-gated helper, which is wired to the shared encrypt pool.
    assert!(
        repos.contains("fn withheld_recipients_gated")
            && repos.contains("state.git_encrypt_semaphore"),
        "U5/P1-e gate missing: the encryption walk must run through \
         withheld_recipients_gated, which acquires git_encrypt_semaphore"
    );

    // U1 / R2 (#173 round-10): the path-scoped filtered-pack serve must thread the
    // caller's AdmissionGuard through BOTH git stages so read + per-caller admission is
    // held until the pack-objects group is reaped on disconnect, closing the cap bypass
    // the plain upload_pack path already fixed. Two load-bearing markers: rev-list hands
    // the disarmed guard back (its tuple return type), and build_filtered_pack forwards
    // that guard into the pack-objects stage (the `admission` arg after the
    // "pack-objects" label). Reverting either — dropping the guard between stages, or
    // passing `None` to pack-objects — trips this.
    assert!(
        smart_http.contains("Result<(Vec<String>, Option<AdmissionGuard>)>")
            && smart_http.contains("\"pack-objects\",\n        admission,"),
        "U1/R2 gate missing: build_filtered_pack must thread the AdmissionGuard through \
         rev-list -> pack-objects so the permits are held until the pack-objects group \
         is reaped on disconnect (the path-scoped half of #174 P1-a)"
    );

    // P1-e non-bypass tripwire: the bounded recipients walk is spawn_blocking'd nowhere
    // but inside withheld_recipients_gated. A second call site (count > 1) is a new
    // detached git walk that skips the admission gate — exactly the class U5 closed.
    assert_eq!(
        repos.matches("withheld_blob_recipients_bounded").count(),
        1,
        "P1-e bypass: the bounded recipients walk must be invoked only inside \
         withheld_recipients_gated; a new call site bypasses the encrypt-walk admission cap"
    );

    // U4 / P2-2: the detached post-push encryption task must be gated by the per-repo
    // coalescing set (`encrypt_inflight.try_begin`) so the OUTSTANDING parked-task set is
    // bounded to <=1 per repo. Removing the gate lets N rapid pushes spawn N parked
    // waiters (the unbounded set U4 closed); the semaphore only caps active walks.
    assert!(
        repos.contains("state.encrypt_inflight.try_begin"),
        "U4/P2-2 gate missing: the detached post-push encryption spawn must consult \
         encrypt_inflight.try_begin to coalesce per repo (bound the outstanding-task set)"
    );
}

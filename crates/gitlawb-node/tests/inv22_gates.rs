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

    // F5: coalescing must REQUEUE, not shed. The in-flight task pins only its own
    // pre-spawn snapshot, so a coalesced push's tip pairs are recorded on its key and
    // the task must loop-drain them (`finish_or_take_pending`) before releasing it.
    // Removing the drain reverts to the silent loss: a coalesced push's pins and
    // recovery copies are absent until an unrelated later push. Scan only the
    // production half of the file — the u5 tests in its `mod tests` also name the
    // drain call, and matching them would make this check vacuous.
    let repos_production = repos
        .split("#[cfg(test)]")
        .next()
        .expect("split always yields a first chunk");
    assert!(
        repos_production.contains("finish_or_take_pending"),
        "F5 gate missing: the post-push encryption task must loop-drain coalesced \
         pushes via finish_or_take_pending before releasing its repo key"
    );

    // F4: every post-receive scan helper admits itself to the shared scan pool via
    // `crate::state::acquire_scan_permit` BEFORE its spawn_blocking git walk, so a
    // push burst cannot accumulate unbounded concurrent scans once the write permit
    // is released. Two halves, both load-bearing: the helper body must actually
    // acquire the pool (state.rs sits the helper at the end of the file, so the
    // definition tail contains no other `acquire_owned` to match vacuously), and
    // within each scan helper the first qualified call precedes the first
    // `spawn_blocking`. Severing a call site pushes the next occurrence past the
    // helper's own `spawn_blocking` (or off the end of the file), turning the
    // assertion red; comments name the helper without the `crate::state::` prefix,
    // so this targets the real call sites.
    let state_rs = src("state.rs");
    let helper_def = state_rs
        .find("fn acquire_scan_permit")
        .expect("F4 gate missing: state.rs no longer defines acquire_scan_permit");
    assert!(
        state_rs[helper_def..].contains("acquire_owned"),
        "F4 gate gutted: acquire_scan_permit must acquire the scan pool via acquire_owned"
    );
    let push_delta = src("git/push_delta.rs");
    for (file_src, file, helper) in [
        (&repos, "api/repos.rs", "fn replication_withheld_set"),
        (&repos, "api/repos.rs", "fn fail_closed_full_scan_objects"),
        (
            &push_delta,
            "git/push_delta.rs",
            "fn resolve_candidates_for_push",
        ),
    ] {
        let start = file_src
            .find(helper)
            .unwrap_or_else(|| panic!("{file}: `{helper}` not found"));
        let tail = &file_src[start..];
        let acquire = tail
            .find("crate::state::acquire_scan_permit(")
            .unwrap_or_else(|| {
                panic!("F4 gate missing: {file} `{helper}` no longer acquires a scan permit")
            });
        let spawn = tail.find("spawn_blocking").unwrap_or_else(|| {
            panic!("{file}: `{helper}` lost its spawn_blocking walk — update this guard")
        });
        assert!(
            acquire < spawn,
            "F4 gate bypassed: {file} `{helper}` must acquire its git_encrypt_semaphore \
             permit BEFORE dispatching the blocking git scan"
        );
    }
}

/// F4 (repo_store advisory-unlock cancellation safety): `RepoWriteGuard::release`
/// must await `pg_advisory_unlock` while `self` still owns the pooled connection,
/// and must not mark itself `released` until that await resolves. Either shape,
/// reintroduced, re-opens the mid-unlock cancellation leak: taking the connection
/// early leaves `Drop` with `conn == None`, and setting `released = true` early
/// leaves the `Drop` backstop inert — both strand the session lock on cancellation.
///
/// Scoped to the `release` fn body: the `Drop` impl legitimately takes the
/// connection and unlocks, so a whole-file scan would match it and read as a false
/// pass. Reverting either ordering turns this red (proven load-bearing).
#[test]
fn f4_release_keeps_conn_owned_until_unlock_resolves() {
    let repo_store = src("git/repo_store.rs");

    let rel_start = repo_store
        .find("pub async fn release(mut self")
        .expect("F4 gate: repo_store.rs no longer defines RepoWriteGuard::release");
    let rel_end = repo_store[rel_start..]
        .find("impl Drop for RepoWriteGuard")
        .map(|off| rel_start + off)
        .expect("F4 gate: release fn / Drop impl markers moved — update this guard");
    let release_body = &repo_store[rel_start..rel_end];

    let unlock = release_body
        .find("pg_advisory_unlock")
        .expect("F4 gate: release must still issue pg_advisory_unlock");
    let before_unlock = &release_body[..unlock];

    // (a) the connection must still be owned by `self` at the unlock await.
    assert!(
        !before_unlock.contains("self.conn.take()"),
        "F4 regression: RepoWriteGuard::release takes self.conn BEFORE awaiting \
         pg_advisory_unlock. A cancellation during the unlock await then strands the \
         session advisory lock (Drop sees conn == None and skips its backstop). \
         Unlock through the still-owned connection instead."
    );
    // (b) `released` must not be set before the unlock await — the other
    // reintroduction shape a single-reorder check on (a) alone is blind to.
    assert!(
        !before_unlock.contains("released = true"),
        "F4 regression: RepoWriteGuard::release sets `released = true` BEFORE awaiting \
         pg_advisory_unlock. A cancellation during the await then leaves the Drop \
         backstop inert (it early-returns on released). Set released only AFTER the \
         unlock await resolves."
    );
}

/// F6/KTD-5 (initial IPFS metadata queries deadline-wrapped): `get_by_cid` acquires
/// the scarce walk permits (RAII, held for the whole request) BEFORE its two initial
/// metadata queries, and the per-repo loop's first budget gate runs only later. So
/// both `list_all_repos` and `list_visibility_rules_for_repos` must be clamped to the
/// remaining request budget — otherwise a query blocked in Postgres pins the walk slot
/// for the whole stall, past the budget. This scans the PRODUCTION half of `api/ipfs.rs`
/// (the `mod tests` half names the same calls in its own harness and would make the
/// check vacuous) and asserts each query call is immediately preceded by a
/// `tokio::time::timeout(` wrapper. Removing either wrapper turns this red (proven
/// load-bearing).
#[test]
fn f6_ipfs_metadata_queries_are_deadline_wrapped() {
    let ipfs = src("api/ipfs.rs");
    let production = ipfs
        .split("#[cfg(test)]")
        .next()
        .expect("split always yields a first chunk");

    for call in [".list_all_repos()", ".list_visibility_rules_for_repos("] {
        assert_eq!(
            production.matches(call).count(),
            1,
            "F6 guard stale: `{call}` must appear exactly once in the production half \
             of api/ipfs.rs (the deadline-wrapped handler call) — update this guard"
        );
        let idx = production
            .find(call)
            .unwrap_or_else(|| panic!("F6 gate: api/ipfs.rs no longer calls `{call}`"));
        // The wrapper opens a few lines above the call (match tokio::time::timeout( ...
        // remaining budget ..., <query> )); a 240-char lookback covers it without
        // reaching the previous statement.
        let window = &production[idx.saturating_sub(240)..idx];
        assert!(
            window.contains("tokio::time::timeout("),
            "F6 gate missing: `{call}` must be wrapped in tokio::time::timeout(...) \
             clamped to the remaining request budget. An unwrapped await pins the held \
             walk permit for the whole DB stall, past GITLAWB_IPFS_REQUEST_BUDGET_SECS."
        );
    }
}

/// #174 F2 / KTD-3: the detached post-receive Pinata replication task must enqueue
/// only the push's `(ref, old, new)` tuples and RE-DERIVE its object set inside the
/// worker once a pin slot frees — it must NOT move the full per-push object list into
/// the closure and hold it across the `pin_semaphore` acquire. Retaining the list makes
/// every parked task (under a slow Pinata backend) hold an MB-scale OID list, so
/// outstanding memory grows O(pushes x object-list). Coalescing/shedding the task is
/// forbidden (its per-ref effects are non-idempotent), so the fix bounds the retained
/// data, not the task count.
///
/// Two load-bearing checks, both against the PRODUCTION half of `api/repos.rs` (the
/// `mod tests` half names the same identifiers in its own harness and would make the
/// scan vacuous): (a) the closure-local `object_list_pinata` binding — the retain form —
/// must be gone; reintroducing `let object_list_pinata = object_list;` turns this red.
/// (b) the re-derivation (`pinata_object_list_for_refs`) must appear AFTER the Pinata
/// pin permit is acquired, so the object list is materialized only inside the pin-bounded
/// section and a parked task holds O(ref tuples).
#[test]
fn f2_pinata_enqueues_refs_not_retained_object_lists() {
    let repos = src("api/repos.rs");
    let production = repos
        .split("#[cfg(test)]")
        .next()
        .expect("split always yields a first chunk");

    // (a) the retained-list form must be gone from production.
    assert!(
        !production.contains("object_list_pinata"),
        "F2/KTD-3 regression: the Pinata task retains a full per-push object list \
         (`object_list_pinata`) across the pin-permit acquire. Enqueue only the ref \
         tuples and re-derive the object set inside the worker (pinata_object_list_for_refs)."
    );

    // (b) the re-derivation runs AFTER the pin permit is acquired. Anchor on the
    // Pinata pin-admission clone so the window is the Pinata task, not the sibling
    // IPFS/encrypt spawn (which shares `pin_semaphore` but never re-derives).
    let anchor = production
        .find("let pin_sem_pinata")
        .expect("F2 gate stale: the Pinata pin-admission clone (pin_sem_pinata) moved");
    let tail = &production[anchor..];
    let acquire = tail
        .find(".acquire_owned()")
        .expect("F2 gate: the Pinata task no longer acquires a pin permit (acquire_owned)");
    let rederive = tail.find("pinata_object_list_for_refs(").expect(
        "F2 gate missing: the Pinata task must re-derive its object set via \
         pinata_object_list_for_refs; it can no longer move a pre-resolved list into the closure",
    );
    assert!(
        acquire < rederive,
        "F2 gate bypassed: the Pinata object-set re-derivation must run AFTER the pin \
         permit is acquired, so a parked task never holds the MB-scale object list"
    );

    // The re-derivation is driven by the push's ref tuples (the enqueued unit), not a
    // retained object list — tie "enqueue ref_updates" to the call explicitly.
    assert!(
        tail[rederive..].starts_with("pinata_object_list_for_refs(")
            && tail[rederive..]
                .get(..400)
                .map(|w| w.contains("ref_updates_clone"))
                .unwrap_or(false),
        "F2 gate: pinata_object_list_for_refs must re-derive from the push's ref tuples \
         (ref_updates_clone), the small unit the parked task retains"
    );
}

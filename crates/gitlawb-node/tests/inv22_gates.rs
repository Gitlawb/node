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
    let ipfs = src("api/ipfs.rs");

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

    // U2 / R1: a cancelled or timed-out `GET /ipfs/{cid}` must release admission only
    // after the blocking work it admitted has finished, not the instant the handler
    // future drops (the /ipfs half of #174 P1-a). The mechanism is the shared
    // `Arc<WalkAdmission>`: both walk permits are moved into it once per request and a
    // clone rides every `spawn_blocking`, so the permits release when the LAST holder
    // drops. Reverting to handler-local permits trips this; the per-site clones are
    // bound separately by `inv22_ipfs_walk_admission_reaches_every_blocking_site`.
    //
    // This previously required the permits to be owned by a detached `tokio::spawn`
    // running the whole pipeline. That closed the same bypass but kept an abandoned
    // request's full legacy scan running against a held slot, so the merge of #173 and
    // #174 kept the Arc and dropped the detached task.
    assert!(
        ipfs.contains("struct WalkAdmission")
            && ipfs.contains("let admission = std::sync::Arc::new(WalkAdmission {"),
        "U2/R1 gate missing: get_by_cid must move both /ipfs admission permits into a \
         shared Arc<WalkAdmission> whose clones ride the blocking work, so admission is \
         released only once that work completes (the /ipfs half of #174 P1-a)"
    );

    // U2 / KTD2 (#173 round-10): the probe/read children on the /ipfs path must be the
    // duration-bounded twins (process-group teardown via run_bounded_git), not the bare
    // `store::object_type` / `read_object_content` (or an unbounded `cat-file -s`) a tokio
    // timeout cannot cancel — otherwise a wedged cat-file lingers and pins the held
    // admission past the deadline. Reverting any twin call site back to a bare read trips
    // this.
    assert!(
        ipfs.contains("object_type_bounded(")
            && ipfs.contains("object_size_bounded(")
            && ipfs.contains("read_object_content_bounded("),
        "U2/KTD2 gate missing: the /ipfs probe+read must call the run_bounded_git-backed \
         *_bounded twins so a wedged cat-file is reaped at the deadline, not left to pin \
         the held /ipfs walk admission"
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
    // Split at the TEST MODULE, not at the first `#[cfg(test)]`. api/repos.rs carries
    // test-only items (the drain fault seam, the task entry point) ABOVE the production
    // code these gates scan for, so splitting on the attribute truncated the production
    // half above every line being checked and the gate went vacuously blind.
    let repos_production = repos
        .split("\nmod tests {")
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

/// F6/KTD-5 (IPFS metadata queries deadline-wrapped): `get_by_cid` acquires
/// the scarce walk permits (RAII, held for the whole request) BEFORE its metadata
/// queries, and the per-repo loop's first budget gate runs only later. So
/// both `list_repos_page_for_scan` and `list_visibility_rules_for_repos` must be clamped to the
/// remaining request budget — otherwise a query blocked in Postgres pins the walk slot
/// for the whole stall, past the budget. This scans the PRODUCTION half of `api/ipfs.rs`
/// (the `mod tests` half names the same calls in its own harness and would make the
/// check vacuous) and asserts each query call is immediately preceded by a
/// `tokio::time::timeout(` wrapper. Removing either wrapper turns this red (proven
/// load-bearing).
#[test]
fn f6_ipfs_metadata_queries_are_deadline_wrapped() {
    let ipfs = src("api/ipfs.rs");
    // Split at the TEST MODULE, not at the first `#[cfg(test)]`: the handler carries
    // in-line `#[cfg(test)]` query counters, so splitting on the attribute cut the
    // production half off above the calls this guard exists to check and the scan went
    // vacuously quiet (found 0 of each rather than failing on a missing wrapper).
    let production = ipfs
        .split("\nmod tests {")
        .next()
        .expect("split always yields a first chunk");

    // EVERY occurrence must be wrapped, not just the first. The handler now reaches
    // these queries from two places (the provenance fast path, one repo at a time, and
    // the legacy scan's preload), and an exact-count check would have to be relaxed
    // every time a call site is added, which is how a guard quietly stops covering the
    // site that matters. Requiring all of them scales with the code instead.
    for call in [
        ".list_repos_page_for_scan(",
        ".list_visibility_rules_for_repos(",
        ".get_repo_by_id(",
        ".is_repo_quarantined(",
    ] {
        let occurrences = production.matches(call).count();
        assert!(
            occurrences >= 1,
            "F6 guard stale: api/ipfs.rs no longer calls `{call}` — update this guard"
        );
        for (n, (idx, _)) in production.match_indices(call).enumerate() {
            // The wrapper opens a few lines above the call (match tokio::time::timeout(
            // ... remaining budget ..., <query> )); a 240-char lookback covers it
            // without reaching the previous statement.
            let window = &production[idx.saturating_sub(240)..idx];
            assert!(
                window.contains("tokio::time::timeout("),
                "F6 gate missing: occurrence {n} of `{call}` (of {occurrences}) is not \
                 wrapped in tokio::time::timeout(...) clamped to the remaining request \
                 budget. An unwrapped await pins the held walk permit for the whole DB \
                 stall, past GITLAWB_IPFS_REQUEST_BUDGET_SECS."
            );
        }
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
    // Split at the TEST MODULE, not at the first `#[cfg(test)]`. api/repos.rs carries
    // test-only items (the drain fault seam, the task entry point) ABOVE the production
    // code these gates scan for, so splitting on the attribute truncated the production
    // half above every line being checked and the gate went vacuously blind.
    let production = repos
        .split("\nmod tests {")
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

/// #174 U2 / F3 (second same-repo writer serialized until a disconnected first push's
/// git group is reaped): `git_receive_pack` must take the per-repo in-process write
/// lease and CARRY it on the write-path `AdmissionGuard` (via `.with_lease`), so the
/// lease rides `KillGroupOnDrop`'s detached reaper and frees only after the group is
/// reaped — supplementing the pg advisory lock, which `RepoWriteGuard::Drop` releases at
/// the disconnect instant. Tying the lease to `RepoWriteGuard` instead (or dropping the
/// `.with_lease` carry) reopens the race; the behavioral RED/GREEN test
/// (`f3_second_push_serialized_until_disconnected_group_reaped`) is the real bar, this
/// is the completeness tripwire. Scanned against the PRODUCTION half of `api/repos.rs`
/// (the `mod tests` half names these identifiers in its own harness).
#[test]
fn f3_second_writer_leased_until_reap() {
    let repos = src("api/repos.rs");
    let smart_http = src("git/smart_http.rs");
    // Split at the TEST MODULE, not at the first `#[cfg(test)]`. api/repos.rs carries
    // test-only items (the drain fault seam, the task entry point) ABOVE the production
    // code these gates scan for, so splitting on the attribute truncated the production
    // half above every line being checked and the gate went vacuously blind.
    let repos_production = repos
        .split("\nmod tests {")
        .next()
        .expect("split always yields a first chunk");

    // The lease is acquired, then carried by the AdmissionGuard (.with_lease), before
    // receive_pack runs the write. Severing any of the three turns this red.
    let lease_acquire = repos_production.find("repo_write_leases").expect(
        "F3 gate missing: git_receive_pack no longer takes the per-repo write lease \
         (state.repo_write_leases)",
    );
    let with_lease = repos_production.find(".with_lease(").expect(
        "F3 gate missing: the write-path AdmissionGuard no longer carries the lease \
         (.with_lease). The lease must ride the disconnect reaper via the AdmissionGuard, \
         NOT RepoWriteGuard (which drops at the disconnect instant, reopening F3).",
    );
    let receive = repos_production
        .find("smart_http::receive_pack_raw(")
        .expect("F3 gate stale: git_receive_pack no longer calls smart_http::receive_pack_raw");
    assert!(
        lease_acquire < with_lease && with_lease < receive,
        "F3 gate bypassed: the write lease must be acquired, then carried by the \
         AdmissionGuard (.with_lease), BEFORE receive_pack runs the write"
    );

    // The AdmissionGuard must actually hold the lease (Option<RepoWriteLease>) via a
    // with_lease setter, so it travels into the detached reaper. Removing the field or
    // method turns this red.
    assert!(
        smart_http.contains("_lease: Option<crate::state::RepoWriteLease>")
            && smart_http.contains("pub fn with_lease("),
        "F3 gate missing: AdmissionGuard must hold an Option<RepoWriteLease> set via \
         with_lease, so the lease rides the guard into KillGroupOnDrop's reaper"
    );
}

/// #174 U1 — every blocking walk in the `/ipfs` scan carries the request's walk
/// admission.
///
/// The admission is an `Arc<WalkAdmission>` cloned into each `spawn_blocking`
/// closure, so the global + per-source permits release only when the last holder
/// drops: a client disconnect leaves the abandoned closure holding the slot, and a
/// panicking closure leaves the handler holding it.
///
/// Only the walk site runs under `state.git_bin`, so only it can be pinned by the
/// fake-git harness and mutation-verified dynamically (see
/// `get_by_cid_walk_permit_held_through_blocking_walk`). The probe and the content
/// read deliberately shell to the real `git`, which is why this structural check
/// exists: it binds all three sites, and any blocking site added to this loop
/// later, without reversing that deliberate independence.
///
/// MUTATION (RED): delete any one `Arc::clone(ctx.admission)` binding, or drop the
/// clone from inside its closure, and the count falls below three.
#[test]
fn inv22_ipfs_walk_admission_reaches_every_blocking_site() {
    let ipfs = src("api/ipfs.rs");

    // The shared owner must exist and be built once per request.
    assert!(
        ipfs.contains("struct WalkAdmission") && ipfs.contains("Arc::new(WalkAdmission {"),
        "U1 gate missing: the /ipfs walk admission must be a shared WalkAdmission, \
         not a handler-local permit pair"
    );

    // Every blocking site in the scan takes its own clone...
    // `Arc::clone(ctx.admission)` in the gate, `Arc::clone(&admission)` if a site is
    // ever added back in the handler body itself; count both spellings.
    let clones = ipfs.matches("Arc::clone(ctx.admission)").count()
        + ipfs.matches("Arc::clone(&admission)").count();
    assert!(
        clones >= 3,
        "U1 gate bypassed: expected an admission clone for each of the three \
         /ipfs spawn_blocking sites (probe, walk, read); found {clones}. A blocking \
         walk that does not hold the admission lets a disconnect or a panic free the \
         slot while its git child is still running."
    );

    // ...and each clone is actually moved INTO the blocking closure, not merely
    // created in the async frame (which would hold nothing across the join).
    let held = ipfs.matches("let _admission = ").count();
    assert!(
        held >= 3,
        "U1 gate bypassed: each admission clone must be bound inside its \
         spawn_blocking closure so the blocking work owns it; found {held} of 3."
    );

    // The count of blocking sites is itself the thing being covered: if a fourth
    // appears, it needs an admission clone too and this gate must be revisited.
    let sites = ipfs.matches("spawn_blocking(move ||").count();
    assert_eq!(
        sites, 3,
        "the /ipfs scan grew or lost a spawn_blocking site ({sites} found, expected 3); \
         give any new blocking walk its own Arc::clone(&admission) and update this gate"
    );
}

/// #174 U5: the post-receive replication tail is spawned at the DURABILITY BOUNDARY,
/// which is the moment receive-pack returns success, not the end of the handler and
/// not after `guard.release()`.
///
/// The tail owes this push its pins, recovery copy, and announcements. Everything
/// below the spawn stays in the cancellable request future, so anything the tail is
/// spawned after is a window where a client disconnect drops that work while the pack
/// is already durable on disk. `guard.release()` is such a window: on success it
/// awaits the Tigris upload and then the advisory unlock.
///
/// The lower bound matters just as much as the upper one: `release` runs on failure
/// too, so an ungated spawn would fire for a push git rejected, pinning and announcing
/// a half-applied repo. Above `release` the `?` on `receive_result` can no longer be
/// what gates it, so the success check is explicit and this gate binds it: the spawn
/// must sit inside `if push_succeeded`, and `release` must consume the same flag so
/// the two cannot drift apart.
///
/// This is an ordering check rather than a cancellation-race test on purpose: it is
/// the companion to `receive_pack_tail_survives_a_disconnect_during_release`, which
/// drives the actual disconnect through a parked `release`. Same instrument the F3
/// gate above uses.
///
/// MUTATION (RED): move the `tokio::spawn(post_receive_replication_tail` call below
/// `guard.release(` and the ordering assertion fails; take it out of the
/// `if push_succeeded` block and the failed-push assertion fails.
#[test]
fn inv22_replication_tail_spawns_at_the_durability_boundary() {
    let repos = src("api/repos.rs");
    // Production half only — the tests below name these identifiers too.
    // Split at the TEST MODULE, not at the first `#[cfg(test)]`. api/repos.rs carries
    // test-only items (the drain fault seam, the task entry point) ABOVE the production
    // code these gates scan for, so splitting on the attribute truncated the production
    // half above every line being checked and the gate went vacuously blind.
    let production = repos
        .split("\nmod tests {")
        .next()
        .expect("split always yields a first chunk");

    let success_flag = production
        .find("let push_succeeded = ")
        .expect("U5 gate missing: the tail's success flag must be bound before the gate");
    let gate_open = production
        .find("if push_succeeded {")
        .expect("U5 gate missing: the tail spawn must be gated on the push having succeeded");
    let spawn = production
        .find("tokio::spawn(post_receive_replication_tail(")
        .expect("U5 gate missing: the replication tail must be spawned by git_receive_pack");
    let release = production
        .find(".release(push_succeeded)")
        .expect("U5 gate stale: release must consume the same success flag as the tail gate");
    let touch = production
        .find("state.db.touch_repo(")
        .expect("U5 gate stale: git_receive_pack no longer calls touch_repo");
    // #26 Split PR 1 step 3 — the webhook fan-out moved into
    // `durable_outbox::apply_request_effects`, which the live
    // handler calls inline (the recovery drain calls the same
    // function on the next startup). The gate now pins that the
    // handler is wired to the executor, not to a per-ref inline
    // webhook call.
    let effects_executor = production
        .find("apply_request_effects(&state, &request_id)")
        .expect("U5 gate stale: git_receive_pack no longer calls apply_request_effects inline");

    assert!(
        success_flag < gate_open && gate_open < spawn,
        "U5 gate bypassed: the tail must be spawned inside `if push_succeeded`, or a \
         rejected push spawns a tail that pins and announces a half-applied repo"
    );
    // Still inside that block: no `}` may close it between the gate and the spawn.
    assert!(
        !production[gate_open + "if push_succeeded {".len()..spawn].contains('}'),
        "U5 gate bypassed: the tail spawn left the `if push_succeeded` block, so a \
         rejected push now spawns a tail"
    );
    assert!(
        spawn < release && spawn < touch && spawn < effects_executor,
        "U5 gate bypassed: the tail must be spawned BEFORE guard.release, touch_repo \
         and the effect executor, so a disconnect in any of those windows cannot drop \
         this push's pins, recovery copy, and announcements"
    );
}

/// #26 Split PR 1 step 3 — drain + handler share a single effect
/// executor. The live handler (api/repos.rs) and the recovery
/// drain (`durable_outbox::drain_receive_pack_requests_with`) both
/// call `apply_request_effects`, so the per-ref effects fan-out
/// lives in exactly one place. The v29 per-ref walk
/// (`derive_one`, `drain_pending_ref_transitions_all`,
/// `lookup_accepted_ordinal`) is dead code: any caller reintroduced
/// would be the per-ref walk the step-3 PR removed. This gate
/// fails if a call site slips back in or the new seam is bypassed.
#[test]
fn inv26_step3_live_and_drain_share_apply_request_effects() {
    let repos = src("api/repos.rs");
    let outbox = src("durable_outbox.rs");

    // The live handler calls `apply_request_effects`. Split the
    // file at the test attribute so test code can't satisfy the
    // gate by itself.
    let production_repos = repos
        .split("\nmod tests {")
        .next()
        .expect("split always yields a first chunk");

    assert!(
        production_repos.contains("apply_request_effects(&state, &request_id)"),
        "live handler must call `apply_request_effects(&state, &request_id)`; \
         reverting to a per-ref inline fan-out splits live and recovery"
    );

    // The drain's per-request seam calls the same executor. Test
    // code lives below `mod drain_tests`, so split there too.
    let production_outbox = outbox
        .split("\nmod drain_tests {")
        .next()
        .expect("split always yields a first chunk");

    assert!(
        production_outbox.contains("drain_receive_pack_requests_with"),
        "drain seam `drain_receive_pack_requests_with` must exist; \
         removing it forces a per-ref walk back into the drain"
    );
    assert!(
        production_outbox.contains("apply_request_effects"),
        "durable_outbox production code must define `apply_request_effects`; \
         removing it splits the executor between live and recovery"
    );

    // The drain's per-request walker is wired to the executor.
    // The closure body of `drain_receive_pack_requests_with` is the
    // only call site — if a future change calls `derive_one`
    // instead, this assertion fires.
    let drain_seam_open = production_outbox
        .find("pub async fn drain_receive_pack_requests_with<F, Fut>")
        .expect("drain seam must be defined in the production half");
    let drain_seam_close = production_outbox[drain_seam_open..]
        .find("\n}\n")
        .expect("drain seam body must close");
    let drain_seam_body = &production_outbox[drain_seam_open..drain_seam_open + drain_seam_close];
    assert!(
        drain_seam_body.contains("apply_request_effects"),
        "drain_receive_pack_requests_with must call apply_request_effects; \
         wiring it to a per-ref helper reintroduces the v29 walk"
    );

    // The deleted per-ref drain must have zero call sites in the
    // production half. A regression that re-adds a caller would
    // bring back the per-ref fan-out.
    assert!(
        !production_outbox.contains("drain_pending_ref_transitions_all("),
        "deleted `drain_pending_ref_transitions_all` must have zero production call sites; \
         a per-ref walk is reintroduced"
    );
    assert!(
        !production_outbox.contains("derive_one("),
        "deleted `derive_one` must have zero production call sites; \
         the per-ref fan-out is reintroduced"
    );
    assert!(
        !production_outbox.contains("lookup_accepted_ordinal("),
        "deleted `lookup_accepted_ordinal` must have zero production call sites; \
         the per-ref ordinal lookup is reintroduced"
    );
    assert!(
        !production_repos.contains("derive_one("),
        "deleted `derive_one` must have zero live-handler call sites"
    );
    assert!(
        !production_repos.contains("drain_pending_ref_transitions"),
        "deleted per-ref drain functions must have zero live-handler call sites"
    );
}

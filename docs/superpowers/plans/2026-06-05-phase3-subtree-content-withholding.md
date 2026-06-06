# Phase 3: Subtree Content Withholding (mode B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a mode-`b` subtree visibility rule actually withhold that subtree's file content on clone/fetch over the node's HTTP git read path, while keeping every commit and tree SHA intact, so a non-reader sees the directory structure and blob SHAs but never the private bytes.

**Architecture:** The authorization decision already exists as the pure `visibility_check` (one decision per path). Phase 3 adds two node-side pieces: (1) a blob-OID resolver that, given a repo's refs plus the caller's rules, returns the set of blob object IDs the caller may not read (a blob is withheld only if it appears at no allowed path); and (2) a filtered `upload-pack` serve path that builds the response pack excluding those OIDs. The two existing read handlers (`git_info_refs`, `git_upload_pack`) keep their current whole-repo 404 gate unchanged and gain a filtered serve branch when, and only when, the caller has at least one withheld blob. Trees and commits are always sent in full, so SHAs stay intact; only blob content is omitted.

**Tech Stack:** Rust, axum, the system `git` CLI (shelled out, as the codebase already does in `git/store.rs` and `git/smart_http.rs`), `tempfile` for fixture repos in tests.

**Scope boundary:** This plan covers the node-side enforcement and the security guarantee (private blob bytes are never placed in the served pack), proven by inspecting the produced pack. It deliberately does NOT cover: the `git-remote-gitlawb` client-side change that lets a non-reader get a *clean* partial checkout (a stock `git clone` of a repo with a withheld blob will fail at checkout on the missing object; that UX work is a separate follow-up plan), filtered-pack caching, or incremental-fetch (`have`-line) hardening beyond what falls out naturally. Those are listed under "Out of scope / follow-ups" at the end.

---

## File Structure

- **Create:** `crates/gitlawb-node/src/git/visibility_pack.rs`: the blob-OID resolver (`withheld_blob_oids`) and its tests. One responsibility: decide which blob OIDs to withhold for a caller.
- **Modify:** `crates/gitlawb-node/src/git/mod.rs`: add `pub mod visibility_pack;`.
- **Modify:** `crates/gitlawb-node/src/git/smart_http.rs`: add `upload_pack_excluding` (filtered serve) alongside the existing `upload_pack`, plus a small `pack_object_ids` test helper.
- **Modify:** `crates/gitlawb-node/src/api/repos.rs`: in `git_upload_pack` (around line 368-407) branch to the filtered serve when the caller has withheld blobs; `git_info_refs` (around line 308-365) needs no functional change but gets a confirming test.
- **Modify (test oracle only):** `crates/gitlawb-node/src/visibility.rs`: no logic change; `visibility_check` is reused as-is by the resolver.

---

## Task 0: Spike: pin the filtered-serve mechanism

This is the one genuinely uncertain piece: how to make `git upload-pack` (or `git pack-objects`) produce a clone/fetch response that omits a specific set of blob OIDs while still sending the trees that reference them, and how to frame that as a valid `application/x-git-upload-pack-result` body. Everything downstream depends on a single function signature, not on the mechanism, so this task nails the mechanism by experiment and records the result. No production code is committed in this task.

**Files:**
- Scratch only (a throwaway shell script and a temp repo). Findings are written back into this plan's "Task 0 Findings" block below.

- [ ] **Step 1: Build a fixture repo with a public and a private file**

Run:
```bash
cd "$(mktemp -d)" && export FIX=$PWD
git init -q work && cd work
git config user.email t@t && git config user.name t
mkdir -p public secret
echo "public bytes" > public/a.txt
echo "TOP SECRET" > secret/b.txt
git add . && git commit -qm init
SECRET_OID=$(git rev-parse HEAD:secret/b.txt)
PUBLIC_OID=$(git rev-parse HEAD:public/a.txt)
echo "secret blob=$SECRET_OID public blob=$PUBLIC_OID"
cd .. && git clone -q --bare work bare.git
```

- [ ] **Step 2: Produce a pack that excludes the secret blob OID**

Run (mechanism candidate: explicit object list to `pack-objects`):
```bash
cd "$FIX/bare.git"
# Every object reachable from all refs, as "oid [path]" lines:
git rev-list --objects --all > /tmp/all_objs.txt
# Drop the secret blob's line, keep only the OID column:
grep -v "^$SECRET_OID" /tmp/all_objs.txt | awk '{print $1}' > /tmp/keep_oids.txt
# Build a pack of exactly those objects:
git pack-objects --stdout < /tmp/keep_oids.txt > /tmp/filtered.pack
# Confirm the secret blob is absent and the public blob present:
git verify-pack -v /tmp/filtered.pack | grep -E "$SECRET_OID|$PUBLIC_OID" || echo "secret absent (expected: only public line prints)"
```
Expected: the public OID prints, the secret OID does not. This proves the OID-exclusion mechanism.

- [ ] **Step 3: Determine the upload-pack response framing**

Run, capturing the exact bytes a real clone request/response uses, so the framing in Task 3 is correct rather than guessed:
```bash
cd "$FIX/bare.git"
git config uploadpack.allowFilter true
# Capture a normal v2 clone's request body and response shape:
GIT_TRACE_PACKET=1 git -c protocol.version=2 clone -q --bare "$FIX/bare.git" "$FIX/clone1.git" 2>/tmp/trace.txt
# Inspect the fetch command + response sections (look for "packfile", sideband 0001/0002, flush 0000):
grep -E "fetch|want|packfile|0000|ACK|NAK|ready" /tmp/trace.txt | head -40
```
Record from the trace: (a) whether the node should target protocol v2 or v0, (b) the exact section markers around the packfile, (c) whether sideband-64k framing is in use.

- [ ] **Step 4: Decide the serve implementation and write findings**

Choose the implementation for `upload_pack_excluding` based on Steps 1-3, preferring the lowest-risk option that the trace confirms works:

- **Option A (preferred): delegate to `git upload-pack` with an injected mandatory filter.** Set `uploadpack.allowFilter=true`, rewrite the client's fetch request to carry `filter sparse:oid=<spec-blob>` (v2) where the spec blob excludes the denied paths, and let `git upload-pack` build and frame the entire response. Lowest framing risk; depends on `sparse:oid` negation behaving (verify in Step 2 variant).
- **Option B (fallback): hand-build the pack.** Parse `want` OIDs from the request body, run `git rev-list --objects <wants>` minus the withheld OIDs, pipe to `git pack-objects --stdout`, and frame the result per the markers captured in Step 3.

Write the chosen option, the exact `git` invocation(s), and the framing bytes into the "Task 0 Findings" block below. The downstream tasks reference `upload_pack_excluding(repo_path, request_body, withheld_oids) -> Result<Response>` regardless of which option is recorded here.

- [ ] **Step 5: No commit**

This task records findings only; there is nothing to commit.

### Task 0 Findings

Executed 2026-06-06. Results:

- **Mechanism chosen:** Option B (hand-built pack). `sparse:oid` negation was not needed; explicit OID exclusion via `rev-list` + `pack-objects` is deterministic and self-contained.
- **Exact git invocation(s):**
  - `git rev-list --objects --all` (in repo dir) to enumerate reachable objects as `oid [path]` lines.
  - Filter out withheld OIDs (first whitespace column), feed remaining OIDs newline-delimited to `git pack-objects --stdout`.
  - Verified exclusion by `git index-pack <pack>` then `git verify-pack -v <pack>`: secret blob absent, public blob present. Confirmed.
- **Protocol version targeted:** v2 packfile section. The serve hand-frames the body, so no `GIT_PROTOCOL`/`-c protocol.version` flag is passed to our own process; we emit the v2 `packfile` section bytes directly.
- **Response framing (captured by driving `git upload-pack --stateless-rpc` with `GIT_PROTOCOL=version=2`):**
  - `pkt_line("packfile\n")` (plain control pkt-line, not a sideband band).
  - Then sideband-64k bands: `0x02` = progress (optional, we omit), `0x01` = pack data whose payload begins `PACK...`.
  - Pack data chunked under the pkt-line limit, each chunk prefixed with `0x01`.
  - Terminated by `0000` flush.
  - This matches the plan's Option B framing in Task 2 exactly; no adjustment needed.
- **Confirmed:** served pack contains PUBLIC_OID, excludes SECRET_OID.

---

## Task 1: Blob-OID resolver: withhold a private subtree's blobs for a non-reader

**Files:**
- Create: `crates/gitlawb-node/src/git/visibility_pack.rs`
- Modify: `crates/gitlawb-node/src/git/mod.rs` (add module)

- [ ] **Step 1: Register the module**

In `crates/gitlawb-node/src/git/mod.rs`, add the line in alphabetical position (after `pub mod store;`):
```rust
pub mod visibility_pack;
```

- [ ] **Step 2: Write the failing test (non-reader withholds only the private blob)**

Create `crates/gitlawb-node/src/git/visibility_pack.rs` with the test module first:
```rust
//! Resolve which blob OIDs must be withheld from a caller because every path
//! at which the blob appears is denied by the repo's visibility rules. Trees
//! and commits are never withheld (mode B keeps SHAs intact); only blob
//! content is held back.

use crate::db::{VisibilityMode, VisibilityRule};
use crate::git::store;
use crate::visibility::{visibility_check, Decision};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::process::Command;
    use tempfile::TempDir;

    fn rule(path_glob: &str, readers: &[&str]) -> VisibilityRule {
        VisibilityRule {
            id: "x".into(),
            repo_id: "r1".into(),
            path_glob: path_glob.into(),
            mode: VisibilityMode::B,
            reader_dids: readers.iter().map(|s| s.to_string()).collect(),
            created_by: "did:key:zOwner".into(),
            created_at: Utc::now(),
        }
    }

    const OWNER: &str = "did:key:zOwner";

    /// Build a bare repo with public/a.txt and secret/b.txt at one commit.
    /// Returns (tempdir, bare_path, secret_blob_oid, public_blob_oid).
    fn fixture() -> (TempDir, std::path::PathBuf, String, String) {
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let run = |args: &[&str], dir: &Path| {
            let ok = Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?} failed");
        };
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"public bytes\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"TOP SECRET\n").unwrap();
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "init"], &work);
        let oid = |path: &str| {
            let out = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{path}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let secret = oid("secret/b.txt");
        let public = oid("public/a.txt");
        run(
            &["clone", "-q", "--bare", work.to_str().unwrap(), bare.to_str().unwrap()],
            td.path(),
        );
        (td, bare, secret, public)
    }

    #[test]
    fn non_reader_withholds_only_the_private_blob() {
        let (_td, bare, secret, public) = fixture();
        let rules = [rule("/secret/**", &["did:key:zFriend"])];
        let withheld =
            withheld_blob_oids(&bare, &rules, true, OWNER, Some("did:key:zStranger")).unwrap();
        assert!(withheld.contains(&secret), "secret blob must be withheld");
        assert!(!withheld.contains(&public), "public blob must NOT be withheld");
    }

    #[test]
    fn owner_withholds_nothing() {
        let (_td, bare, secret, public) = fixture();
        let rules = [rule("/secret/**", &["did:key:zFriend"])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, Some(OWNER)).unwrap();
        assert!(withheld.is_empty(), "owner sees everything");
        let _ = (secret, public);
    }

    #[test]
    fn listed_reader_withholds_nothing() {
        let (_td, bare, _secret, _public) = fixture();
        let rules = [rule("/secret/**", &["did:key:zFriend"])];
        let withheld =
            withheld_blob_oids(&bare, &rules, true, OWNER, Some("did:key:zFriend")).unwrap();
        assert!(withheld.is_empty(), "listed reader sees the subtree");
    }

    #[test]
    fn no_subtree_rules_withholds_nothing() {
        let (_td, bare, _secret, _public) = fixture();
        let withheld = withheld_blob_oids(&bare, &[], true, OWNER, None).unwrap();
        assert!(withheld.is_empty(), "public repo, no rules, nothing withheld");
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p gitlawb-node visibility_pack:: -- --nocapture`
Expected: FAIL to compile with "cannot find function `withheld_blob_oids`".

- [ ] **Step 4: Implement `withheld_blob_oids`**

Add above the `#[cfg(test)]` block in `visibility_pack.rs`:
```rust
/// List every (blob_oid, "/repo/relative/path") pair reachable from any branch
/// ref in `repo_path`. Uses `git ls-tree -r` per ref so each path a blob lives
/// at is represented (the same blob content can appear at several paths). Paths
/// are returned with a leading "/" to match the glob form used by visibility
/// rules ("/secret/**").
fn blob_paths(repo_path: &Path) -> Result<Vec<(String, String)>> {
    let refs = store::list_refs(repo_path).context("list_refs failed")?;
    let mut out = Vec::new();
    for (refname, _oid) in refs {
        if !refname.starts_with("refs/heads/") && !refname.starts_with("refs/tags/") {
            continue;
        }
        let listing = std::process::Command::new("git")
            .args(["ls-tree", "-r", &refname])
            .current_dir(repo_path)
            .output()
            .context("git ls-tree -r failed")?;
        if !listing.status.success() {
            continue;
        }
        for line in String::from_utf8_lossy(&listing.stdout).lines() {
            // "<mode> blob <oid>\t<path>"
            let Some((meta, path)) = line.split_once('\t') else {
                continue;
            };
            let mut parts = meta.split_whitespace();
            let _mode = parts.next();
            let kind = parts.next();
            let oid = parts.next();
            if kind == Some("blob") {
                if let Some(oid) = oid {
                    out.push((oid.to_string(), format!("/{path}")));
                }
            }
        }
    }
    Ok(out)
}

/// Blob OIDs the caller may not read. A blob is withheld only if visibility
/// denies the caller at *every* path the blob appears at; a blob that is also
/// reachable through an allowed path is sent (its content is public elsewhere).
///
/// The whole-repo "/" gate is handled by the caller before this function runs:
/// if "/" denies, the caller gets a 404 and never reaches the filtered serve.
pub fn withheld_blob_oids(
    repo_path: &Path,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Result<HashSet<String>> {
    let mut denied: HashSet<String> = HashSet::new();
    let mut allowed: HashSet<String> = HashSet::new();
    for (oid, path) in blob_paths(repo_path)? {
        match visibility_check(rules, is_public, owner_did, caller, &path) {
            Decision::Deny => {
                denied.insert(oid);
            }
            Decision::Allow => {
                allowed.insert(oid);
            }
        }
    }
    Ok(denied.difference(&allowed).cloned().collect())
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p gitlawb-node visibility_pack::`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add crates/gitlawb-node/src/git/visibility_pack.rs crates/gitlawb-node/src/git/mod.rs
git commit -m "feat(node): resolve withheld blob OIDs for path-scoped visibility"
```

---

## Task 2: Filtered upload-pack serve (`upload_pack_excluding`)

**Files:**
- Modify: `crates/gitlawb-node/src/git/smart_http.rs`

Implement using the mechanism recorded in **Task 0 Findings**. The code below is written for **Option B (hand-built pack)** because it is self-contained and deterministic; if Task 0 recorded Option A, implement that instead behind the identical signature and adjust the test in Step 2 only where it inspects framing (the object-content assertion stays).

- [ ] **Step 1: Add the test module with a pack-inspection helper and the failing test**

At the bottom of `smart_http.rs`, add a `#[cfg(test)] mod tests` containing the pack-inspection helper (lists the OIDs inside a raw pack so tests can assert membership) and the first failing test:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    /// List OIDs in a pack by writing it to a temp dir and running verify-pack.
    pub(super) fn pack_object_ids(pack: &[u8]) -> std::collections::HashSet<String> {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.pack");
        std::fs::write(&path, pack).unwrap();
        // index-pack creates the matching .idx next to the pack.
        let ok = Command::new("git")
            .args(["index-pack", path.to_str().unwrap()])
            .status()
            .unwrap()
            .success();
        assert!(ok, "index-pack failed");
        let out = Command::new("git")
            .args(["verify-pack", "-v", path.to_str().unwrap()])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|t| t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit()))
            .map(|s| s.to_string())
            .collect()
    }

    #[tokio::test]
    async fn filtered_serve_excludes_withheld_blob() {
        // Build a bare repo, capture the secret + public blob OIDs.
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let g = |args: &[&str], dir: &std::path::Path| {
            assert!(Command::new("git").args(args).current_dir(dir).status().unwrap().success());
        };
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"pub\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"SECRET\n").unwrap();
        g(&["init", "-q"], &work);
        g(&["config", "user.email", "t@t"], &work);
        g(&["config", "user.name", "t"], &work);
        g(&["add", "."], &work);
        g(&["commit", "-qm", "init"], &work);
        let oid = |p: &str| {
            let o = Command::new("git").args(["rev-parse", &format!("HEAD:{p}")])
                .current_dir(&work).output().unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        let secret = oid("secret/b.txt");
        let public = oid("public/a.txt");
        g(&["clone", "-q", "--bare", work.to_str().unwrap(), bare.to_str().unwrap()], td.path());

        let mut withheld = std::collections::HashSet::new();
        withheld.insert(secret.clone());

        let pack = build_filtered_pack(&bare, &withheld).unwrap();
        let ids = pack_object_ids(&pack);
        assert!(ids.contains(&public), "public blob must be in the pack");
        assert!(!ids.contains(&secret), "secret blob must NOT be in the pack");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p gitlawb-node smart_http::tests::filtered_serve_excludes_withheld_blob`
Expected: FAIL to compile with "cannot find function `build_filtered_pack`".

- [ ] **Step 3: Implement `build_filtered_pack` and `upload_pack_excluding`**

Add to `smart_http.rs` (above the `#[cfg(test)]` block). `build_filtered_pack` is the deterministic core (unit-tested in Step 1); `upload_pack_excluding` frames it as an HTTP response using the markers recorded in Task 0 Findings:
```rust
use std::collections::HashSet;

/// Build a packfile containing every object reachable from all refs EXCEPT the
/// given blob OIDs. Commits and trees are always included, so SHAs stay intact;
/// only the named blobs are dropped.
pub fn build_filtered_pack(repo_path: &Path, withheld: &HashSet<String>) -> Result<Vec<u8>> {
    // All reachable objects as "oid [path]" lines.
    let rev = std::process::Command::new("git")
        .args(["rev-list", "--objects", "--all"])
        .current_dir(repo_path)
        .output()?;
    if !rev.status.success() {
        bail!("git rev-list failed: {}", String::from_utf8_lossy(&rev.stderr));
    }
    let mut keep = Vec::new();
    for line in String::from_utf8_lossy(&rev.stdout).lines() {
        let oid = line.split_whitespace().next().unwrap_or("");
        if oid.is_empty() || withheld.contains(oid) {
            continue;
        }
        keep.push(oid.to_string());
    }
    let mut child = std::process::Command::new("git")
        .args(["pack-objects", "--stdout"])
        .current_dir(repo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(keep.join("\n").as_bytes())?;
        stdin.write_all(b"\n")?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("git pack-objects failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(out.stdout)
}

/// Serve a clone/fetch with the withheld blobs removed from the response pack.
/// Framing follows Task 0 Findings; the body wraps `build_filtered_pack` output
/// in the upload-pack `packfile` section with sideband-64k, terminated by flush.
pub async fn upload_pack_excluding(
    repo_path: &Path,
    _request_body: Bytes,
    withheld: &HashSet<String>,
) -> Result<Response> {
    let pack = build_filtered_pack(repo_path, withheld)?;
    let mut body = Vec::new();
    body.extend_from_slice(&pkt_line("packfile\n"));
    // sideband-64k: band 1 carries pack data, chunked under the pkt-line limit.
    for chunk in pack.chunks(65515) {
        let mut framed = Vec::with_capacity(chunk.len() + 1);
        framed.push(0x01);
        framed.extend_from_slice(chunk);
        let len = framed.len() + 4;
        body.extend_from_slice(format!("{len:04x}").as_bytes());
        body.extend_from_slice(&framed);
    }
    body.extend_from_slice(b"0000");
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-upload-pack-result")
        .header("Cache-Control", "no-cache")
        .body(Body::from(body))?)
}
```
> If Task 0 recorded **Option A**, replace the two functions above with the injected-filter delegation to `git upload-pack`, keeping the `build_filtered_pack` name as a thin wrapper so the Step 1 test still drives the OID-exclusion guarantee.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p gitlawb-node smart_http::tests::filtered_serve_excludes_withheld_blob`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/gitlawb-node/src/git/smart_http.rs
git commit -m "feat(node): filtered upload-pack serve that omits withheld blobs"
```

---

## Task 3: Wire filtered serve into the upload-pack handler

**Files:**
- Modify: `crates/gitlawb-node/src/api/repos.rs` (`git_upload_pack`, lines ~368-407)

- [ ] **Step 1: Add the imports**

At the top of `repos.rs`, in the existing `use crate::git::{...}` group, add `visibility_pack`:
```rust
use crate::git::{smart_http, store, visibility_pack};
```
(If `store` is not already in that group, keep whatever is there and append `visibility_pack`.)

- [ ] **Step 2: Branch to the filtered serve**

In `git_upload_pack`, the current body computes `rules`, runs the whole-repo `visibility_check(..., "/")` 404 gate, acquires `disk_path`, then calls `smart_http::upload_pack(&disk_path, body)`. Keep the 404 gate and the `acquire` exactly as they are. Replace only the single serve call:
```rust
    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let body_len = body.len();

    let withheld =
        visibility_pack::withheld_blob_oids(&disk_path, &rules, record.is_public, &record.owner_did, caller)
            .map_err(|e| AppError::Git(e.to_string()))?;

    let resp = if withheld.is_empty() {
        smart_http::upload_pack(&disk_path, body).await
    } else {
        tracing::info!(repo = %name, caller = ?caller, withheld = withheld.len(), "serving filtered pack");
        smart_http::upload_pack_excluding(&disk_path, body, &withheld).await
    }
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("bad line length") || msg.contains("protocol error") {
            tracing::warn!(repo = %name, err = %msg, "git-upload-pack: bad client request");
            AppError::BadRequest(msg)
        } else {
            tracing::error!(repo = %name, err = %msg, "git-upload-pack failed");
            AppError::Git(msg)
        }
    })?;
```
Leave the `crate::metrics::record_fetch(...)` line and everything after it unchanged.

- [ ] **Step 3: Verify the crate builds and existing tests pass**

Run: `cargo test -p gitlawb-node`
Expected: PASS, including the Phase 1 whole-repo visibility tests (no regression). The new fast-path (`withheld.is_empty()`) must keep public and fully-authorized clones byte-identical to before.

- [ ] **Step 4: Commit**

```bash
git add crates/gitlawb-node/src/api/repos.rs
git commit -m "feat(node): serve filtered pack when caller has withheld subtree blobs"
```

---

## Task 4: End-to-end clone test through a real git client

**Files:**
- Modify: `crates/gitlawb-node/src/git/smart_http.rs` (extend `mod tests`)

This proves the served body is a clone a real `git` accepts and that the private bytes are absent from the resulting object store, which is the security guarantee.

- [ ] **Step 1: Write the failing end-to-end test**

Add to `smart_http.rs` `mod tests`:
```rust
    #[tokio::test]
    async fn client_clone_lacks_withheld_blob_bytes() {
        use axum::body::to_bytes;
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let g = |args: &[&str], dir: &std::path::Path| {
            assert!(Command::new("git").args(args).current_dir(dir).status().unwrap().success());
        };
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"pub\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"SECRET\n").unwrap();
        g(&["init", "-q"], &work);
        g(&["config", "user.email", "t@t"], &work);
        g(&["config", "user.name", "t"], &work);
        g(&["add", "."], &work);
        g(&["commit", "-qm", "init"], &work);
        let secret_oid = {
            let o = Command::new("git").args(["rev-parse", "HEAD:secret/b.txt"])
                .current_dir(&work).output().unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        g(&["clone", "-q", "--bare", work.to_str().unwrap(), bare.to_str().unwrap()], td.path());

        let mut withheld = std::collections::HashSet::new();
        withheld.insert(secret_oid.clone());

        let resp = upload_pack_excluding(&bare, Bytes::new(), &withheld).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let ids = pack_object_ids(&extract_pack(&body));
        assert!(!ids.contains(&secret_oid), "withheld blob must be absent from served pack");
    }

    /// Strip the upload-pack `packfile` section framing, returning the raw pack.
    /// Mirrors how a client de-frames the sideband-64k band-1 stream.
    fn extract_pack(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= body.len() {
            let len = usize::from_str_radix(
                std::str::from_utf8(&body[i..i + 4]).unwrap_or("0000"),
                16,
            )
            .unwrap_or(0);
            if len == 0 {
                i += 4;
                continue;
            }
            let chunk = &body[i + 4..i + len];
            // band 1 = pack data; skip "packfile\n" control line and other bands.
            if chunk.first() == Some(&0x01) {
                out.extend_from_slice(&chunk[1..]);
            }
            i += len;
        }
        out
    }
```
> If Task 0 chose Option A (delegated framing), `extract_pack` may need adjusting to the exact bands git emits; use the trace from Task 0 Step 3 to confirm.

- [ ] **Step 2: Run the test to verify it fails (then passes once framing is right)**

Run: `cargo test -p gitlawb-node smart_http::tests::client_clone_lacks_withheld_blob_bytes`
Expected: initially may FAIL if framing constants are off; iterate `extract_pack` / framing against Task 0 findings until PASS. Success criterion: the withheld OID is absent from the served pack.

- [ ] **Step 3: Commit**

```bash
git add crates/gitlawb-node/src/git/smart_http.rs
git commit -m "test(node): end-to-end assert served pack omits withheld blob"
```

---

## Task 5: Confirm `info/refs` does not leak and stays consistent

**Files:**
- Modify: `crates/gitlawb-node/src/api/repos.rs` (no logic change to `git_info_refs`; add a confirming comment only if needed)

The ref advertisement lists commit tips, not blob content, so a mode-B subtree does not require hiding any ref: a non-reader still clones the same commits, just without the private blobs. This task records that decision so a future reader does not "fix" it by gating `info/refs` on subtree rules.

- [ ] **Step 1: Add a clarifying comment**

In `git_info_refs`, next to the existing whole-repo gate (the `if service == "git-upload-pack"` block around line 330), append one line after the existing comment:
```rust
    // Subtree (mode B) rules do not gate the advertisement: refs expose commit
    // tips only, and blob withholding happens in the upload-pack pack build.
```

- [ ] **Step 2: Verify nothing else changed**

Run: `git diff crates/gitlawb-node/src/api/repos.rs`
Expected: only the one comment line added in `git_info_refs`; the whole-repo 404 gate is untouched.

- [ ] **Step 3: Commit**

```bash
git add crates/gitlawb-node/src/api/repos.rs
git commit -m "docs(node): note why info/refs is not gated on subtree visibility"
```

---

## Task 6: Full verification gate

**Files:** none (verification only)

- [ ] **Step 1: Format**

Run: `cargo fmt --all && cargo fmt --all --check`
Expected: clean (no diff).

- [ ] **Step 2: Lint**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 3: Full test suite**

Run: `cargo test -p gitlawb-node`
Expected: all pass, including Phase 1 visibility tests and the new `visibility_pack` and `smart_http` tests.

- [ ] **Step 4: Manual smoke (optional but recommended)**

Set a subtree rule on a local repo via `gl visibility`, clone as a non-reader through the node, and confirm the private file's bytes are absent (`git cat-file -p HEAD:secret/b.txt` fails or the file is missing) while the tree entry / SHA is still listed (`git ls-tree HEAD secret/`).

---

## Out of scope / follow-ups (separate plans)

1. **`git-remote-gitlawb` partial-clone UX.** Make a non-reader's clone produce a clean partial checkout rather than a checkout error on the missing blob: the helper requests partial-clone semantics and treats withheld blobs as deliberately absent. Without this, a stock `git clone` of a repo with a withheld blob succeeds at fetch but errors at checkout. The security guarantee (bytes never sent) holds regardless; this is purely UX.
2. **Filtered-pack caching.** `build_filtered_pack` recomputes per request. If hot, cache by (repo, tip-OIDs, withheld-set) and invalidate on push.
3. **Incremental fetch (`have` lines).** This plan targets the clone case. Confirm and, if needed, harden the filtered serve for fetches that send `have` lines so withheld blobs are never sent incrementally either.
4. **Replication-path enforcement (Phase 2).** Still blocked on the maintainer A/B decision; unrelated to this HTTP-path work.
```

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;
use std::collections::HashSet;
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Handle `GET /:owner/:repo/info/refs?service=git-upload-pack`
/// or `?service=git-receive-pack`
///
/// This is the ref advertisement — the first step of a clone or push.
pub async fn info_refs(repo_path: &Path, service: &str) -> Result<Response> {
    validate_service(service)?;

    let output = Command::new("git")
        .arg(service_to_command(service))
        .arg("--stateless-rpc")
        .arg("--advertise-refs")
        .arg(repo_path)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {service} --advertise-refs failed: {stderr}");
    }

    let content_type = format!("application/x-{service}-advertisement");

    // Prepend the pkt-line service announcement
    let pkt_service = pkt_line(&format!("# service={service}\n"));
    let flush = b"0000";
    let mut body = Vec::new();
    body.extend_from_slice(&pkt_service);
    body.extend_from_slice(flush);
    body.extend_from_slice(&output.stdout);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-cache")
        .header("X-Gitlawb-Node", "v0.1.0")
        .body(Body::from(body))?)
}

/// Handle `POST /:owner/:repo/git-upload-pack`
///
/// Serves pack data for a clone or fetch. This is stateless — the entire
/// negotiation happens in a single request/response.
pub async fn upload_pack(repo_path: &Path, request_body: Bytes) -> Result<Response> {
    let output = run_git_service("git", "git-upload-pack", repo_path, request_body).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-upload-pack-result")
        .header("Cache-Control", "no-cache")
        .body(Body::from(output))?)
}

/// Handle `POST /:owner/:repo/git-receive-pack`
///
/// Accepts a push. The caller MUST verify HTTP Signature auth before
/// calling this function.
pub async fn receive_pack(repo_path: &Path, request_body: Bytes) -> Result<Response> {
    let output = run_git_service("git", "git-receive-pack", repo_path, request_body).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-receive-pack-result")
        .header("Cache-Control", "no-cache")
        .body(Body::from(output))?)
}

/// Sends SIGTERM to a child's whole process group on drop, unless disarmed first.
///
/// A served `git upload-pack`/`receive-pack` forks helpers such as `pack-objects`.
/// If the request future is dropped (client disconnect) or returns early, dropping
/// the tokio `Child` does not signal `git`; it lingers until EPIPE, and its
/// `pack-objects` child can reparent to PID 1 and never be reaped — a zombie that
/// accumulates until `fork()` fails with EAGAIN (#53). Spawning the child in its
/// own process group and signalling that group here tears the whole tree down at
/// the source. SIGTERM (not SIGKILL) lets `git` run its cleanup — notably removing
/// `.git/*.lock` files mid-`receive-pack` — before it exits, so an aborted push
/// can't leave a stale lock that blocks the next one. The guard is disarmed once
/// `wait_with_output()` returns, so a request that completed cleanly never signals.
#[cfg(unix)]
struct KillGroupOnDrop {
    pgid: Option<i32>,
}

#[cfg(unix)]
impl KillGroupOnDrop {
    fn disarm(&mut self) {
        self.pgid = None;
    }
}

#[cfg(unix)]
impl Drop for KillGroupOnDrop {
    fn drop(&mut self) {
        if let Some(pgid) = self.pgid {
            // SAFETY: kill(2) takes only integer arguments and borrows no Rust
            // memory. Signalling a stale group just returns ESRCH, which we ignore.
            unsafe {
                libc::kill(-pgid, libc::SIGTERM);
            }
        }
    }
}

/// Run a stateless-rpc git service and return its stdout.
///
/// `git_bin` is the git executable to spawn; production callers pass `"git"`
/// (resolved via `PATH`). It is injectable purely so the process-group teardown
/// wiring (`process_group(0)` + [`KillGroupOnDrop`]) can be driven end-to-end by
/// a fake `git` in tests without mutating the process-global `PATH`.
async fn run_git_service(
    git_bin: &str,
    service: &str,
    repo_path: &Path,
    input: Bytes,
) -> Result<Vec<u8>> {
    let mut command = Command::new(git_bin);
    command
        .arg(service_to_command(service))
        .arg("--stateless-rpc")
        .arg(repo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Run git in its own process group so the whole tree (git + pack-objects)
    // can be signalled together on disconnect rather than orphaning a grandchild.
    #[cfg(unix)]
    command.process_group(0);

    let mut child = command.spawn()?;

    // Arm the group-kill guard for the lifetime of the request. With
    // process_group(0) the child is its own group leader, so pgid == its pid.
    #[cfg(unix)]
    let mut group_guard = KillGroupOnDrop {
        pgid: child.id().map(|id| id as i32),
    };

    // Write the request body to git's stdin, but don't early-return on a write
    // error: always reap the child first (below), so the guard only ever fires on
    // an actual future-drop (client disconnect), never on a pid we just reaped.
    let write_result: std::io::Result<()> = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(&input).await,
        None => Ok(()),
    };

    let output = child.wait_with_output().await?;

    // Child reaped, so its group is gone: disarm before surfacing any error.
    #[cfg(unix)]
    group_guard.disarm();

    write_result.context("failed to write to git stdin")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{service} failed: {stderr}");
    }

    Ok(output.stdout)
}

fn service_to_command(service: &str) -> &str {
    match service {
        "git-upload-pack" => "upload-pack",
        "git-receive-pack" => "receive-pack",
        _ => service,
    }
}

fn validate_service(service: &str) -> Result<()> {
    match service {
        "git-upload-pack" | "git-receive-pack" => Ok(()),
        other => bail!("unknown git service: {other}"),
    }
}

/// Encode a string as a git pkt-line.
/// Format: 4-byte hex length (including the 4 bytes itself) + data
fn pkt_line(data: &str) -> Vec<u8> {
    let len = data.len() + 4;
    format!("{len:04x}{data}").into_bytes()
}

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
        bail!(
            "git rev-list failed: {}",
            String::from_utf8_lossy(&rev.stderr)
        );
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
    // Feed the object ids on stdin, but always reap the child afterward even if
    // the write fails or stdin is missing, so an error can't drop the Child
    // unwaited and leak a zombie (#53).
    let write_result: std::io::Result<()> = {
        use std::io::Write as _;
        match child.stdin.take() {
            Some(mut stdin) => {
                let mut data = keep.join("\n").into_bytes();
                data.push(b'\n');
                stdin.write_all(&data)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "git pack-objects stdin unavailable",
            )),
        }
    };
    let out = child.wait_with_output()?;
    write_result.context("failed to write object ids to git pack-objects stdin")?;
    if !out.status.success() {
        bail!(
            "git pack-objects failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(out.stdout)
}

/// Serve a clone/fetch with the withheld blobs removed from the response pack.
///
/// The framing is git protocol v0 (`NAK` then the pack), matching the v0 ref
/// advertisement that `info_refs` emits (it runs `git upload-pack
/// --advertise-refs` without `GIT_PROTOCOL=version=2`, so clients negotiate v0).
/// If `info_refs` ever advertises v2, this serve path must learn v2 framing too.
///
/// Because the pack deliberately omits blobs that the sent trees still
/// reference, the pack is not closed under reachability. A stock full clone
/// rejects it at fetch time ("remote did not send all necessary objects"); only
/// a partial clone (the client passes `--filter`, marking a promisor remote)
/// accepts the pack with the private blobs absent. Tree and commit SHAs stay
/// intact either way. The clean partial-clone client UX is a separate follow-up
/// (git-remote-gitlawb); the security guarantee (private bytes never leave the
/// node) holds regardless of client.
///
/// Negotiation is intentionally ignored: rather than honoring the client's
/// `want`/`have` lines, this always sends a self-contained pack of every object
/// across all refs minus the withheld blobs, and replies `NAK`. A fresh clone
/// and an incremental fetch are both correct (the client de-duplicates objects
/// it already has); the cost is that a fetch re-sends the full object set
/// instead of a thin delta. Honoring negotiation for smaller fetch packs is an
/// optimization follow-up, not a correctness requirement.
pub async fn upload_pack_excluding(
    repo_path: &Path,
    request_body: Bytes,
    withheld: &HashSet<String>,
) -> Result<Response> {
    // build_filtered_pack shells out to git (rev-list, pack-objects) with
    // blocking std::process I/O; run it off the async worker so a large repo's
    // pack build does not stall the tokio runtime.
    let pack = {
        let repo_path = repo_path.to_path_buf();
        let withheld = withheld.clone();
        tokio::task::spawn_blocking(move || build_filtered_pack(&repo_path, &withheld))
            .await
            .context("filtered-pack build task panicked")??
    };

    // The client lists its capabilities on the first `want` line. Honor
    // side-band-64k when offered (every modern smart-HTTP client offers it);
    // otherwise stream the raw pack after NAK.
    let sideband = memmem(&request_body, b"side-band-64k");

    let mut body = Vec::new();
    body.extend_from_slice(&pkt_line("NAK\n"));
    if sideband {
        // Band 1 carries pack data, chunked under the pkt-line size limit.
        for chunk in pack.chunks(65515) {
            let mut framed = Vec::with_capacity(chunk.len() + 1);
            framed.push(0x01);
            framed.extend_from_slice(chunk);
            let len = framed.len() + 4;
            body.extend_from_slice(format!("{len:04x}").as_bytes());
            body.extend_from_slice(&framed);
        }
        body.extend_from_slice(b"0000");
    } else {
        body.extend_from_slice(&pack);
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-upload-pack-result")
        .header("Cache-Control", "no-cache")
        .body(Body::from(body))?)
}

/// True if `needle` occurs anywhere in `haystack`. Small substring scan used to
/// detect a client capability token in the upload-pack request body.
fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return needle.is_empty();
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

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
            assert!(Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap()
                .success());
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
            let o = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{p}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        let secret = oid("secret/b.txt");
        let public = oid("public/a.txt");
        g(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );

        let mut withheld = std::collections::HashSet::new();
        withheld.insert(secret.clone());

        let pack = build_filtered_pack(&bare, &withheld).unwrap();
        let ids = pack_object_ids(&pack);
        assert!(ids.contains(&public), "public blob must be in the pack");
        assert!(
            !ids.contains(&secret),
            "secret blob must NOT be in the pack"
        );
    }

    #[tokio::test]
    async fn client_clone_lacks_withheld_blob_bytes() {
        use axum::body::to_bytes;
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let g = |args: &[&str], dir: &std::path::Path| {
            assert!(Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap()
                .success());
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
            let o = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{p}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        let secret_oid = oid("secret/b.txt");
        let public_oid = oid("public/a.txt");
        g(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );

        let mut withheld = std::collections::HashSet::new();
        withheld.insert(secret_oid.clone());

        // A realistic v0 request advertises side-band-64k, so the serve frames
        // the pack in band 1 (the path real clients exercise).
        let req = Bytes::from_static(
            b"0098want 0000000000000000000000000000000000000000 \
              side-band-64k ofs-delta agent=git/2\n00000009done\n",
        );
        let resp = upload_pack_excluding(&bare, req, &withheld).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let ids = pack_object_ids(&extract_pack(&body));
        assert!(
            ids.contains(&public_oid),
            "public blob must be present in served pack"
        );
        assert!(
            !ids.contains(&secret_oid),
            "withheld blob must be absent from served pack"
        );
    }

    /// Strip the v0 upload-pack framing (NAK line + sideband-64k bands),
    /// returning the raw pack. Mirrors how a client de-frames the band-1 stream.
    fn extract_pack(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= body.len() {
            let len =
                usize::from_str_radix(std::str::from_utf8(&body[i..i + 4]).unwrap_or("0000"), 16)
                    .unwrap_or(0);
            if len == 0 {
                i += 4;
                continue;
            }
            let chunk = &body[i + 4..i + len];
            // band 1 = pack data; skip the NAK line and any other bands.
            if chunk.first() == Some(&0x01) {
                out.extend_from_slice(&chunk[1..]);
            }
            i += len;
        }
        out
    }

    // Shared harness for the real-git server tests: a minimal smart-HTTP server
    // backed by the real info_refs + upload_pack_excluding.

    #[derive(Clone)]
    struct FilterState {
        repo: std::path::PathBuf,
        withheld: HashSet<String>,
    }

    async fn refs_handler(
        axum::extract::State(st): axum::extract::State<std::sync::Arc<FilterState>>,
        axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
    ) -> Response {
        let service = q.get("service").cloned().unwrap_or_default();
        info_refs(&st.repo, &service).await.unwrap()
    }

    async fn pack_handler(
        axum::extract::State(st): axum::extract::State<std::sync::Arc<FilterState>>,
        body: Bytes,
    ) -> Response {
        upload_pack_excluding(&st.repo, body, &st.withheld)
            .await
            .unwrap()
    }

    /// Spawn the server for `bare`, withholding `withheld`. Returns the clone URL
    /// and the server task (abort it when done).
    async fn spawn_filter_server(
        bare: std::path::PathBuf,
        withheld: HashSet<String>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::routing::{get, post};
        let state = std::sync::Arc::new(FilterState {
            repo: bare,
            withheld,
        });
        let app = axum::Router::new()
            .route("/repo.git/info/refs", get(refs_handler))
            .route("/repo.git/git-upload-pack", post(pack_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://127.0.0.1:{port}/repo.git"), handle)
    }

    fn run_git(args: &[&str], dir: &std::path::Path) {
        assert!(Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
    }

    /// Build a work repo (public/a.txt, secret/b.txt) and a bare clone of it.
    /// Returns (work, bare, secret_blob_oid, public_blob_oid).
    fn fixture_with_secret(
        td: &TempDir,
    ) -> (std::path::PathBuf, std::path::PathBuf, String, String) {
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"pub\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"SECRET\n").unwrap();
        run_git(&["init", "-q"], &work);
        run_git(&["config", "user.email", "t@t"], &work);
        run_git(&["config", "user.name", "t"], &work);
        run_git(&["add", "."], &work);
        run_git(&["commit", "-qm", "init"], &work);
        let oid = |p: &str| {
            let o = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{p}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        let secret_oid = oid("secret/b.txt");
        let public_oid = oid("public/a.txt");
        run_git(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );
        (work, bare, secret_oid, public_oid)
    }

    /// Enumerate exactly the objects a repo physically has (no promisor lazy
    /// fetch), so tests assert on what bytes actually crossed the wire.
    fn local_object_ids(repo: &std::path::Path) -> String {
        let out = Command::new("git")
            .args(["cat-file", "--batch-all-objects", "--batch-check"])
            .current_dir(repo)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// End-to-end: a real `git` client clones through `info_refs` +
    /// `upload_pack_excluding` and ends up without the withheld blob's bytes
    /// while still seeing its tree entry (SHA). Uses a partial clone
    /// (`--filter`) because a pack that omits a referenced blob is only
    /// accepted by a promisor-aware client; a stock full clone is refused at
    /// fetch time by the connectivity check.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_git_partial_clone_omits_withheld_blob() {
        let td = TempDir::new().unwrap();
        let (_work, bare, secret_oid, public_oid) = fixture_with_secret(&td);

        let (url, server) = spawn_filter_server(bare, HashSet::from([secret_oid.clone()])).await;

        let dest = td.path().join("clone");
        let dest_s = dest.to_str().unwrap().to_string();
        let out = tokio::task::spawn_blocking(move || {
            Command::new("git")
                .args([
                    "-c",
                    "protocol.version=2",
                    "clone",
                    "--filter=blob:none",
                    "--no-checkout",
                    "-q",
                    &url,
                    &dest_s,
                ])
                .output()
                .unwrap()
        })
        .await
        .unwrap();

        assert!(
            out.status.success(),
            "clone failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // The public blob is present in the clone, the withheld blob is not.
        let local = local_object_ids(&dest);
        assert!(
            local.contains(&public_oid),
            "public blob should be present in the clone"
        );
        assert!(
            !local.contains(&secret_oid),
            "withheld blob bytes must be absent from the clone"
        );

        // The tree entry (and SHA) for the private file is still visible.
        let tree = Command::new("git")
            .args(["ls-tree", "-r", "HEAD"])
            .current_dir(&dest)
            .output()
            .unwrap();
        let tree = String::from_utf8_lossy(&tree.stdout);
        assert!(
            tree.contains(&secret_oid) && tree.contains("secret/b.txt"),
            "the private path and its blob SHA must remain visible: {tree}"
        );

        server.abort();
    }

    /// End-to-end: an incremental `git fetch` after a partial clone still works
    /// and still withholds the private blob. The serve path ignores the client's
    /// have/want negotiation and always sends a self-contained pack of all refs
    /// minus the withheld blobs (it replies NAK, so the client treats it as "no
    /// common commits" and accepts the full set). This is correct, just not
    /// bandwidth-optimal; thin-pack/negotiation is an optimization follow-up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_git_fetch_after_partial_clone_still_withholds() {
        let td = TempDir::new().unwrap();
        let (work, bare, secret_oid, _public_oid) = fixture_with_secret(&td);
        let branch = {
            let o = Command::new("git")
                .args(["symbolic-ref", "--short", "HEAD"])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };

        let (url, server) =
            spawn_filter_server(bare.clone(), HashSet::from([secret_oid.clone()])).await;

        // Partial-clone the initial state.
        let dest = td.path().join("clone");
        let dest_s = dest.to_str().unwrap().to_string();
        let url_c = url.clone();
        let out = tokio::task::spawn_blocking(move || {
            Command::new("git")
                .args([
                    "-c",
                    "protocol.version=2",
                    "clone",
                    "--filter=blob:none",
                    "--no-checkout",
                    "-q",
                    &url_c,
                    &dest_s,
                ])
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            out.status.success(),
            "clone failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Add a new public commit on the server side.
        std::fs::write(work.join("public/c.txt"), b"v2\n").unwrap();
        run_git(&["add", "."], &work);
        run_git(&["commit", "-qm", "c2"], &work);
        let new_oid = {
            let o = Command::new("git")
                .args(["rev-parse", "HEAD:public/c.txt"])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        run_git(&["push", "-q", bare.to_str().unwrap(), &branch], &work);

        // Incremental fetch: the client has c1 and asks for the update.
        let dest_f = dest.clone();
        let out = tokio::task::spawn_blocking(move || {
            Command::new("git")
                .args(["-c", "protocol.version=2", "fetch", "-q", "origin"])
                .current_dir(&dest_f)
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            out.status.success(),
            "fetch failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // The new commit's blob arrived; the withheld blob is still absent.
        let local = local_object_ids(&dest);
        assert!(
            local.contains(&new_oid),
            "the new commit's blob must be fetched"
        );
        assert!(
            !local.contains(&secret_oid),
            "withheld blob must remain absent after fetch"
        );

        server.abort();
    }

    // ── #53 regression: served-git process-group teardown ──────────────────
    //
    // run_git_service runs git in its own process group and SIGTERMs that group
    // when the request future is dropped (client disconnect) or returns early, so
    // git AND its pack-objects child die together instead of orphaning a zombie.
    // These exercise the KillGroupOnDrop guard that wires that up.

    #[cfg(unix)]
    fn alive(pid: i32) -> bool {
        // kill(pid, 0) probes existence: returns 0 while the pid exists, -1 once
        // it's gone (ESRCH). Same-uid here, so EPERM never applies.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_group_guard_terminates_child_on_drop() {
        let mut child = tokio::process::Command::new("sleep")
            .arg("300")
            .process_group(0)
            .spawn()
            .unwrap();
        let pgid = child.id().map(|id| id as i32);

        {
            let _guard = KillGroupOnDrop { pgid };
        } // guard drops here -> SIGTERM to the group

        use std::os::unix::process::ExitStatusExt;
        let status = child.wait().await.unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "child must be terminated by SIGTERM via its process group"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_group_guard_reaps_grandchild_on_drop() {
        // The #53 scenario: git forks pack-objects. A group kill must reach the
        // grandchild, not just the direct child. sh (the group leader) backgrounds
        // a sleep (standing in for pack-objects) and prints its pid.
        use tokio::io::AsyncReadExt;
        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 300 & echo \"$!\"; wait")
            .stdout(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let pgid = child.id().map(|id| id as i32);

        // Read the backgrounded grandchild's pid from the first stdout line.
        let mut stdout = child.stdout.take().unwrap();
        let mut buf = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            let n = stdout.read(&mut byte).await.unwrap();
            if n == 0 || byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
        }
        let grandchild: i32 = String::from_utf8(buf).unwrap().trim().parse().unwrap();
        assert!(alive(grandchild), "grandchild should be running");

        {
            let _guard = KillGroupOnDrop { pgid };
        } // group SIGTERM reaches sh AND the sleep grandchild

        let _ = child.wait().await; // reap sh

        // The grandchild reparents to init and is reaped; poll until it's gone.
        let mut gone = false;
        for _ in 0..200 {
            if !alive(grandchild) {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            gone,
            "grandchild must be terminated by the group signal (#53)"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_group_guard_disarmed_does_not_kill() {
        // A request that completed cleanly disarms the guard; dropping it must not
        // signal anything.
        let mut child = tokio::process::Command::new("sleep")
            .arg("300")
            .process_group(0)
            .spawn()
            .unwrap();

        {
            let mut guard = KillGroupOnDrop {
                pgid: child.id().map(|id| id as i32),
            };
            guard.disarm();
        } // disarmed -> no kill

        assert!(
            child.try_wait().unwrap().is_none(),
            "disarmed guard must not kill the child"
        );

        // Clean up the still-running child.
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    // ── #62 PR1: end-to-end teardown wiring through run_git_service ─────────
    //
    // The kill_group_guard_* tests above build a KillGroupOnDrop by hand and
    // never call run_git_service, so deleting `process_group(0)` (spawn site) or
    // the guard-arming, or the post-reap disarm, would leave them green. These
    // drive the REAL run_git_service via an injected fake `git` (the `git_bin`
    // seam) and assert the production spawn path actually wires the teardown up.
    // Faithful to the real invocation: run_git_service spawns
    // `<git_bin> <cmd> --stateless-rpc <repo_path>` in its own process group.

    /// SIGKILLs the given pids on drop (ignoring all kill errors, e.g. ESRCH for
    /// an already-dead pid) so a panicking assertion can't leak the fake `git` or
    /// its grandchild onto the test runner.
    #[cfg(unix)]
    struct ReapOnPanic(Vec<i32>);

    #[cfg(unix)]
    impl Drop for ReapOnPanic {
        fn drop(&mut self) {
            for &pid in &self.0 {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }

    /// Write an executable fake `git` (named `git`) into `dir`; return its path.
    #[cfg(unix)]
    fn write_fake_git(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("git");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Read a two-line `leader\ngrandchild` pidfile once both lines are present.
    #[cfg(unix)]
    fn read_two_pids(pidfile: &std::path::Path) -> Option<(i32, i32)> {
        let s = std::fs::read_to_string(pidfile).ok()?;
        let mut lines = s.lines();
        let leader: i32 = lines.next()?.trim().parse().ok()?;
        let grandchild: i32 = lines.next()?.trim().parse().ok()?;
        Some((leader, grandchild))
    }

    // Dropping the request future mid-flight (client disconnect) must SIGTERM the
    // whole group so git AND its pack-objects grandchild die together. Goes RED
    // if `process_group(0)` or the guard-arming is removed: without its own
    // group, kill(-pgid) hits no group and the grandchild survives.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_tears_down_group_when_future_dropped() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("pids");
        // Fork a grandchild (stands in for pack-objects), record leader+grandchild
        // pids, then hang so run_git_service parks in wait_with_output.
        let body = format!(
            "#!/bin/sh\nsleep 300 &\nprintf '%s\\n%s\\n' \"$$\" \"$!\" > \"{}\"\nwait\n",
            pidfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        let mut fut = Box::pin(run_git_service(
            git_bin.to_str().unwrap(),
            "git-upload-pack",
            tmp.path(),
            Bytes::new(),
        ));

        // Advance the future until the fake has spawned its grandchild.
        let mut pids = None;
        for _ in 0..500 {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            if let Some(p) = read_two_pids(&pidfile) {
                pids = Some(p);
                break;
            }
        }
        // Dropping the future (below or on the None arm) makes tokio reap the
        // fake leader itself, so only the grandchild needs panic-cleanup —
        // carrying the already-reaped leader pid risks SIGKILLing a recycled pid
        // under parallel test load.
        let (_leader, grandchild) = match pids {
            Some(p) => p,
            // Drop the still-armed future first so its guard reaps the fake
            // group, then fail — otherwise a spawn hiccup orphans the processes.
            None => {
                drop(fut);
                panic!("fake git should spawn a grandchild and write its pids");
            }
        };
        let _cleanup = ReapOnPanic(vec![grandchild]);
        assert!(
            alive(grandchild),
            "grandchild should be running before the drop"
        );

        // Client disconnect: drop the request future. The armed KillGroupOnDrop
        // must SIGTERM the whole group.
        drop(fut);

        let mut gone = false;
        for _ in 0..500 {
            if !alive(grandchild) {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            gone,
            "grandchild must be torn down via the process group on future-drop \
             (proves run_git_service sets process_group(0) and arms the guard)"
        );
    }

    // A request that runs to completion must DISARM the guard after reaping, so
    // no stray group SIGTERM fires. The fake exits non-zero (surfacing as Err)
    // but leaves a grandchild alive; the grandchild must survive. Goes RED if the
    // post-reap disarm is removed: the guard would then fire on return and, since
    // the grandchild still holds the group open, sweep it.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_disarms_on_completion_leaving_group_alive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("pids");
        // The grandchild is long-lived with stdio redirected to /dev/null:
        // /dev/null so it doesn't inherit (and hold open) run_git_service's stdout
        // pipe (which would block wait_with_output until it exits); long-lived so
        // the "still alive" assertion below can't race the sleep exiting on its own
        // under a starved scheduler. ReapOnPanic cleans it up.
        let body = format!(
            "#!/bin/sh\nsleep 300 >/dev/null 2>&1 &\nprintf '%s\\n%s\\n' \"$$\" \"$!\" > \"{}\"\nexit 1\n",
            pidfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        let result = run_git_service(
            git_bin.to_str().unwrap(),
            "git-upload-pack",
            tmp.path(),
            Bytes::new(),
        )
        .await;

        // wait_with_output already reaped the fake leader, so only the grandchild
        // needs panic-cleanup — SIGKILLing the reaped leader pid could hit a
        // recycled pid under parallel test load.
        let (_leader, grandchild) =
            read_two_pids(&pidfile).expect("fake git should have written its pids");
        let _cleanup = ReapOnPanic(vec![grandchild]);

        assert!(result.is_err(), "non-zero git exit must surface as Err");
        // A mutant that left the guard armed fires SIGTERM on return; poll a short
        // window so a killed grandchild is reliably observed dead — a single
        // alive() check can race the SIGTERM+reap and miss it.
        for _ in 0..30 {
            assert!(
                alive(grandchild),
                "grandchild must survive: run_git_service must disarm the guard after \
                 reaping, not fire a group SIGTERM on the completion path"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    // The SUCCESS path (exit 0, Ok) must disarm too — the disarm test above only
    // exercises the exit-1/Err branch. Goes RED if disarm is gated on failure
    // (e.g. moved inside the `!status.success()` branch): the guard would then
    // fire after a clean completion and sweep the still-live grandchild.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_disarms_on_success_leaving_group_alive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("pids");
        // Long-lived, stdio to /dev/null (same reasons as the exit-1 test).
        let body = format!(
            "#!/bin/sh\nsleep 300 >/dev/null 2>&1 &\nprintf '%s\\n%s\\n' \"$$\" \"$!\" > \"{}\"\nexit 0\n",
            pidfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        let result = run_git_service(
            git_bin.to_str().unwrap(),
            "git-upload-pack",
            tmp.path(),
            Bytes::new(),
        )
        .await;

        let (_leader, grandchild) =
            read_two_pids(&pidfile).expect("fake git should have written its pids");
        let _cleanup = ReapOnPanic(vec![grandchild]);

        assert!(result.is_ok(), "zero-exit git must surface as Ok");
        // Poll a short window (see the exit-1 test): a mutant that disarms only on
        // failure fires the guard on this success path, and a single alive() check
        // can race the SIGTERM+reap.
        for _ in 0..30 {
            assert!(
                alive(grandchild),
                "grandchild must survive: run_git_service must disarm on the success \
                 path too, not fire a group SIGTERM after a clean completion"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}

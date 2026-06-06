use anyhow::{bail, Result};
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
    let output = run_git_service("git-upload-pack", repo_path, request_body).await?;

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
    let output = run_git_service("git-receive-pack", repo_path, request_body).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-receive-pack-result")
        .header("Cache-Control", "no-cache")
        .body(Body::from(output))?)
}

async fn run_git_service(service: &str, repo_path: &Path, input: Bytes) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .arg(service_to_command(service))
        .arg("--stateless-rpc")
        .arg(repo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Write request body to git's stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&input).await?;
    }

    let output = child.wait_with_output().await?;

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
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(keep.join("\n").as_bytes())?;
        stdin.write_all(b"\n")?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "git pack-objects failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(out.stdout)
}

/// Serve a clone/fetch with the withheld blobs removed from the response pack.
/// Framing: the body wraps `build_filtered_pack` output in the upload-pack
/// `packfile` section with sideband-64k band 1, terminated by flush.
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
}

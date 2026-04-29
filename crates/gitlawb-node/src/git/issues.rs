//! Issue storage as git refs.
//!
//! Issues are stored as signed JSON blobs in git refs:
//!   refs/gitlawb/issues/<uuid>
//!
//! This makes them content-addressed and travel with the repo.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Write a JSON blob for an issue and set the ref.
pub fn create_issue(repo_path: &Path, issue_id: &str, json: &str) -> Result<()> {
    // Write the JSON blob as a git object
    let hash_output = Command::new("git")
        .args(["hash-object", "--stdin", "-w"])
        .current_dir(repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn git hash-object")?;

    use std::io::Write;
    let mut child = hash_output;
    if let Some(stdin) = child.stdin.take() {
        let mut stdin = stdin;
        stdin
            .write_all(json.as_bytes())
            .context("failed to write to git hash-object stdin")?;
    }
    let output = child.wait_with_output().context("git hash-object failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git hash-object failed: {stderr}");
    }

    let hash =
        String::from_utf8(output.stdout).context("git hash-object output is not valid UTF-8")?;
    let hash = hash.trim();

    // Update the ref
    let ref_name = format!("refs/gitlawb/issues/{issue_id}");
    let update_output = Command::new("git")
        .args(["update-ref", &ref_name, hash])
        .current_dir(repo_path)
        .output()
        .context("failed to run git update-ref")?;

    if !update_output.status.success() {
        let stderr = String::from_utf8_lossy(&update_output.stderr);
        anyhow::bail!("git update-ref failed: {stderr}");
    }

    Ok(())
}

/// List all issue refs and return their JSON content.
pub fn list_issues(repo_path: &Path) -> Result<Vec<String>> {
    // List all refs under refs/gitlawb/issues/
    let list_output = Command::new("git")
        .args([
            "for-each-ref",
            "--format=%(refname)",
            "refs/gitlawb/issues/",
        ])
        .current_dir(repo_path)
        .output()
        .context("failed to run git for-each-ref")?;

    if !list_output.status.success() {
        // No issues yet
        return Ok(vec![]);
    }

    let refs_str = String::from_utf8_lossy(&list_output.stdout);
    let mut issues = Vec::new();

    for ref_name in refs_str.lines() {
        let ref_name = ref_name.trim();
        if ref_name.is_empty() {
            continue;
        }

        // Read the blob content
        let cat_output = Command::new("git")
            .args(["cat-file", "blob", ref_name])
            .current_dir(repo_path)
            .output()
            .context("failed to run git cat-file")?;

        if cat_output.status.success() {
            let content = String::from_utf8_lossy(&cat_output.stdout).to_string();
            issues.push(content);
        }
    }

    Ok(issues)
}

/// Resolve an issue ID or 8-char prefix to the full UUID stored in git refs.
/// Returns Ok(Some(full_id)) on unique match, Ok(None) if not found,
/// Err if the prefix is ambiguous (matches more than one issue).
pub fn resolve_issue_id(repo_path: &Path, id_or_prefix: &str) -> Result<Option<String>> {
    // Try exact match first — fast path for callers passing the full UUID.
    let exact_ref = format!("refs/gitlawb/issues/{id_or_prefix}");
    let check = Command::new("git")
        .args(["cat-file", "-e", &exact_ref])
        .current_dir(repo_path)
        .output()
        .context("failed to run git cat-file -e")?;
    if check.status.success() {
        return Ok(Some(id_or_prefix.to_string()));
    }

    // Prefix search: list all refs that start with the given string.
    let prefix_glob = format!("refs/gitlawb/issues/{id_or_prefix}*");
    let list = Command::new("git")
        .args(["for-each-ref", "--format=%(refname)", &prefix_glob])
        .current_dir(repo_path)
        .output()
        .context("failed to run git for-each-ref")?;

    if !list.status.success() {
        return Ok(None);
    }

    let output = String::from_utf8_lossy(&list.stdout);
    let matches: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();

    match matches.len() {
        0 => Ok(None),
        1 => {
            // Strip the "refs/gitlawb/issues/" prefix to get the bare ID.
            let full_id = matches[0]
                .trim()
                .strip_prefix("refs/gitlawb/issues/")
                .unwrap_or(matches[0].trim())
                .to_string();
            Ok(Some(full_id))
        }
        _ => anyhow::bail!(
            "ambiguous issue prefix '{}': matches {} issues",
            id_or_prefix,
            matches.len()
        ),
    }
}

/// Close an issue by updating its status to "closed" in the git ref.
/// Returns the updated JSON, or None if the issue doesn't exist.
pub fn close_issue(repo_path: &Path, issue_id: &str) -> Result<Option<String>> {
    let full_id = match resolve_issue_id(repo_path, issue_id)? {
        Some(id) => id,
        None => return Ok(None),
    };

    let raw = get_issue(repo_path, &full_id)?
        .expect("ref existed in resolve but not in get — should be impossible");

    let mut issue: serde_json::Value =
        serde_json::from_str(&raw).context("invalid issue JSON in git ref")?;
    issue["status"] = serde_json::Value::String("closed".to_string());

    let updated = serde_json::to_string(&issue).context("failed to serialize updated issue")?;
    create_issue(repo_path, &full_id, &updated)?;
    Ok(Some(updated))
}

/// Get a single issue by ID or 8-char prefix.
pub fn get_issue(repo_path: &Path, issue_id: &str) -> Result<Option<String>> {
    let full_id = match resolve_issue_id(repo_path, issue_id)? {
        Some(id) => id,
        None => return Ok(None),
    };

    let ref_name = format!("refs/gitlawb/issues/{full_id}");
    let cat_output = Command::new("git")
        .args(["cat-file", "blob", &ref_name])
        .current_dir(repo_path)
        .output()
        .context("failed to run git cat-file")?;

    if !cat_output.status.success() {
        return Ok(None);
    }

    let content = String::from_utf8_lossy(&cat_output.stdout).to_string();
    Ok(Some(content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn init_bare_repo(dir: &TempDir) {
        Command::new("git")
            .args(["init", "--bare"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        // git hash-object -w needs a non-bare repo; use a working repo instead
    }

    fn init_repo(dir: &TempDir) {
        Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir.path())
            .output()
            .unwrap();
    }

    #[test]
    fn test_resolve_exact_id_found() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "abc12345-0000-0000-0000-000000000000";
        create_issue(
            dir.path(),
            full_id,
            r#"{"id":"abc12345-0000-0000-0000-000000000000","status":"open"}"#,
        )
        .unwrap();
        let resolved = resolve_issue_id(dir.path(), full_id).unwrap();
        assert_eq!(resolved, Some(full_id.to_string()));
    }

    #[test]
    fn test_resolve_prefix_matches_unique() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "abc12345-0000-0000-0000-000000000000";
        create_issue(
            dir.path(),
            full_id,
            r#"{"id":"abc12345-0000-0000-0000-000000000000","status":"open"}"#,
        )
        .unwrap();
        let resolved = resolve_issue_id(dir.path(), "abc12345").unwrap();
        assert_eq!(resolved, Some(full_id.to_string()));
    }

    #[test]
    fn test_resolve_prefix_not_found() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let resolved = resolve_issue_id(dir.path(), "deadbeef").unwrap();
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_resolve_ambiguous_prefix_errors() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        create_issue(
            dir.path(),
            "abc12345-aaaa-0000-0000-000000000000",
            r#"{"status":"open"}"#,
        )
        .unwrap();
        create_issue(
            dir.path(),
            "abc12345-bbbb-0000-0000-000000000000",
            r#"{"status":"open"}"#,
        )
        .unwrap();
        let result = resolve_issue_id(dir.path(), "abc12345");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ambiguous"));
    }

    #[test]
    fn test_close_issue_via_prefix() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "def99999-0000-0000-0000-000000000000";
        create_issue(
            dir.path(),
            full_id,
            r#"{"id":"def99999-0000-0000-0000-000000000000","status":"open"}"#,
        )
        .unwrap();

        let updated = close_issue(dir.path(), "def99999").unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&updated).unwrap();
        assert_eq!(v["status"], "closed");
    }
}

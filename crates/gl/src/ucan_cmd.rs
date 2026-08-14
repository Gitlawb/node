//! `gl ucan` — delegate, show, and verify UCAN capability tokens.

use anyhow::{Context, Result};
use clap::Args;
use serde_json::json;
use std::path::PathBuf;

use gitlawb_core::did::Did;
use gitlawb_core::ucan::{Capability, Ucan};

use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct UcanArgs {
    #[command(subcommand)]
    pub cmd: UcanCmd,
}

#[derive(clap::Subcommand)]
pub enum UcanCmd {
    /// Delegate capabilities to another agent
    Delegate {
        /// Audience DID — who receives this capability
        #[arg(long)]
        to: String,
        /// Resource URI, e.g. "gitlawb://repos/owner/repo"
        #[arg(long)]
        cap: String,
        /// Action, e.g. "git/push", "pr/open", "repo/admin"
        #[arg(long)]
        can: String,
        /// Expiry in hours (default: no expiry)
        #[arg(long)]
        expiry: Option<u64>,
        /// Save the UCAN to a file instead of printing
        #[arg(long)]
        out: Option<PathBuf>,
        /// Identity directory
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show the saved bootstrap UCAN token
    Show {
        /// Identity directory
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Verify a UCAN token (from stdin, file, or argument)
    Verify {
        /// UCAN JSON token (or path to file containing it)
        token: String,
    },
    /// Store a delegation received from a repo owner, so `git push` can present it
    Import {
        /// UCAN JSON token (or path to a file containing it)
        token: String,
        /// Identity directory
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

/// Where a delegation for `owner_did`/`repo` is stored.
///
/// Keyed on the bare base58 key rather than the full DID: `did:key:` contains a
/// colon, which is not a legal filename character on Windows, and the same
/// identity appears in both forms across this codebase — storing under one form
/// and looking up by the other would silently miss.
///
/// `git-remote-gitlawb` derives the same path from a `gitlawb://` URL alone; the
/// two must agree, and the helper carries a pointer back to this function.
pub fn delegation_path(dir: &std::path::Path, owner_did: &str, repo: &str) -> PathBuf {
    let bare = owner_did.strip_prefix("did:key:").unwrap_or(owner_did);
    dir.join("delegations").join(format!("{bare}__{repo}.ucan"))
}

/// Pull the repo this capability names out of `gitlawb://repos/<owner>/<repo>`.
fn repo_from_resource(with: &str) -> Option<(String, String)> {
    let rest = with.strip_prefix("gitlawb://repos/")?;
    let (owner, name) = rest.rsplit_once('/')?;
    if owner.is_empty() || name.is_empty() {
        return None;
    }
    Some((owner.to_string(), name.to_string()))
}

pub async fn run(args: UcanArgs) -> Result<()> {
    match args.cmd {
        UcanCmd::Delegate {
            to,
            cap,
            can,
            expiry,
            out,
            dir,
            json: json_out,
        } => cmd_delegate(to, cap, can, expiry, out, dir, json_out).await,
        UcanCmd::Show { dir } => cmd_show(dir).await,
        UcanCmd::Verify { token } => cmd_verify(token).await,
        UcanCmd::Import { token, dir } => cmd_import(token, dir).await,
    }
}

/// Store a delegation where `git-remote-gitlawb` will look for it on push.
///
/// The token is decoded here rather than at push time so a malformed delegation
/// fails where the error is actionable, instead of surfacing as an unexplained
/// 403 in the middle of a `git push`.
async fn cmd_import(token: String, dir: Option<PathBuf>) -> Result<()> {
    let raw = match std::fs::read_to_string(&token) {
        Ok(contents) => contents.trim().to_string(),
        Err(_) => token.clone(),
    };

    let ucan = Ucan::decode(&raw).context(
        "not a valid UCAN token — pass the JSON emitted by `gl ucan delegate`, or a path to it",
    )?;

    let push_caps: Vec<(String, String)> = ucan
        .payload
        .att
        .iter()
        .filter_map(|cap| repo_from_resource(&cap.with))
        .collect();

    if push_caps.is_empty() {
        anyhow::bail!(
            "this delegation names no repository — expected a capability on \
             gitlawb://repos/<owner>/<repo>, found: {}",
            ucan.payload
                .att
                .iter()
                .map(|c| c.with.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let base = crate::identity::gitlawb_dir(dir)?;
    std::fs::create_dir_all(base.join("delegations"))
        .with_context(|| format!("could not create {}", base.join("delegations").display()))?;

    for (owner, repo) in &push_caps {
        let path = delegation_path(&base, owner, repo);
        std::fs::write(&path, &raw)
            .with_context(|| format!("could not write {}", path.display()))?;
        println!("Stored delegation for {owner}/{repo} at {}", path.display());
    }

    Ok(())
}

async fn cmd_delegate(
    to: String,
    cap: String,
    can: String,
    expiry: Option<u64>,
    out: Option<PathBuf>,
    dir: Option<PathBuf>,
    json_out: bool,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let audience: Did = to
        .parse()
        .map_err(|e: gitlawb_core::Error| anyhow::anyhow!("{e}"))?;

    let exp = expiry.map(|h| chrono::Utc::now() + chrono::Duration::hours(h as i64));
    let ucan = Ucan::issue(&keypair, audience, vec![Capability::new(&cap, &can)], exp)?;
    let encoded = ucan.encode()?;

    if let Some(path) = out {
        std::fs::write(&path, &encoded)?;
        println!("UCAN saved to {}", path.display());
        return Ok(());
    }

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "issuer": ucan.payload.iss.to_string(),
                "audience": ucan.payload.aud.to_string(),
                "capability": { "with": cap, "can": can },
                "expires": ucan.payload.exp,
                "token": encoded,
            }))?
        );
    } else {
        println!("Issuer:   {}", ucan.payload.iss);
        println!("Audience: {}", ucan.payload.aud);
        println!("Cap:      {} → {}", cap, can);
        if let Some(exp) = ucan.payload.exp {
            println!(
                "Expires:  {}",
                chrono::DateTime::from_timestamp(exp, 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| exp.to_string())
            );
        } else {
            println!("Expires:  never");
        }
        println!();
        println!("{encoded}");
    }
    Ok(())
}

async fn cmd_show(dir: Option<PathBuf>) -> Result<()> {
    let home = dir
        .or_else(|| dirs::home_dir().map(|h| h.join(".gitlawb")))
        .context("cannot find identity directory")?;
    let ucan_path = home.join("ucan.json");

    if !ucan_path.exists() {
        println!("No UCAN saved. Run `gl register` first.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&ucan_path)?;
    let ucan = Ucan::decode(&content)?;

    println!("Issuer:   {}", ucan.payload.iss);
    println!("Audience: {}", ucan.payload.aud);
    println!("Version:  {}", ucan.payload.ucan);
    if ucan.payload.att.is_empty() {
        println!("Caps:     (none)");
    } else {
        for cap in &ucan.payload.att {
            println!("Cap:      {} → {}", cap.with, cap.can);
        }
    }
    if let Some(exp) = ucan.payload.exp {
        let expired = ucan.is_expired();
        println!(
            "Expires:  {} {}",
            chrono::DateTime::from_timestamp(exp, 0)
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| exp.to_string()),
            if expired { "(EXPIRED)" } else { "" }
        );
    } else {
        println!("Expires:  never");
    }
    println!("Sig OK:   {}", ucan.verify_signature().is_ok());
    Ok(())
}

async fn cmd_verify(token: String) -> Result<()> {
    // Try as file first, then as raw JSON
    let content = if std::path::Path::new(&token).exists() {
        std::fs::read_to_string(&token)?
    } else {
        token
    };

    let ucan = Ucan::decode(&content).context("failed to parse UCAN token")?;

    match ucan.verify_signature() {
        Ok(()) => println!("Signature: valid"),
        Err(e) => println!("Signature: INVALID — {e}"),
    }

    if ucan.is_expired() {
        println!("Expired:   yes");
    } else {
        println!("Expired:   no");
    }

    println!("Issuer:    {}", ucan.payload.iss);
    println!("Audience:  {}", ucan.payload.aud);
    for cap in &ucan.payload.att {
        println!("Cap:       {} → {}", cap.with, cap.can);
    }

    if ucan.verify_signature().is_err() || ucan.is_expired() {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitlawb_core::identity::Keypair;
    use tempfile::TempDir;

    fn setup_identity(dir: &TempDir) -> Keypair {
        let kp = Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
        kp
    }

    #[tokio::test]
    async fn test_delegate_prints_ucan() {
        let dir = TempDir::new().unwrap();
        let _kp = setup_identity(&dir);
        let audience = Keypair::generate();

        cmd_delegate(
            audience.did().to_string(),
            "gitlawb://repos/test/repo".into(),
            "git/push".into(),
            None,
            None,
            Some(dir.path().to_path_buf()),
            false,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_delegate_with_expiry() {
        let dir = TempDir::new().unwrap();
        let _kp = setup_identity(&dir);
        let audience = Keypair::generate();

        cmd_delegate(
            audience.did().to_string(),
            "gitlawb://repos/test/repo".into(),
            "pr/open".into(),
            Some(24),
            None,
            Some(dir.path().to_path_buf()),
            false,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_delegate_json_output() {
        let dir = TempDir::new().unwrap();
        let _kp = setup_identity(&dir);
        let audience = Keypair::generate();

        cmd_delegate(
            audience.did().to_string(),
            "gitlawb://repos/org/project".into(),
            "repo/admin".into(),
            Some(48),
            None,
            Some(dir.path().to_path_buf()),
            true,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_delegate_to_file() {
        let dir = TempDir::new().unwrap();
        let _kp = setup_identity(&dir);
        let audience = Keypair::generate();
        let out = dir.path().join("delegated.json");

        cmd_delegate(
            audience.did().to_string(),
            "gitlawb://repos/test/repo".into(),
            "git/push".into(),
            None,
            Some(out.clone()),
            Some(dir.path().to_path_buf()),
            false,
        )
        .await
        .unwrap();

        assert!(out.exists());
        let content = std::fs::read_to_string(&out).unwrap();
        let ucan = Ucan::decode(&content).unwrap();
        ucan.verify_signature().unwrap();
        assert!(ucan.can("gitlawb://repos/test/repo", "git/push"));
    }

    #[tokio::test]
    async fn test_show_no_ucan() {
        let dir = TempDir::new().unwrap();
        cmd_show(Some(dir.path().to_path_buf())).await.unwrap();
    }

    #[tokio::test]
    async fn test_show_existing_ucan() {
        let dir = TempDir::new().unwrap();
        let kp = setup_identity(&dir);
        let audience = Keypair::generate();
        let ucan = Ucan::bootstrap(&kp, audience.did()).unwrap();
        std::fs::write(dir.path().join("ucan.json"), ucan.encode().unwrap()).unwrap();

        cmd_show(Some(dir.path().to_path_buf())).await.unwrap();
    }

    #[tokio::test]
    async fn test_verify_valid_token() {
        let kp = Keypair::generate();
        let audience = Keypair::generate();
        let ucan = Ucan::issue(
            &kp,
            audience.did(),
            vec![Capability::new("gitlawb://repos/test", "git/push")],
            None,
        )
        .unwrap();
        let encoded = ucan.encode().unwrap();

        cmd_verify(encoded).await.unwrap();
    }

    #[tokio::test]
    async fn test_verify_from_file() {
        let dir = TempDir::new().unwrap();
        let kp = Keypair::generate();
        let audience = Keypair::generate();
        let ucan = Ucan::issue(
            &kp,
            audience.did(),
            vec![Capability::new("gitlawb://repos/test", "git/fetch")],
            None,
        )
        .unwrap();
        let path = dir.path().join("token.json");
        std::fs::write(&path, ucan.encode().unwrap()).unwrap();

        cmd_verify(path.to_string_lossy().to_string())
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod delegation_store_tests {
    use super::*;

    #[test]
    fn delegation_path_strips_the_did_prefix_and_separates_owner_from_repo() {
        let base = std::path::Path::new("/tmp/id");
        let expected = base.join("delegations").join("z6MkAbc__myrepo.ucan");

        assert_eq!(
            delegation_path(base, "did:key:z6MkAbc", "myrepo"),
            expected,
            "the bare key keys the file: `did:key:` contains ':', which is not a \
             legal filename character on Windows"
        );
        // A bare owner and a full DID must resolve to the same file, or a
        // delegation stored under one form is invisible to a lookup by the other.
        assert_eq!(
            delegation_path(base, "z6MkAbc", "myrepo"),
            expected,
            "bare and full owner forms must address the same delegation"
        );
    }
}

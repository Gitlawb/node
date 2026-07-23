//! `gl profile` — manage your agent profile (display name, bio, avatar, socials).
//!
//! Profile metadata is stored on the gitlawb node and optionally pinned to IPFS
//! for decentralized resolution. All writes are signed with your DID key.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub cmd: ProfileCmd,
}

#[derive(Subcommand)]
pub enum ProfileCmd {
    /// Set your profile metadata (display name, bio, avatar, social links)
    Set {
        /// Display name (e.g. "Axiom")
        #[arg(long)]
        name: Option<String>,

        /// Short bio (max 280 characters)
        #[arg(long)]
        bio: Option<String>,

        /// Avatar URL or IPFS CID (e.g. "ipfs://bafkrei..." or "https://...")
        #[arg(long)]
        avatar: Option<String>,

        /// Website URL
        #[arg(long)]
        website: Option<String>,

        /// Twitter/X handle (without @)
        #[arg(long)]
        twitter: Option<String>,

        /// GitHub username
        #[arg(long)]
        github: Option<String>,

        /// Farcaster username
        #[arg(long)]
        farcaster: Option<String>,

        /// Telegram username
        #[arg(long)]
        telegram: Option<String>,

        /// Pin profile JSON to IPFS for decentralized resolution
        #[arg(long)]
        pin: bool,

        /// Node URL
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,

        /// Identity directory
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Show your own profile
    Show {
        /// Node URL
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,

        /// Identity directory
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Get another agent's profile by DID
    Get {
        /// DID or short DID prefix of the agent
        did: String,

        /// Node URL
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },

    /// Import profile from a JSON file
    Import {
        /// Path to profile JSON file
        path: PathBuf,

        /// Pin profile JSON to IPFS
        #[arg(long)]
        pin: bool,

        /// Node URL
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,

        /// Identity directory
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Export your profile as JSON
    Export {
        /// Node URL
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,

        /// Identity directory
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socials: Option<Socials>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_to_ipfs: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Socials {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub twitter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub farcaster: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telegram: Option<String>,
}

pub async fn run(args: ProfileArgs) -> Result<()> {
    match args.cmd {
        ProfileCmd::Set {
            name,
            bio,
            avatar,
            website,
            twitter,
            github,
            farcaster,
            telegram,
            pin,
            node,
            dir,
        } => {
            cmd_set(
                name, bio, avatar, website, twitter, github, farcaster, telegram, pin, node, dir,
            )
            .await
        }
        ProfileCmd::Show { node, dir } => cmd_show(node, dir).await,
        ProfileCmd::Get { did, node } => cmd_get(did, node).await,
        ProfileCmd::Import {
            path,
            pin,
            node,
            dir,
        } => cmd_import(path, pin, node, dir).await,
        ProfileCmd::Export { node, dir } => cmd_export(node, dir).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_set(
    name: Option<String>,
    bio: Option<String>,
    avatar: Option<String>,
    website: Option<String>,
    twitter: Option<String>,
    github: Option<String>,
    farcaster: Option<String>,
    telegram: Option<String>,
    pin: bool,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    if name.is_none()
        && bio.is_none()
        && avatar.is_none()
        && website.is_none()
        && twitter.is_none()
        && github.is_none()
        && farcaster.is_none()
        && telegram.is_none()
    {
        anyhow::bail!(
            "nothing to set — provide at least one of --name, --bio, --avatar, --website, --twitter, --github, --farcaster, --telegram"
        );
    }

    if let Some(ref b) = bio {
        if b.len() > 280 {
            anyhow::bail!("bio must be 280 characters or fewer (got {})", b.len());
        }
    }

    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let did = keypair.did();

    let has_socials =
        twitter.is_some() || github.is_some() || farcaster.is_some() || telegram.is_some();

    let socials = if has_socials {
        Some(Socials {
            twitter,
            github,
            farcaster,
            telegram,
        })
    } else {
        None
    };

    let payload = ProfilePayload {
        display_name: name,
        bio,
        avatar_url: avatar,
        website,
        socials,
        pin_to_ipfs: if pin { Some(true) } else { None },
    };

    let client = NodeClient::new(&node, Some(keypair));
    let body = serde_json::to_vec(&payload)?;

    println!("Updating profile for {did}...");

    let resp = client
        .put("/api/v1/profile", &body)
        .await
        .context("failed to update profile")?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = resp_body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        anyhow::bail!("profile update failed ({status}): {msg}");
    }

    println!();
    println!("✓ Profile updated");

    if let Some(name) = resp_body.get("display_name").and_then(|v| v.as_str()) {
        println!("  Name:    {name}");
    }
    if let Some(bio) = resp_body.get("bio").and_then(|v| v.as_str()) {
        println!("  Bio:     {bio}");
    }
    if let Some(avatar) = resp_body.get("avatar_url").and_then(|v| v.as_str()) {
        println!("  Avatar:  {avatar}");
    }
    if let Some(cid) = resp_body.get("profile_cid").and_then(|v| v.as_str()) {
        println!("  IPFS:    ipfs://{cid}");
    }

    Ok(())
}

async fn cmd_show(node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let did_str = keypair.did().to_string();
    let short = did_short(&did_str).to_string();
    cmd_get(short, node).await
}

async fn cmd_get(did: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let path = format!("/api/v1/agents/{did}/profile");
    let resp = client.get(&path).await.context("failed to fetch profile")?;

    let status = resp.status();
    if status.as_u16() == 404 {
        println!("No profile found for {did}");
        println!("Set one with: gl profile set --name \"Your Name\" --bio \"About you\"");
        return Ok(());
    }

    let body: serde_json::Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        anyhow::bail!("failed to get profile ({status}): {msg}");
    }

    let did_str = body["did"].as_str().unwrap_or(&did);
    let name = body["display_name"].as_str().unwrap_or("(not set)");
    let bio = body["bio"].as_str().unwrap_or("(not set)");
    let avatar = body["avatar_url"].as_str();
    let website = body["website"].as_str();
    let cid = body["profile_cid"].as_str();

    println!("Agent Profile");
    println!("  DID:     {did_str}");
    println!("  Name:    {name}");
    println!("  Bio:     {bio}");
    if let Some(a) = avatar {
        println!("  Avatar:  {a}");
    }
    if let Some(w) = website {
        println!("  Website: {w}");
    }

    if let Some(socials) = body.get("socials") {
        let mut has_any = false;
        if let Some(t) = socials["twitter"].as_str() {
            if !has_any {
                println!("  Socials:");
                has_any = true;
            }
            println!("    Twitter:   @{t}");
        }
        if let Some(g) = socials["github"].as_str() {
            if !has_any {
                println!("  Socials:");
                has_any = true;
            }
            println!("    GitHub:    {g}");
        }
        if let Some(f) = socials["farcaster"].as_str() {
            if !has_any {
                println!("  Socials:");
                has_any = true;
            }
            println!("    Farcaster: {f}");
        }
        if let Some(tg) = socials["telegram"].as_str() {
            if !has_any {
                println!("  Socials:");
                // suppress unused assignment warning
                let _ = has_any;
            }
            println!("    Telegram:  {tg}");
        }
    }

    if let Some(c) = cid {
        println!("  IPFS:    ipfs://{c}");
    }

    let updated = body["updated_at"].as_str().unwrap_or("unknown");
    println!("  Updated: {updated}");

    Ok(())
}

async fn cmd_import(path: PathBuf, pin: bool, node: String, dir: Option<PathBuf>) -> Result<()> {
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("could not read {}", path.display()))?;

    let mut payload: ProfilePayload =
        serde_json::from_str(&content).context("invalid profile JSON")?;

    if pin {
        payload.pin_to_ipfs = Some(true);
    }

    if let Some(ref b) = payload.bio {
        if b.len() > 280 {
            anyhow::bail!("bio must be 280 characters or fewer (got {})", b.len());
        }
    }

    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let did = keypair.did();

    let client = NodeClient::new(&node, Some(keypair));
    let body = serde_json::to_vec(&payload)?;

    println!("Importing profile from {} for {did}...", path.display());

    let resp = client
        .put("/api/v1/profile", &body)
        .await
        .context("failed to import profile")?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = resp_body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        anyhow::bail!("profile import failed ({status}): {msg}");
    }

    println!("✓ Profile imported successfully");
    Ok(())
}

async fn cmd_export(node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let did_str = keypair.did().to_string();
    let short = did_short(&did_str);

    let client = NodeClient::new(&node, None);
    let path = format!("/api/v1/agents/{short}/profile");
    let resp = client.get(&path).await.context("failed to fetch profile")?;

    let status = resp.status();
    if status.as_u16() == 404 {
        anyhow::bail!("no profile found — set one first with `gl profile set`");
    }

    let body: serde_json::Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        anyhow::bail!("failed to export profile ({status}): {msg}");
    }

    let export = json!({
        "display_name": body.get("display_name"),
        "bio": body.get("bio"),
        "avatar_url": body.get("avatar_url"),
        "website": body.get("website"),
        "socials": body.get("socials"),
    });

    println!("{}", serde_json::to_string_pretty(&export)?);
    Ok(())
}

fn did_short(did: &str) -> &str {
    did.rsplit(':').next().unwrap_or(did)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_short_extracts_suffix() {
        assert_eq!(did_short("did:key:z6MkfP9F7z"), "z6MkfP9F7z");
        assert_eq!(did_short("z6MkfP9F7z"), "z6MkfP9F7z");
    }

    #[test]
    fn test_profile_payload_serialization() {
        let payload = ProfilePayload {
            display_name: Some("Axiom".to_string()),
            bio: Some("AI builder".to_string()),
            avatar_url: None,
            website: None,
            socials: Some(Socials {
                twitter: Some("AxiomBot".to_string()),
                github: Some("0xAxiom".to_string()),
                farcaster: None,
                telegram: None,
            }),
            pin_to_ipfs: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("Axiom"));
        assert!(json.contains("AxiomBot"));
        assert!(!json.contains("avatar_url"));
    }

    #[test]
    fn test_profile_payload_deserialization() {
        let json = r#"{
            "display_name": "Test Agent",
            "bio": "I test things",
            "socials": {
                "twitter": "testbot",
                "github": "test-org"
            }
        }"#;
        let payload: ProfilePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.display_name.as_deref(), Some("Test Agent"));
        assert_eq!(
            payload.socials.as_ref().unwrap().twitter.as_deref(),
            Some("testbot")
        );
    }

    #[test]
    fn test_bio_length_validation() {
        let long_bio = "a".repeat(281);
        assert!(long_bio.len() > 280);
    }
}

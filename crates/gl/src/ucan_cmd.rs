//! `gl ucan` — delegate, show, and verify UCAN capability tokens.

use anyhow::{Context, Result};
use clap::Args;
use serde_json::json;
use std::path::PathBuf;

use gitlawb_core::did::Did;
use gitlawb_core::ucan::{caps, Capability, Ucan};

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
        /// Expiry in hours. Defaults to 720 (30 days).
        ///
        /// A capability that authorizes a write must lapse on its own: there is no
        /// revocation path yet, so an unbounded delegation cannot be withdrawn once
        /// the token leaks. A node refuses an unbounded `git/push` chain outright.
        #[arg(long, default_value_t = DEFAULT_DELEGATION_EXPIRY_HOURS)]
        expiry: u64,
        /// Issue with no expiry. The result cannot authorize a push, and cannot be
        /// withdrawn — only use it for advisory or read-shaped capabilities.
        #[arg(long, conflicts_with = "expiry")]
        no_expiry: bool,
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

/// A path component that is safe to build a filename from.
///
/// This is load-bearing, not defensive tidiness: the values it guards flow into
/// [`delegation_path`], which `gl ucan import` WRITES to, and they come from a
/// field of an untrusted token. `Path::join` with an absolute component discards
/// the base entirely, so an owner of `/etc/cron.d/x` or `C:/Windows/...` escapes
/// the delegations directory completely rather than merely climbing out of it.
///
/// Deliberately an allow-list. A DID carries `:` (`did:key:z6Mk…`) and repo names
/// carry `.`, `-` and `_`; nothing else is needed, and a deny-list of separators
/// would miss whichever ones the next platform introduces.
fn is_safe_component(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// Pull the repo this capability names out of `gitlawb://repos/<owner>/<repo>`.
///
/// Requires exactly two components after the prefix. Anything else — extra
/// segments, a trailing slash, an empty half — is refused rather than
/// interpreted, so no input can address a location the caller did not intend.
fn repo_from_resource(with: &str) -> Option<(String, String)> {
    let rest = with.strip_prefix("gitlawb://repos/")?;
    let mut parts = rest.split('/');
    let owner = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if !is_safe_component(owner) || !is_safe_component(name) {
        return None;
    }
    Some((owner.to_string(), name.to_string()))
}

/// Default delegation lifetime. Finite on purpose: an unbounded write capability
/// cannot be withdrawn while there is no revocation path, and the node refuses one.
pub const DEFAULT_DELEGATION_EXPIRY_HOURS: u64 = 720;

pub async fn run(args: UcanArgs) -> Result<()> {
    match args.cmd {
        UcanCmd::Delegate {
            to,
            cap,
            can,
            expiry,
            no_expiry,
            out,
            dir,
            json: json_out,
        } => {
            let exp_hours = if no_expiry { None } else { Some(expiry) };
            cmd_delegate(to, cap, can, exp_hours, out, dir, json_out).await
        }
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

    // The audience has to be THIS identity. The node requires `proof.aud` to equal
    // the invocation issuer, so a token addressed to someone else is unusable here
    // however well-formed it is: the helper would sign as us, the proof would name
    // them, and the node would refuse the linkage — a 403 with nothing locally to
    // explain it. Import is the last cheap place to say so.
    let me = crate::identity::load_keypair_from_dir(dir.as_deref())
        .context("cannot tell who this delegation is for without a local identity")?;
    let my_did = me.did().to_string();
    if !did_eq(&ucan.payload.aud.to_string(), &my_did) {
        anyhow::bail!(
            "this delegation is addressed to {}, but the local identity is {my_did}. \
             Ask the owner to re-issue it with `--to {my_did}`.",
            ucan.payload.aud
        );
    }

    // Verify before it can displace a working delegation: a token the node would
    // refuse is not worth overwriting a good one for.
    let root = ucan
        .verify_chain()
        .map_err(|e| anyhow::anyhow!("this delegation does not verify: {e}"))?;
    if ucan.is_expired() {
        anyhow::bail!("this delegation has already expired");
    }
    if !ucan.chain_lifetime_is_bounded() {
        anyhow::bail!(
            "this delegation has an unbounded link, and a node refuses an unbounded push chain"
        );
    }
    tracing::debug!("delegation verified, rooted at {root}");

    // Import admits only what the push path can actually use. `build_invocation`
    // requires a push-class action on a concrete repository resource, so a token
    // carrying only `pr/open` would import "successfully", print a stored path, and
    // then be dropped at push time behind a `tracing::warn` the operator never
    // sees — a denial wearing the shape of an empty success.
    let push_caps: Vec<(String, String)> = ucan
        .payload
        .att
        .iter()
        .filter(|cap| is_push_class(&cap.can))
        .filter_map(|cap| repo_from_resource(&cap.with))
        .collect();

    if push_caps.is_empty() {
        anyhow::bail!(
            "this delegation carries no storable push capability — expected {} or {} \
             (or \"*\") on gitlawb://repos/<owner>/<repo>, found: {}\n\
             A delegation whose resource is \"*\" cannot be imported either: the store \
             is keyed by repository, so re-issue it against the repository you intend \
             to push to.",
            caps::GIT_PUSH,
            caps::REPO_ADMIN,
            ucan.payload
                .att
                .iter()
                .map(|c| format!("{} -> {}", c.with, c.can))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // The identity directory is a private-data contract, not a public one: it
    // already holds `identity.pem`, whose disclosure is strictly worse than a
    // delegation's. `create_private_dir` and `write_private_file` below carry the
    // per-platform reasoning.
    let base = crate::identity::gitlawb_dir(dir)?;
    let store = base.join("delegations");
    create_private_dir(&store).with_context(|| format!("could not create {}", store.display()))?;

    for (owner, repo) in &push_caps {
        let path = delegation_path(&base, owner, repo);
        // 0600, like the sibling identity key. The token is not itself sufficient to
        // push — the node requires `iss` to equal the request signer, so a reader
        // still needs the delegate's private key — but it does disclose the
        // delegation graph and which identities hold capabilities on which repos.
        write_private_file(&path, raw.as_bytes())
            .with_context(|| format!("could not write {}", path.display()))?;
        println!("Stored delegation for {owner}/{repo} at {}", path.display());
    }

    Ok(())
}

/// Actions the push path accepts. Kept in step with the filter in
/// `git-remote-gitlawb`'s `build_invocation`, which is what actually mints an
/// invocation from a stored delegation.
fn is_push_class(can: &str) -> bool {
    can == caps::GIT_PUSH || can == "*" || can == caps::REPO_ADMIN
}

/// Create the delegation store owner-only, with no window at a wider mode.
///
/// `create_dir_all` followed by `set_permissions` leaves the directory at the
/// process umask — 0755 under the usual 022 — until the second call lands, which
/// is long enough for another local user to open it. The mode rides on the
/// creating syscall instead. The follow-up `set_permissions` is not the window
/// reopening: it only matters when the directory already existed, and repairs a
/// 0755 store left behind by an older `gl`.
#[cfg(unix)]
fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Write `contents`, owner-only from the moment the file exists.
///
/// Not `create_new`: re-importing a refreshed delegation has to overwrite the
/// stored one. `mode` applies only when the file is created, so the trailing
/// `set_permissions` covers a 0644 file written by an older `gl`.
#[cfg(unix)]
fn write_private_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // Written to a sibling temp first, then renamed. Opening the real path with
    // `truncate(true)` empties a working delegation before the replacement is
    // written, so an interruption, ENOSPC, or a short write between the two leaves
    // the operator with an unreadable token and pushes that silently drop `X-Ucan`.
    // `rename` within a directory is atomic: either the old token or the new one is
    // there, never a half of either.
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));

    let write = || -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(contents)?;
        // Durable before it becomes the live token: a rename that beats the data to
        // disk can surface an empty file after a crash.
        file.sync_all()?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
    };

    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

// `std::fs` has no portable ACL API, and `gitlawb_dir` accepts any directory, so
// the contract off Unix is that the caller supplies a user-private directory —
// which is what the platform's per-user profile gives by default. The private key
// sits in the same directory under the same assumption, and its disclosure is
// strictly worse than a delegation's, so hardening this one file alone would be
// theatre.
#[cfg(not(unix))]
fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

#[cfg(not(unix))]
fn write_private_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)
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
    let ucan_path = crate::identity::gitlawb_dir(dir)?.join("ucan.json");

    if !ucan_path.exists() {
        println!("No UCAN saved. Run `gl register` first.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&ucan_path)?;
    let ucan = decode_saved_ucan(&content)
        .with_context(|| format!("could not read the saved UCAN at {}", ucan_path.display()))?;

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

    /// `repo_from_resource` feeds `delegation_path`, which builds a filesystem
    /// path that `gl ucan import` then WRITES to — from a field of an untrusted
    /// token. A separator, a parent-directory hop, or an absolute prefix in the
    /// owner escapes the delegations directory; `Path::join` with an absolute
    /// component discards the base entirely, so an absolute owner writes anywhere
    /// the user can write.
    #[test]
    fn repo_from_resource_rejects_anything_that_could_escape_the_store() {
        for bad in [
            "gitlawb://repos/../../evil/x",
            "gitlawb://repos/../x",
            "gitlawb://repos/a/../../x",
            "gitlawb://repos//x",
            "gitlawb://repos/C:/Windows/System32/x",
            "gitlawb://repos//etc/cron.d/x",
            "gitlawb://repos/a\\b/x",
            "gitlawb://repos/owner/sub/dir/x",
            "gitlawb://repos/owner/x/",
            "gitlawb://repos/owner/",
            "gitlawb://repos/owner",
            "gitlawb://repos/",
            "gitlawb://repos/owner/..",
            "gitlawb://repos/owner/.",
            "gitlawb://repos/./x",
            "https://repos/owner/x",
            "",
        ] {
            assert!(
                repo_from_resource(bad).is_none(),
                "{bad:?} must not yield a storable owner/repo pair"
            );
        }
    }

    #[test]
    fn repo_from_resource_accepts_the_canonical_shape() {
        assert_eq!(
            repo_from_resource("gitlawb://repos/did:key:z6MkAbc/myrepo"),
            Some(("did:key:z6MkAbc".to_string(), "myrepo".to_string()))
        );
        assert_eq!(
            repo_from_resource("gitlawb://repos/z6MkAbc/my-repo.rs"),
            Some(("z6MkAbc".to_string(), "my-repo.rs".to_string()))
        );
    }

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

    /// Seed `dir` with a local identity and issue a delegation addressed to it.
    ///
    /// Import now binds the token's audience to the local key, so a fixture that
    /// issues to an unrelated DID is testing the audience check rather than
    /// whatever it meant to test.
    pub(super) fn seed_identity(dir: &std::path::Path) -> gitlawb_core::identity::Keypair {
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(dir.join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();
        kp
    }

    pub(super) fn token_for_agent(
        agent: &gitlawb_core::identity::Keypair,
        can: &str,
        with: &str,
    ) -> String {
        let owner = gitlawb_core::identity::Keypair::generate();
        Ucan::issue(
            &owner,
            agent.did(),
            vec![Capability::new(with, can)],
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    /// A delegation the push path cannot use must fail at import, where the
    /// operator is watching. `build_invocation` requires a push-class action, so a
    /// `pr/open` token that imported "successfully" would be silently dropped from
    /// the push behind a `tracing::warn` and surface only as a 403 with no
    /// connection to the earlier success.
    #[tokio::test]
    async fn import_refuses_a_delegation_the_push_path_cannot_use() {
        for can in ["pr/open", "issue/create", "git/fetch"] {
            let dir = tempfile::tempdir().unwrap();
            let agent = seed_identity(dir.path());
            let token = token_for_agent(&agent, can, "gitlawb://repos/z6MkAbc/myrepo");

            let err = cmd_import(token, Some(dir.path().to_path_buf()))
                .await
                .expect_err("{can} is not a push capability and must be refused");

            assert!(
                err.to_string().contains(caps::GIT_PUSH),
                "the error must name the action the push path needs: {err}"
            );
            assert!(
                !dir.path().join("delegations").exists(),
                "nothing may be written before the capability is accepted"
            );
        }
    }

    /// The resource is `*`, so the store — which is keyed by repository — has no
    /// filename to write under. Refused with an explanation rather than reported as
    /// an import that stored nothing.
    #[tokio::test]
    async fn import_refuses_a_wildcard_resource() {
        let dir = tempfile::tempdir().unwrap();
        let agent = seed_identity(dir.path());
        let token = token_for_agent(&agent, caps::GIT_PUSH, "*");

        let err = cmd_import(token, Some(dir.path().to_path_buf()))
            .await
            .expect_err("a wildcard resource cannot be keyed by repository");

        assert!(
            err.to_string().contains("re-issue"),
            "the error must say what to do instead: {err}"
        );
        assert!(!dir.path().join("delegations").exists());
    }

    #[tokio::test]
    async fn import_accepts_every_push_class_action() {
        for can in [caps::GIT_PUSH, caps::REPO_ADMIN, "*"] {
            let dir = tempfile::tempdir().unwrap();
            let agent = seed_identity(dir.path());
            let token = token_for_agent(&agent, can, "gitlawb://repos/z6MkAbc/myrepo");

            cmd_import(token, Some(dir.path().to_path_buf()))
                .await
                .unwrap_or_else(|e| panic!("{can} must import: {e}"));

            let stored = delegation_path(dir.path(), "z6MkAbc", "myrepo");
            assert!(stored.exists(), "{can} must leave a stored delegation");
        }
    }

    /// The store and the token file must never exist at a wider mode, not even
    /// briefly: `create_dir_all` then chmod leaves 0755 under the usual umask, and
    /// the token discloses the delegation graph.
    #[cfg(unix)]
    #[tokio::test]
    async fn import_creates_the_store_and_token_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let agent = seed_identity(dir.path());
        let token = token_for_agent(&agent, caps::GIT_PUSH, "gitlawb://repos/z6MkAbc/myrepo");
        cmd_import(token.clone(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();

        let store = dir.path().join("delegations");
        let stored = delegation_path(dir.path(), "z6MkAbc", "myrepo");
        assert_eq!(
            std::fs::metadata(&store).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&stored).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Re-import has to overwrite, which is why this is not `create_new`.
        cmd_import(token, Some(dir.path().to_path_buf()))
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(&stored).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

/// Decode the token out of a saved `ucan.json`.
///
/// `gl register`, `gl init`, and `gl quickstart` all write an envelope —
/// `{"ucan": "<token>", "node": ..., "did": ..., "saved_at": ...}` — and `doctor`
/// and `quickstart` read it back as one. `cmd_show` was the only reader calling
/// `Ucan::decode` on the whole file, and `Ucan` is `{payload, s}`, so it failed
/// with "missing field `payload`" immediately after a successful `gl register`.
///
/// The bare-token form is still accepted: a file written by an older `gl`, or by
/// hand, should not stop being readable just because the envelope is now canonical.
pub(crate) fn decode_saved_ucan(content: &str) -> Result<Ucan> {
    if let Ok(envelope) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(token) = envelope.get("ucan").and_then(|v| v.as_str()) {
            return Ucan::decode(token).map_err(Into::into);
        }
    }
    Ucan::decode(content.trim()).map_err(Into::into)
}

#[cfg(test)]
mod saved_ucan_tests {
    use super::*;

    fn a_token() -> String {
        let kp = gitlawb_core::identity::Keypair::generate();
        let aud = gitlawb_core::identity::Keypair::generate();
        Ucan::issue(
            &kp,
            aud.did(),
            vec![Capability::new("*", caps::GIT_PUSH)],
            None,
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    /// The shape `gl register`, `gl init`, and `gl quickstart` all write, and the
    /// shape `doctor` and `quickstart` already read back. `cmd_show` used to call
    /// `Ucan::decode` on the whole file and failed with "missing field `payload`"
    /// immediately after a successful `gl register`.
    #[test]
    fn the_register_envelope_decodes() {
        let token = a_token();
        let envelope = serde_json::json!({
            "ucan": token,
            "node": "https://node.gitlawb.com",
            "did": "did:key:z6MkAbc",
            "saved_at": "2026-08-17T00:00:00Z",
        })
        .to_string();

        let decoded = decode_saved_ucan(&envelope).expect("the written envelope must decode");
        assert_eq!(decoded.encode().unwrap(), token);
    }

    /// A file written by an older `gl`, or by hand, stays readable.
    #[test]
    fn a_bare_token_still_decodes() {
        let token = a_token();
        assert_eq!(
            decode_saved_ucan(&format!("  {token}\n"))
                .expect("a bare token must still decode")
                .encode()
                .unwrap(),
            token
        );
    }

    #[test]
    fn neither_shape_swallows_garbage() {
        assert!(decode_saved_ucan("not a ucan").is_err());
        assert!(decode_saved_ucan(r#"{"node":"x"}"#).is_err());
    }
}

/// Compare two DIDs ignoring the `did:key:` prefix.
///
/// The same identity appears in both forms across this codebase — the node stores
/// canonical rows full and mirror rows bare, and `delegation_path` keys on the bare
/// form for filename safety — so a literal string compare would reject a match that
/// every other layer accepts.
fn did_eq(a: &str, b: &str) -> bool {
    let bare = |d: &str| d.strip_prefix("did:key:").unwrap_or(d).to_string();
    bare(a) == bare(b)
}

#[cfg(test)]
mod import_binding_tests {
    use super::delegation_store_tests::{seed_identity, token_for_agent};
    use super::*;

    /// A valid delegation addressed to somebody else must fail at import, not at
    /// push. The node requires `proof.aud == invocation.iss`, so storing it only
    /// buys a 403 later with nothing pointing back to the import that caused it.
    #[tokio::test]
    async fn import_refuses_a_delegation_addressed_to_another_identity() {
        let dir = tempfile::tempdir().unwrap();
        let _me = seed_identity(dir.path());
        let someone_else = gitlawb_core::identity::Keypair::generate();
        let token = token_for_agent(
            &someone_else,
            caps::GIT_PUSH,
            "gitlawb://repos/z6MkAbc/myrepo",
        );

        let err = cmd_import(token, Some(dir.path().to_path_buf()))
            .await
            .expect_err("a delegation for another DID is unusable here");

        assert!(
            err.to_string().contains("addressed to"),
            "the error must name the mismatch: {err}"
        );
        assert!(
            !dir.path().join("delegations").exists(),
            "nothing may be stored for a delegation this identity cannot invoke"
        );
    }

    /// A failed re-import must not destroy the delegation already in place.
    /// `truncate(true)` on the live path emptied it before the replacement landed.
    #[tokio::test]
    async fn a_refused_reimport_leaves_the_stored_delegation_intact() {
        let dir = tempfile::tempdir().unwrap();
        let me = seed_identity(dir.path());
        let good = token_for_agent(&me, caps::GIT_PUSH, "gitlawb://repos/z6MkAbc/myrepo");
        cmd_import(good.clone(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
        let stored = delegation_path(dir.path(), "z6MkAbc", "myrepo");
        let before = std::fs::read_to_string(&stored).unwrap();

        // A token for the same repo that import must refuse.
        let someone_else = gitlawb_core::identity::Keypair::generate();
        let bad = token_for_agent(
            &someone_else,
            caps::GIT_PUSH,
            "gitlawb://repos/z6MkAbc/myrepo",
        );
        let _ = cmd_import(bad, Some(dir.path().to_path_buf())).await;

        assert_eq!(
            std::fs::read_to_string(&stored).unwrap(),
            before,
            "a refused import must leave the working delegation exactly as it was"
        );
    }

    /// An expired delegation cannot displace a live one either.
    #[tokio::test]
    async fn import_refuses_an_expired_delegation() {
        let dir = tempfile::tempdir().unwrap();
        let me = seed_identity(dir.path());
        let owner = gitlawb_core::identity::Keypair::generate();
        let expired = Ucan::issue(
            &owner,
            me.did(),
            vec![Capability::new(
                "gitlawb://repos/z6MkAbc/myrepo",
                caps::GIT_PUSH,
            )],
            Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        )
        .unwrap()
        .encode()
        .unwrap();

        let err = cmd_import(expired, Some(dir.path().to_path_buf()))
            .await
            .expect_err("an expired delegation is not importable");
        assert!(
            err.to_string().contains("expired"),
            "the error must name expiry: {err}"
        );
    }
}

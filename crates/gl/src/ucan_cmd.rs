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
    /// Verify a UCAN token: signature, expiry, and its proof chain back to the root
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

/// Largest token file `gl ucan import` and `gl ucan verify` will read. A full
/// eight-link chain encodes to well under 32 KiB even though every nesting level
/// re-escapes the one inside it, so this only stops a mistaken argument from
/// slurping something enormous into memory.
const MAX_TOKEN_FILE_BYTES: u64 = 1 << 20;

/// The token a command was given: the argument itself when it is JSON, otherwise
/// the contents of the file it names.
///
/// A path that exists but cannot be read — a directory, a permission problem, a
/// file past the size cap — is reported as that. It used to fall through to
/// "treat the argument as a token", which then failed in `Ucan::decode` with a
/// message about the path string not being JSON, sending the reader after the
/// wrong problem.
fn read_token_argument(arg: &str) -> Result<String> {
    let trimmed = arg.trim();
    if trimmed.starts_with('{') {
        return Ok(trimmed.to_string());
    }
    let meta = match std::fs::metadata(arg) {
        Ok(meta) => meta,
        // Not a path at all: a token in some form `decode` may or may not accept,
        // whose error will say so. `InvalidFilename` is what a long JSON string
        // produces on Windows (and past PATH_MAX elsewhere), `InvalidInput` its
        // older spelling.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::InvalidFilename
                    | std::io::ErrorKind::InvalidInput
            ) =>
        {
            return Ok(trimmed.to_string());
        }
        Err(e) => return Err(e).with_context(|| format!("cannot read token file {arg}")),
    };
    if !meta.is_file() {
        anyhow::bail!("{arg} is not a file");
    }
    if meta.len() > MAX_TOKEN_FILE_BYTES {
        anyhow::bail!(
            "{arg} is {} bytes, larger than any UCAN token (the cap is {MAX_TOKEN_FILE_BYTES})",
            meta.len()
        );
    }
    let contents =
        std::fs::read_to_string(arg).with_context(|| format!("cannot read token file {arg}"))?;
    Ok(contents.trim().to_string())
}

/// Most characters of one token-derived value that reach the terminal.
const SHOWN_MAX_CHARS: usize = 512;

/// Token-derived text, made safe for a terminal.
///
/// Every string a token carries — `with`, `can`, `iss`, `aud`, and the error text
/// `verify_chain` builds out of them — is chosen by whoever built the token: `Did`
/// deserializes any string, and a capability field is free text. Printed raw, an
/// ANSI or OSC sequence in one of them drives the operator's terminal (INV-6).
/// The strip is the workspace's one definition; the cap keeps a megabyte of
/// nonsense from scrolling the reason off the screen.
fn shown(s: &str) -> String {
    let clean = gitlawb_core::sanitize::strip_terminal_controls(s);
    if clean.chars().count() > SHOWN_MAX_CHARS {
        let mut cut: String = clean.chars().take(SHOWN_MAX_CHARS).collect();
        cut.push('…');
        cut
    } else {
        clean
    }
}

/// What a successful import stored, for the caller to report.
pub(crate) struct Imported {
    pub owner: String,
    pub repo: String,
    pub path: PathBuf,
    /// The root issuer the chain verified to — the owner the node will anchor on.
    pub root: String,
    pub expires: Option<i64>,
}

/// Store a delegation where `git-remote-gitlawb` will look for it on push.
///
/// The token is decoded here rather than at push time so a malformed delegation
/// fails where the error is actionable, instead of surfacing as an unexplained
/// 403 in the middle of a `git push`. `gl ucan import` and the MCP `ucan_import`
/// tool are both this function: one set of checks, one store.
pub(crate) async fn import_delegation(
    token: &str,
    dir: Option<&std::path::Path>,
) -> Result<Imported> {
    let raw = read_token_argument(token)?;

    let ucan = Ucan::decode(&raw).context(
        "not a valid UCAN token — pass the JSON emitted by `gl ucan delegate`, or a path to it",
    )?;

    // The audience has to be THIS identity. The node requires `proof.aud` to equal
    // the invocation issuer, so a token addressed to someone else is unusable here
    // however well-formed it is: the helper would sign as us, the proof would name
    // them, and the node would refuse the linkage — a 403 with nothing locally to
    // explain it. Import is the last cheap place to say so.
    let me = crate::identity::load_keypair_from_dir(dir)
        .context("cannot tell who this delegation is for without a local identity")?;
    let my_did = me.did().to_string();
    if !gitlawb_core::ucan::push::did_key_eq(&ucan.payload.aud.to_string(), &my_did) {
        anyhow::bail!(
            "this delegation is addressed to {}, but the local identity is {my_did}. \
             Ask the owner to re-issue it with `--to {my_did}`.",
            shown(&ucan.payload.aud.to_string())
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

    // Every capability is admitted by the SAME rule the helper and the node apply —
    // `gitlawb_core::ucan::push`. Three independent definitions of "usable for push"
    // is how a token got accepted at one stage and refused at the next: a
    // constrained grant that imported and then authorized nothing; a wildcard proof
    // the helper narrowed and the node rejected; a resource whose owner the leaf
    // named but the chain root did not.
    //
    // Two things are checked here that `verify_chain` does not establish:
    //
    //  - The owner named by each capability is the VERIFIED ROOT. `verify_chain`
    //    proves a chain is internally valid; it says nothing about which repository
    //    that chain applies to. Without this, any key holder could issue a valid
    //    bounded token naming `gitlawb://repos/<victim>/repo` and displace the
    //    working delegation for a repository they have no authority over.
    //
    //  - EVERY LINK names the repository, not just the leaf. `is_attenuated_by`
    //    accepts a concrete child under a `*` parent, so a leaf that names the
    //    repository can sit on a proof that names every repository the root owns.
    //    The node walks the whole chain and refuses that; storing it here would
    //    turn a successful import into a guaranteed 403 at push time — the silent
    //    success this command exists to prevent.
    //
    // Everything is validated before anything is written, so a later bad capability
    // cannot leave a multi-repository import half applied.
    let mut push_caps: Vec<(String, String)> = Vec::new();
    let mut rejected_owner: Vec<String> = Vec::new();
    let mut rejected_chain: Vec<String> = Vec::new();
    for cap in &ucan.payload.att {
        if !gitlawb_core::ucan::push::is_push_action(&cap.can) || cap.constraints.is_some() {
            continue;
        }
        // `repo_from_resource` is the shared structural parse plus a filename
        // allow-list: this value becomes a path the store WRITES to.
        let Some((owner, repo)) = repo_from_resource(&cap.with) else {
            continue;
        };
        if !gitlawb_core::ucan::push::did_key_eq(&owner, &root.to_string()) {
            rejected_owner.push(cap.with.clone());
            continue;
        }
        if !ucan.chain_grants_push_to(&owner, &repo) {
            rejected_chain.push(cap.with.clone());
            continue;
        }
        push_caps.push((owner, repo));
    }

    if !rejected_owner.is_empty() {
        anyhow::bail!(
            "this delegation names repositories owned by someone other than the \
             chain's root issuer ({}): {}\n\
             The root is the identity the whole chain rests on, so a capability for \
             another owner cannot have come from them and will be refused on push.",
            shown(&root.to_string()),
            rejected_owner
                .iter()
                .map(|s| shown(s))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if !rejected_chain.is_empty() {
        anyhow::bail!(
            "this delegation's leaf names {}, but a proof behind it does not — it is a \
             wildcard, is constrained, or names another repository. A delegation's \
             scope is fixed when it is issued, and the node refuses a chain whose \
             proofs are wider than its leaf, so storing this would only defer the \
             refusal to `git push`. Ask the owner to issue the delegation directly \
             against this repository.",
            rejected_chain
                .iter()
                .map(|s| shown(s))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if push_caps.is_empty() {
        anyhow::bail!(
            "this delegation carries no storable push capability — expected {} or {} \
             (or \"*\" as the action) on gitlawb://repos/<owner>/<repo>, unconstrained, \
             found: {}\n\
             A \"*\" RESOURCE cannot be imported: the store is keyed by repository, and \
             a wildcard cannot say which repositories it covered when issued: re-issue \
             it against the repository you intend to push to. A \
             capability carrying `nb` cannot be used either — constraints are refused \
             rather than interpreted, so it would authorize nothing on push.",
            caps::GIT_PUSH,
            caps::REPO_ADMIN,
            ucan.payload
                .att
                .iter()
                .map(|c| format!(
                    "{} -> {}{}",
                    shown(&c.with),
                    shown(&c.can),
                    if c.constraints.is_some() {
                        " (constrained)"
                    } else {
                        ""
                    }
                ))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // One repository per token. `gl ucan delegate` and the MCP tool issue one
    // capability per token, so anything naming several repositories was built by
    // hand. The store publishes one file per repository and `write_private_file`
    // is atomic per file, not across files: a failure on the second write would
    // leave the first published while the command reports failure. Refusing is
    // honest where a half-applied import is not. Several capabilities on the SAME
    // repository (`git/push` plus `repo/admin`, say) are one file and are fine.
    push_caps.sort();
    push_caps.dedup();
    if push_caps.len() > 1 {
        anyhow::bail!(
            "this delegation names {} repositories ({}), and `gl ucan import` stores one \
             repository per token. Ask the owner for one delegation per repository.",
            push_caps.len(),
            push_caps
                .iter()
                .map(|(owner, repo)| format!("{owner}/{repo}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let (owner, repo) = push_caps
        .into_iter()
        .next()
        .expect("push_caps is non-empty: the empty case bailed above");

    // The identity directory is a private-data contract, not a public one: it
    // already holds `identity.pem`, whose disclosure is strictly worse than a
    // delegation's. `create_private_dir` and `write_private_file` below carry the
    // per-platform reasoning.
    let base = crate::identity::gitlawb_dir(dir.map(std::path::Path::to_path_buf))?;
    let store = base.join("delegations");
    create_private_dir(&store).with_context(|| format!("could not create {}", store.display()))?;

    let path = delegation_path(&base, &owner, &repo);
    // 0600, like the sibling identity key. The token is not itself sufficient to
    // push — the node requires `iss` to equal the request signer, so a reader
    // still needs the delegate's private key — but it does disclose the
    // delegation graph and which identities hold capabilities on which repos.
    write_private_file(&path, raw.as_bytes())
        .with_context(|| format!("could not write {}", path.display()))?;

    Ok(Imported {
        owner,
        repo,
        path,
        root: root.to_string(),
        expires: ucan.payload.exp,
    })
}

async fn cmd_import(token: String, dir: Option<PathBuf>) -> Result<()> {
    let imported = import_delegation(&token, dir.as_deref()).await?;
    // `owner` and `repo` passed `is_safe_component`, so they are plain to print.
    println!(
        "Stored delegation for {}/{} at {}",
        imported.owner,
        imported.repo,
        imported.path.display()
    );
    Ok(())
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

/// Test-only fault injection for the staging write.
///
/// The refresh contract — a failed replacement leaves the old token complete — can
/// only be proven by making a replacement fail, and filesystem permissions are not
/// a reliable way to do that: `create_private_dir` repairs the store to 0700 before
/// every write, which undid the read-only directory a previous test relied on, and a
/// privileged runner ignores modes altogether. So the write path asks this hook at
/// the most damaging moment — bytes written, nothing published — and production
/// code compiles it to a no-op.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    thread_local! {
        static FAIL_STAGING_WRITE: Cell<bool> = const { Cell::new(false) };
        static FAIL_PUBLISH: Cell<bool> = const { Cell::new(false) };
    }

    /// Fails every staging write on this thread until dropped.
    pub(crate) struct FailStagingWrites;

    impl FailStagingWrites {
        pub(crate) fn arm() -> Self {
            FAIL_STAGING_WRITE.with(|f| f.set(true));
            Self
        }
    }

    impl Drop for FailStagingWrites {
        fn drop(&mut self) {
            FAIL_STAGING_WRITE.with(|f| f.set(false));
        }
    }

    pub(crate) fn staging_write_fault() -> std::io::Result<()> {
        if FAIL_STAGING_WRITE.with(|f| f.get()) {
            Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "injected: staging write failed after the bytes were written",
            ))
        } else {
            Ok(())
        }
    }

    /// Fails the publish step — the rename over the live path — on this thread
    /// until dropped. The staged bytes are complete and durable by then, so this
    /// is the moment at which a writer that cleared the live path before renaming
    /// would leave no delegation at all.
    pub(crate) struct FailPublish;

    impl FailPublish {
        pub(crate) fn arm() -> Self {
            FAIL_PUBLISH.with(|f| f.set(true));
            Self
        }
    }

    impl Drop for FailPublish {
        fn drop(&mut self) {
            FAIL_PUBLISH.with(|f| f.set(false));
        }
    }

    pub(crate) fn publish_fault() -> std::io::Result<()> {
        if FAIL_PUBLISH.with(|f| f.get()) {
            Err(std::io::Error::other(
                "injected: publish failed after the staged token was complete",
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
use fault::{publish_fault, staging_write_fault};

#[cfg(not(test))]
#[inline]
fn staging_write_fault() -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[inline]
fn publish_fault() -> std::io::Result<()> {
    Ok(())
}

/// A staging path unique to this call, in the same directory as `path`.
///
/// A single deterministic `.<name>.tmp` is shared by every importer for a
/// repository: two concurrent refreshes truncate and write the same inode, and one
/// can rename bytes the other validated, reporting success for a token it never
/// published. Process id plus a monotonic counter keeps them apart.
fn staging_path(path: &std::path::Path) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    dir.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Write `contents`, owner-only from the moment the file exists, and never
/// half-published: staged to a per-call sibling at 0600, synced, then renamed over
/// the live path. See `staging_path` for why the sibling is per-call.
#[cfg(unix)]
fn write_private_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // Staged, then renamed. Opening the live path with `truncate(true)` empties a
    // working delegation before the replacement is written, so an interruption,
    // ENOSPC, or short write leaves an unreadable token and pushes that silently
    // drop `X-Ucan`. `rename` within a directory is atomic: either the old token or
    // the new one is there, never half of either.
    let tmp = staging_path(path);

    let write = || -> std::io::Result<()> {
        // `create_new`: the staging path is this operation's alone, so colliding
        // with an existing one is a bug to surface rather than a file to clobber.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(contents)?;
        staging_write_fault()?;
        // Durable before it becomes live: a rename that beats the data to disk can
        // surface an empty file after a crash.
        file.sync_all()?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
    };

    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = publish_fault().and_then(|()| std::fs::rename(&tmp, path)) {
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
    // `fs::write` opens the live delegation with truncation, so a failed or
    // interrupted refresh destroyed a working token here even though the Unix path
    // staged first. The refresh contract is the same on every platform: failure
    // preserves the old credential, success publishes one complete new one.
    use std::io::Write;
    let tmp = staging_path(path);

    let write = || -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(contents)?;
        staging_write_fault()?;
        file.sync_all()
    };

    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // `rename` replaces an existing destination here too: std maps it to
    // `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`. An earlier version removed
    // the live file first on the belief that Windows refused the overwrite, which
    // opened a window with no delegation at all — the one outcome the staging
    // dance exists to prevent. One step, same contract as the Unix path;
    // `a_failed_publish_leaves_the_stored_delegation_intact` is what reddens if
    // that remove ever comes back.
    if let Err(e) = publish_fault().and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
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

    // A push-class wildcard cannot be honoured: the node requires every link in the
    // chain to name the repository, because a delegation's scope is fixed when it is
    // issued and a bare `*` cannot express which repositories it covered at that
    // moment. Refusing at issuance beats minting a token that imports cleanly and
    // then fails every push.
    if gitlawb_core::ucan::push::is_push_wildcard(&cap, &can) {
        anyhow::bail!(
            "a wildcard resource cannot carry a push capability: a delegation is scoped \n             to the repositories it names when issued, and `*` cannot say which those \n             were. Re-run with --cap gitlawb://repos/<owner>/<repo>."
        );
    }

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

    // The saved token came from the node at registration: token-derived, so shown
    // through the same sanitizer as `verify` and `import`.
    println!("Issuer:   {}", shown(&ucan.payload.iss.to_string()));
    println!("Audience: {}", shown(&ucan.payload.aud.to_string()));
    println!("Version:  {}", shown(&ucan.payload.ucan));
    if ucan.payload.att.is_empty() {
        println!("Caps:     (none)");
    } else {
        for cap in &ucan.payload.att {
            println!("Cap:      {} → {}", shown(&cap.with), shown(&cap.can));
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

/// What `gl ucan verify` and the MCP `ucan_verify` tool report about a token.
///
/// One definition for both surfaces, so they cannot disagree about what "valid"
/// means. Both used to answer from the leaf alone — signature and expiry — and
/// called a token valid whose proof chain was broken (a proof signed by the
/// wrong key, an audience that did not match the issuer, a child claiming more
/// than its parent granted). Import and the node then refused it, with nothing
/// on the client side having said why.
pub struct VerifyReport {
    /// The leaf's own signature, or why it failed.
    pub signature: std::result::Result<(), String>,
    pub expired: bool,
    /// The root issuer the proof chain walks to, or why the walk failed.
    /// [`Ucan::verify_chain`] covers signature and expiry of every link, the
    /// leaf included, so `chain` alone decides validity; the other fields say
    /// which part of it went wrong.
    pub chain: std::result::Result<String, String>,
    pub issuer: String,
    pub audience: String,
    pub capabilities: Vec<(String, String)>,
    pub expires: Option<i64>,
}

impl VerifyReport {
    pub fn of(ucan: &Ucan) -> Self {
        Self {
            signature: ucan.verify_signature().map_err(|e| e.to_string()),
            expired: ucan.is_expired(),
            chain: ucan
                .verify_chain()
                .map(|root| root.to_string())
                .map_err(|e| e.to_string()),
            issuer: ucan.payload.iss.to_string(),
            audience: ucan.payload.aud.to_string(),
            capabilities: ucan
                .payload
                .att
                .iter()
                .map(|c| (c.with.clone(), c.can.clone()))
                .collect(),
            expires: ucan.payload.exp,
        }
    }

    /// Signature good, not expired, and the proof chain walks to a root.
    pub fn is_valid(&self) -> bool {
        self.signature.is_ok() && !self.expired && self.chain.is_ok()
    }

    /// The MCP shape. `valid` is [`Self::is_valid`]; the rest is there so a
    /// caller can see which check failed without re-running them.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "valid": self.is_valid(),
            "signature_valid": self.signature.is_ok(),
            "expired": self.expired,
            "chain_valid": self.chain.is_ok(),
            "chain_error": self.chain.as_ref().err(),
            "root_issuer": self.chain.as_ref().ok(),
            "issuer": self.issuer,
            "audience": self.audience,
            "capabilities": self.capabilities
                .iter()
                .map(|(with, can)| serde_json::json!({ "with": with, "can": can }))
                .collect::<Vec<_>>(),
            "expires": self.expires,
        })
    }

    /// The CLI shape, one line per check. Every value here came out of the token
    /// (the error strings too — `verify_chain` quotes `with`, `can`, `iss` and
    /// `aud` in them), so each passes through [`shown`] on its way out.
    pub fn render(&self) -> String {
        let mut out = String::new();
        match &self.signature {
            Ok(()) => out.push_str("Signature: valid\n"),
            Err(e) => out.push_str(&format!("Signature: INVALID — {}\n", shown(e))),
        }
        out.push_str(if self.expired {
            "Expired:   yes\n"
        } else {
            "Expired:   no\n"
        });
        match &self.chain {
            Ok(root) => out.push_str(&format!("Chain:     valid (root {})\n", shown(root))),
            Err(e) => out.push_str(&format!("Chain:     INVALID — {}\n", shown(e))),
        }
        out.push_str(&format!("Issuer:    {}\n", shown(&self.issuer)));
        out.push_str(&format!("Audience:  {}\n", shown(&self.audience)));
        for (with, can) in &self.capabilities {
            out.push_str(&format!("Cap:       {} → {}\n", shown(with), shown(can)));
        }
        out
    }
}

async fn cmd_verify(token: String) -> Result<()> {
    let content = read_token_argument(&token)?;
    let ucan = Ucan::decode(&content).context("failed to parse UCAN token")?;

    let report = VerifyReport::of(&ucan);
    print!("{}", report.render());

    if !report.is_valid() {
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
mod verify_report_tests {
    use super::*;
    use gitlawb_core::identity::Keypair;

    fn hour() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::hours(1)
    }

    /// The round-ten P2: `gl ucan verify` answered from the leaf alone. A leaf with
    /// a good signature on a proof that never named its issuer was reported valid,
    /// then refused by import and by the node.
    #[test]
    fn a_broken_proof_chain_is_not_valid() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let eve = Keypair::generate();
        let node = Keypair::generate();
        let cap = || vec![Capability::new("gitlawb://repos/alice/r", caps::GIT_PUSH)];

        let root = Ucan::issue(&alice, bob.did(), cap(), Some(hour())).unwrap();
        let forged = Ucan::delegate(&eve, node.did(), cap(), Some(hour()), &root).unwrap();

        let report = VerifyReport::of(&forged);
        assert!(
            report.signature.is_ok(),
            "fixture: the leaf signature is valid"
        );
        assert!(!report.expired);
        let chain_err = report
            .chain
            .as_ref()
            .expect_err("the chain must be reported broken");
        assert!(chain_err.contains("proof chain broken"), "{chain_err}");
        assert!(!report.is_valid());

        let rendered = report.render();
        assert!(rendered.contains("Signature: valid"), "{rendered}");
        assert!(rendered.contains("Chain:     INVALID"), "{rendered}");

        let json = report.to_json();
        assert_eq!(json["valid"], false);
        assert_eq!(json["signature_valid"], true);
        assert_eq!(json["chain_valid"], false);
        assert!(json["root_issuer"].is_null());
    }

    /// Everything the report prints came out of the token, and `Did` deserializes
    /// any string, so a crafted token can put an escape sequence in `iss`, `aud`,
    /// `with` or `can` — and, through `verify_chain`'s error text, in the chain
    /// line too. None of it may reach the terminal.
    #[test]
    fn rendered_output_carries_no_terminal_controls_from_the_token() {
        let alice = Keypair::generate();
        let node = Keypair::generate();
        let hostile = "gitlawb://repos/x/\u{1b}]0;pwned\u{7}\u{202E}r";
        let mut ucan = Ucan::issue(
            &alice,
            node.did(),
            vec![Capability::new(hostile, "git/push\u{1b}[31m")],
            Some(hour()),
        )
        .unwrap();
        // A hostile issuer too, by the route a crafted token takes: `Did`'s
        // `FromStr` validates, its `Deserialize` does not. The signature no longer
        // matches, which is fine — the point is what the lines look like, not
        // whether they say "valid".
        ucan.payload.iss = serde_json::from_str::<Did>("\"did:key:z6Mk\\u001b[2J\"").unwrap();

        let rendered = VerifyReport::of(&ucan).render();
        assert!(
            !rendered.chars().any(|c| c.is_control() && c != '\n'),
            "control characters leaked into the report: {rendered:?}"
        );
        assert!(!rendered.contains('\u{202E}'), "{rendered:?}");
        assert!(
            rendered.contains("pwned"),
            "the text itself stays: {rendered}"
        );
    }

    #[test]
    fn shown_caps_runaway_values_and_marks_the_cut() {
        let long = "a".repeat(SHOWN_MAX_CHARS + 50);
        let out = shown(&long);
        assert_eq!(out.chars().count(), SHOWN_MAX_CHARS + 1);
        assert!(out.ends_with('…'));
        assert_eq!(shown("plain"), "plain");
    }

    #[test]
    fn a_sound_chain_reports_its_root() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let node = Keypair::generate();
        let cap = || vec![Capability::new("gitlawb://repos/alice/r", caps::GIT_PUSH)];

        let root = Ucan::issue(&alice, bob.did(), cap(), Some(hour())).unwrap();
        let leaf = Ucan::delegate(&bob, node.did(), cap(), Some(hour()), &root).unwrap();

        let report = VerifyReport::of(&leaf);
        assert!(report.is_valid());
        assert_eq!(
            report.chain.as_deref(),
            Ok(alice.did().to_string().as_str())
        );
        assert!(
            report
                .render()
                .contains(&format!("Chain:     valid (root {})", alice.did())),
            "{}",
            report.render()
        );
        assert_eq!(report.to_json()["root_issuer"], alice.did().to_string());
    }
}

#[cfg(test)]
mod token_argument_tests {
    use super::*;

    #[test]
    fn json_passes_through_without_touching_the_filesystem() {
        let raw = r#"  {"payload":{}}  "#;
        assert_eq!(read_token_argument(raw).unwrap(), r#"{"payload":{}}"#);
    }

    #[test]
    fn a_file_is_read_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        std::fs::write(&path, "  {\"a\":1}\n").unwrap();
        assert_eq!(
            read_token_argument(path.to_str().unwrap()).unwrap(),
            "{\"a\":1}"
        );
    }

    /// A path that exists but cannot be read is an error about the file. It used
    /// to fall through to "treat the argument as a token" and fail in `decode`
    /// with a message about the path string not being JSON.
    #[test]
    fn an_unreadable_path_is_reported_as_the_file_problem_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_token_argument(dir.path().to_str().unwrap())
            .expect_err("a directory is not a token file");
        assert!(err.to_string().contains("is not a file"), "{err}");
    }

    #[test]
    fn a_file_past_the_cap_is_refused_before_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_TOKEN_FILE_BYTES + 1).unwrap();
        let err = read_token_argument(path.to_str().unwrap()).expect_err("must refuse");
        assert!(err.to_string().contains("larger than"), "{err}");
    }

    /// A missing file is indistinguishable from a raw token that is not JSON, and
    /// `decode` names both possibilities in its error, so this stays permissive.
    #[test]
    fn a_missing_path_falls_through_to_decode() {
        assert_eq!(
            read_token_argument("no-such-token.json").unwrap(),
            "no-such-token.json"
        );
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

    /// A delegation whose resource owner is the issuing owner — the shape import
    /// now requires, since the owner segment is checked against the verified root.
    /// Returns the token and the bare owner key the store is keyed on.
    pub(super) fn owned_token(
        agent: &gitlawb_core::identity::Keypair,
        can: &str,
        repo: &str,
    ) -> (String, String) {
        let owner = gitlawb_core::identity::Keypair::generate();
        let full = owner.did().to_string();
        let bare = full.strip_prefix("did:key:").unwrap().to_string();
        let token = Ucan::issue(
            &owner,
            agent.did(),
            vec![Capability::new(
                format!("gitlawb://repos/{bare}/{repo}"),
                can,
            )],
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
        .unwrap()
        .encode()
        .unwrap();
        (token, bare)
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
            let (token, _owner) = owned_token(&agent, can, "myrepo");

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
            let (token, owner) = owned_token(&agent, can, "myrepo");

            cmd_import(token, Some(dir.path().to_path_buf()))
                .await
                .unwrap_or_else(|e| panic!("{can} must import: {e}"));

            let stored = delegation_path(dir.path(), &owner, "myrepo");
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
        // Owner-consistent: import binds the resource owner to the chain root, so a
        // synthetic `z6MkAbc` owner is refused before the mode assertions are reached.
        let (token, owner) = owned_token(&agent, caps::GIT_PUSH, "myrepo");
        cmd_import(token.clone(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();

        let store = dir.path().join("delegations");
        let stored = delegation_path(dir.path(), &owner, "myrepo");
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

#[cfg(test)]
mod import_binding_tests {
    use super::delegation_store_tests::{owned_token, seed_identity, token_for_agent};
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

    /// A REJECTED import must not touch the store. This stops at validation, before
    /// `write_private_file` is reached — which is the point: rejection happens ahead
    /// of any mutation. `a_failed_write_leaves_the_stored_delegation_intact` covers
    /// the writer itself.
    #[tokio::test]
    async fn a_rejected_import_leaves_the_stored_delegation_intact() {
        let dir = tempfile::tempdir().unwrap();
        let me = seed_identity(dir.path());
        let (good, owner) = owned_token(&me, caps::GIT_PUSH, "myrepo");
        cmd_import(good.clone(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
        let stored = delegation_path(dir.path(), &owner, "myrepo");
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

#[cfg(test)]
mod refresh_atomicity_tests {
    use super::delegation_store_tests::{owned_token, seed_identity};
    use super::*;

    /// The writer's own contract: a failed replacement preserves the old token,
    /// complete, and leaves nothing half-published behind.
    ///
    /// Failure is injected, not arranged. The previous version chmod'd the store to
    /// 0500 and expected the staging create to fail; `create_private_dir` repairs
    /// the store to 0700 before every write, so the second import succeeded and the
    /// test failed on `is_err()` — and a privileged CI user would have made the same
    /// arrangement pass anyway. The seam fires after the bytes are written and
    /// before anything is published, the most damaging point, on every platform.
    #[tokio::test]
    async fn a_failed_write_leaves_the_stored_delegation_intact() {
        let dir = tempfile::tempdir().unwrap();
        let me = seed_identity(dir.path());
        let (good, owner_key) = owned_token(&me, caps::GIT_PUSH, "myrepo");
        cmd_import(good.clone(), Some(dir.path().to_path_buf()))
            .await
            .expect("the first import must succeed");

        let stored = delegation_path(dir.path(), &owner_key, "myrepo");
        let before = std::fs::read(&stored).unwrap();
        assert!(!before.is_empty());

        let result = {
            let _fail = fault::FailStagingWrites::arm();
            cmd_import(good, Some(dir.path().to_path_buf())).await
        };

        assert!(result.is_err(), "the injected staging failure must surface");
        assert_eq!(
            std::fs::read(&stored).unwrap(),
            before,
            "a failed refresh must leave the old token complete, not empty or partial"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("delegations"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "a failed staging write must clean up after itself, found {leftovers:?}"
        );
    }

    /// The publish step itself failing — staged bytes complete and durable, the
    /// rename over the live path refused — must leave the old token in place.
    /// This is the moment the non-Unix writer used to have already removed the
    /// live file, so a failed rename there left NO delegation; the success-path
    /// test below cannot tell that writer from this one, because a rename that
    /// succeeds ends in the same state either way. Reinstating the remove reddens
    /// this on the platform that had it.
    #[tokio::test]
    async fn a_failed_publish_leaves_the_stored_delegation_intact() {
        let dir = tempfile::tempdir().unwrap();
        let me = seed_identity(dir.path());
        let (good, owner_key) = owned_token(&me, caps::GIT_PUSH, "myrepo");
        cmd_import(good.clone(), Some(dir.path().to_path_buf()))
            .await
            .expect("the first import must succeed");
        let stored = delegation_path(dir.path(), &owner_key, "myrepo");
        let before = std::fs::read(&stored).unwrap();

        let result = {
            let _fail = fault::FailPublish::arm();
            cmd_import(good, Some(dir.path().to_path_buf())).await
        };

        assert!(result.is_err(), "the injected publish failure must surface");
        assert!(
            stored.exists(),
            "a failed publish must not leave the delegation absent"
        );
        assert_eq!(
            std::fs::read(&stored).unwrap(),
            before,
            "a failed publish must leave the old token complete"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("delegations"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "found {leftovers:?}");
    }

    /// The other half of the contract: a successful refresh replaces the stored
    /// token in one step. On Windows this is `rename` over an existing file, which
    /// std supports (`MOVEFILE_REPLACE_EXISTING`); the writer used to remove the
    /// live file first, on the belief that it did not, and that remove was the
    /// only moment the delegation could be absent.
    #[tokio::test]
    async fn a_successful_refresh_replaces_the_stored_delegation_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let me = seed_identity(dir.path());
        let owner = gitlawb_core::identity::Keypair::generate();
        let bare = owner
            .did()
            .to_string()
            .strip_prefix("did:key:")
            .unwrap()
            .to_string();
        let token_for = |hours: i64| {
            Ucan::issue(
                &owner,
                me.did(),
                vec![Capability::new(
                    format!("gitlawb://repos/{bare}/myrepo"),
                    caps::GIT_PUSH,
                )],
                Some(chrono::Utc::now() + chrono::Duration::hours(hours)),
            )
            .unwrap()
            .encode()
            .unwrap()
        };
        let first = token_for(1);
        let second = token_for(2);
        assert_ne!(first, second);

        cmd_import(first.clone(), Some(dir.path().to_path_buf()))
            .await
            .expect("first import");
        let stored = delegation_path(dir.path(), &bare, "myrepo");
        assert_eq!(std::fs::read_to_string(&stored).unwrap(), first);

        cmd_import(second.clone(), Some(dir.path().to_path_buf()))
            .await
            .expect("a refresh over an existing delegation must succeed");
        assert_eq!(
            std::fs::read_to_string(&stored).unwrap(),
            second,
            "the refresh must publish the new token over the old one"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("delegations"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "found {leftovers:?}");
    }

    /// Two refreshes must not share a staging path: one could rename bytes the other
    /// validated and report success for a token it never published.
    #[test]
    fn staging_paths_are_unique_per_call() {
        let p = std::path::Path::new("/tmp/store/z6MkAbc__myrepo.ucan");
        let a = staging_path(p);
        let b = staging_path(p);
        assert_ne!(a, b, "each write needs its own staging file");
        assert_eq!(
            a.parent(),
            p.parent(),
            "staging must be a sibling, for rename"
        );
    }
}

#[cfg(test)]
mod chain_scope_tests {
    use super::delegation_store_tests::{owned_token, seed_identity};
    use super::*;

    /// A hand-built token naming two repositories is refused before anything is
    /// written. `write_private_file` is atomic per file, not across files, so
    /// applying such a token could publish one repository's delegation and then
    /// fail on the other while reporting failure for both.
    #[tokio::test]
    async fn import_refuses_a_token_naming_two_repositories() {
        let dir = tempfile::tempdir().unwrap();
        let me = seed_identity(dir.path());
        let owner = gitlawb_core::identity::Keypair::generate();
        let bare = owner
            .did()
            .to_string()
            .strip_prefix("did:key:")
            .unwrap()
            .to_string();
        let token = Ucan::issue(
            &owner,
            me.did(),
            vec![
                Capability::new(format!("gitlawb://repos/{bare}/first"), caps::GIT_PUSH),
                Capability::new(format!("gitlawb://repos/{bare}/second"), caps::GIT_PUSH),
            ],
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
        .unwrap()
        .encode()
        .unwrap();

        let err = cmd_import(token, Some(dir.path().to_path_buf()))
            .await
            .expect_err("two repositories in one token must be refused");
        assert!(
            err.to_string().contains("one repository per token"),
            "the refusal must say what the supported shape is: {err}"
        );
        for repo in ["first", "second"] {
            assert!(
                !delegation_path(dir.path(), &bare, repo).exists(),
                "nothing may be written for a refused import ({repo})"
            );
        }
    }

    /// The refusal is about distinct repositories, not distinct capabilities: two
    /// push-class actions on one repository are one stored file.
    #[tokio::test]
    async fn import_accepts_two_capabilities_on_one_repository() {
        let dir = tempfile::tempdir().unwrap();
        let me = seed_identity(dir.path());
        let owner = gitlawb_core::identity::Keypair::generate();
        let bare = owner
            .did()
            .to_string()
            .strip_prefix("did:key:")
            .unwrap()
            .to_string();
        let resource = format!("gitlawb://repos/{bare}/only");
        let token = Ucan::issue(
            &owner,
            me.did(),
            vec![
                Capability::new(&resource, caps::GIT_PUSH),
                Capability::new(&resource, caps::REPO_ADMIN),
            ],
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
        .unwrap()
        .encode()
        .unwrap();

        cmd_import(token.clone(), Some(dir.path().to_path_buf()))
            .await
            .expect("two capabilities on one repository are one delegation");
        assert_eq!(
            std::fs::read_to_string(delegation_path(dir.path(), &bare, "only")).unwrap(),
            token
        );
    }

    /// The round-9 P2: a leaf that names the repository sitting on a proof that is
    /// `*`. Attenuation accepts it, the root matches, and the leaf-only check that
    /// import used to apply stored it — after which the node's full-chain walk
    /// refused every push. Import applies the same walk now and refuses before it
    /// touches the store.
    #[tokio::test]
    async fn import_refuses_a_leaf_whose_proof_is_a_wildcard() {
        let dir = tempfile::tempdir().unwrap();
        let me = seed_identity(dir.path());
        let hour = chrono::Utc::now() + chrono::Duration::hours(1);

        // A good delegation already in place, so the test can also prove the
        // refused one did not displace it.
        let (good, owner_key) = owned_token(&me, caps::GIT_PUSH, "myrepo");
        cmd_import(good, Some(dir.path().to_path_buf()))
            .await
            .expect("seed import");
        let stored = delegation_path(dir.path(), &owner_key, "myrepo");
        let before = std::fs::read(&stored).unwrap();

        // owner --*--> intermediary --concrete--> me
        let owner = gitlawb_core::identity::Keypair::generate();
        let intermediary = gitlawb_core::identity::Keypair::generate();
        let owner_bare = owner
            .did()
            .to_string()
            .strip_prefix("did:key:")
            .unwrap()
            .to_string();
        let wildcard_proof = Ucan::issue(
            &owner,
            intermediary.did(),
            vec![Capability::new("*", caps::GIT_PUSH)],
            Some(hour),
        )
        .unwrap();
        let concrete_leaf = Ucan::delegate(
            &intermediary,
            me.did(),
            vec![Capability::new(
                format!("gitlawb://repos/{owner_bare}/other"),
                caps::GIT_PUSH,
            )],
            Some(hour),
            &wildcard_proof,
        )
        .unwrap();
        assert!(
            concrete_leaf.verify_chain().is_ok(),
            "the chain is cryptographically valid — that is the point"
        );

        let err = cmd_import(
            concrete_leaf.encode().unwrap(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .expect_err("a wildcard proof must be refused at import, not at push");
        assert!(
            err.to_string().contains("proof behind it"),
            "the error must say the proof, not the leaf, is the problem: {err}"
        );
        assert!(
            !delegation_path(dir.path(), &owner_bare, "other").exists(),
            "nothing may be written for a chain the node would refuse"
        );
        assert_eq!(
            std::fs::read(&stored).unwrap(),
            before,
            "the existing delegation must be untouched"
        );
    }

    /// Issuance is the first boundary. Minting a push-class wildcard only creates a
    /// token that every later stage refuses with less context than this.
    #[tokio::test]
    async fn delegate_refuses_a_push_class_wildcard() {
        let dir = tempfile::tempdir().unwrap();
        let _me = seed_identity(dir.path());
        let audience = gitlawb_core::identity::Keypair::generate();

        for can in [caps::GIT_PUSH, "*", caps::REPO_ADMIN] {
            let err = cmd_delegate(
                audience.did().to_string(),
                "*".into(),
                can.into(),
                Some(24),
                None,
                Some(dir.path().to_path_buf()),
                false,
            )
            .await
            .expect_err("a wildcard resource with a push-class action must be refused");
            assert!(err.to_string().contains("wildcard"), "{can}: {err}");
        }

        // A non-push wildcard is still fine: nothing downstream refuses it.
        cmd_delegate(
            audience.did().to_string(),
            "*".into(),
            caps::GIT_FETCH.into(),
            Some(24),
            None,
            Some(dir.path().to_path_buf()),
            false,
        )
        .await
        .expect("a fetch wildcard is not push-class");
    }
}

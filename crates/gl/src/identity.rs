use anyhow::{Context, Result};
use clap::Subcommand;
use gitlawb_core::did::DidDocument;
use gitlawb_core::identity::Keypair;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum IdentityCmd {
    /// Generate a new Ed25519 keypair and DID
    New {
        /// Output directory for key files
        /// (default: the parent of $GITLAWB_KEY, else ~/.gitlawb)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Overwrite existing keys if present
        #[arg(long)]
        force: bool,
    },
    /// Print your current DID
    Show {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Export your DID document as JSON
    Export {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Sign a message with your private key and print base64url signature
    Sign {
        message: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Back up your identity key to a secure location
    Backup {
        /// Destination path for the backup file (default: ./identity.pem.bak)
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Restore your identity key from a backup file
    Restore {
        /// Path to the backup PEM file
        src: PathBuf,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Overwrite existing identity without prompting
        #[arg(long)]
        force: bool,
    },
}

pub async fn run(cmd: IdentityCmd) -> Result<()> {
    match cmd {
        IdentityCmd::New { dir, force } => cmd_new(dir, force).await,
        IdentityCmd::Show { dir } => cmd_show(dir).await,
        IdentityCmd::Export { dir } => cmd_export(dir).await,
        IdentityCmd::Sign { message, dir } => cmd_sign(message, dir).await,
        IdentityCmd::Backup { out, dir } => cmd_backup(out, dir).await,
        IdentityCmd::Restore { src, dir, force } => cmd_restore(src, dir, force).await,
    }
}

/// Resolve the identity directory, honouring an explicit override.
/// Public so sibling commands (`gl ucan import`, `gl doctor`) look in the same
/// place the identity itself lives.
///
/// Without an override this is [`gitlawb_core::identity_path::identity_dir`] — the
/// parent of `GITLAWB_KEY`, else `~/.gitlawb`. The rules live in `gitlawb-core`
/// because `git-remote-gitlawb` needs the identical answer: an operator who moved
/// their key (`GITLAWB_KEY=/data/keys/identity.pem`, the shape `.env.example`
/// documents) would otherwise have `gl ucan import` write the delegation to
/// `~/.gitlawb/delegations` while the helper reads `/data/keys/delegations` and
/// finds it empty. The push then goes out with no `X-Ucan` and the delegate is
/// refused, with nothing on either side to indicate why.
pub fn gitlawb_dir(override_dir: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(d) = override_dir {
        return Ok(d);
    }
    // `home_dir()` is passed as an Option rather than demanded here: an absolute
    // GITLAWB_KEY resolves without a home directory, and a host that has none is a
    // normal container shape, not a reason to refuse a correctly-configured key.
    let home = dirs::home_dir();
    gitlawb_core::identity_path::identity_dir(home.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))
}

/// The identity PEM to read or write.
///
/// With an explicit `--dir` this is `<dir>/identity.pem`, the conventional layout.
/// Without one it is [`gitlawb_core::identity_path::identity_key_path`] — the whole
/// of `GITLAWB_KEY`, basename included.
///
/// Taking only the parent and re-appending `identity.pem` was a real divergence,
/// not a tidy-up: `GITLAWB_KEY` is documented as a path to a PEM, and
/// `git-remote-gitlawb` opens exactly that path. With
/// `GITLAWB_KEY=/data/keys/ci-agent.pem`, `gl identity new` wrote
/// `/data/keys/identity.pem` while every push loaded `/data/keys/ci-agent.pem`, so
/// the two either disagreed on identity or the helper found no key at all — and
/// owner enforcement and the delegation proof both key off that identity.
pub(crate) fn key_path_for(dir: Option<&Path>) -> Result<PathBuf> {
    match dir {
        Some(d) => Ok(d.join(gitlawb_core::identity_path::KEY_FILE_NAME)),
        None => {
            let home = dirs::home_dir();
            gitlawb_core::identity_path::identity_key_path(home.as_deref())
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
    }
}

fn load_keypair(dir: Option<PathBuf>) -> Result<Keypair> {
    load_keypair_from_dir(dir.as_deref())
}

/// Load keypair from an optional directory override.
/// Used by other modules (register, repo, mcp).
///
/// Routed through [`gitlawb_dir`] rather than reaching for `~/.gitlawb` directly:
/// `gl identity new` writes the key wherever `GITLAWB_KEY` points, so a second
/// resolver here would have every other command read a different file than the one
/// just created — `gl ucan delegate` would either fail to find an identity or sign
/// with a stale DID that is not the repo owner.
pub fn load_keypair_from_dir(dir: Option<&std::path::Path>) -> Result<Keypair> {
    let path = key_path_for(dir)?;
    let pem = fs::read_to_string(&path).with_context(|| {
        format!(
            "no identity found at {}\nRun `gl identity new` to create one",
            path.display()
        )
    })?;
    Keypair::from_pem(&pem).context("failed to load keypair from PEM")
}

async fn cmd_new(dir: Option<PathBuf>, force: bool) -> Result<()> {
    cmd_new_with_reader(dir, force, &mut std::io::stdin().lock()).await
}

async fn cmd_new_with_reader(
    dir: Option<PathBuf>,
    force: bool,
    reader: &mut impl std::io::BufRead,
) -> Result<()> {
    let path = key_path_for(dir.as_deref())?;
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    if path.exists() {
        if force {
            eprint!(
                "warning: --force specified. Overwriting existing identity at {}.\nThis will permanently destroy your current DID. Continue? [y/N] ",
                path.display()
            );
        } else {
            eprint!(
                "identity already exists at {}.\nThis will permanently replace your current DID. Continue? [y/N] ",
                path.display()
            );
        }
        let mut input = String::new();
        reader.read_line(&mut input)?;
        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;

    let keypair = Keypair::generate();
    let pem = keypair.to_pem()?;

    // Write with restricted permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&path, pem.as_bytes())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, pem.as_bytes())?;
    }

    let did = keypair.did();
    println!("✓ Generated new identity");
    println!("  DID:  {did}");
    println!("  Key:  {}", path.display());
    println!();
    println!("  Your DID is your identity on the gitlawb network.");
    println!("  Keep your key file safe — it cannot be recovered if lost.");

    Ok(())
}

async fn cmd_show(dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair(dir)?;
    println!("{}", keypair.did());
    Ok(())
}

async fn cmd_export(dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair(dir)?;
    let did = keypair.did();
    let vk = keypair.verifying_key();
    let doc = DidDocument::new(did, &vk);
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}

async fn cmd_sign(message: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair(dir)?;
    let sig = keypair.sign_b64(message.as_bytes());
    println!("{sig}");
    Ok(())
}

async fn cmd_backup(out: Option<PathBuf>, dir: Option<PathBuf>) -> Result<()> {
    let src = key_path_for(dir.as_deref())?;

    let pem = fs::read_to_string(&src).with_context(|| {
        format!(
            "no identity found at {} — run `gl identity new` first",
            src.display()
        )
    })?;

    // Verify it loads before copying
    let keypair = Keypair::from_pem(&pem).context("identity.pem is corrupted")?;

    let dest = out.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_default()
            .join("identity.pem.bak")
    });

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&dest, pem.as_bytes())?;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&dest, pem.as_bytes())?;
    }

    println!("✓ Identity backed up");
    println!("  DID:  {}", keypair.did());
    println!("  From: {}", src.display());
    println!("  To:   {}", dest.display());
    println!();
    println!("  Store this file somewhere safe — a password manager, encrypted drive,");
    println!("  or offline backup. Anyone with this file controls your DID.");
    Ok(())
}

async fn cmd_restore(src: PathBuf, dir: Option<PathBuf>, force: bool) -> Result<()> {
    cmd_restore_with_reader(src, dir, force, &mut std::io::stdin().lock()).await
}

async fn cmd_restore_with_reader(
    src: PathBuf,
    dir: Option<PathBuf>,
    force: bool,
    reader: &mut impl std::io::BufRead,
) -> Result<()> {
    let pem = fs::read_to_string(&src)
        .with_context(|| format!("could not read backup file {}", src.display()))?;

    // Verify it's a valid keypair before writing anything
    let keypair = Keypair::from_pem(&pem).context("backup file is not a valid identity PEM")?;

    let dest = key_path_for(dir.as_deref())?;
    let base = dest
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    if dest.exists() {
        if force {
            eprint!(
                "warning: --force specified. Overwriting existing identity at {}.\nThis will permanently destroy your current DID. Continue? [y/N] ",
                dest.display()
            );
        } else {
            eprint!(
                "identity already exists at {}.\nRestoring will permanently replace your current DID. Continue? [y/N] ",
                dest.display()
            );
        }
        let mut input = String::new();
        reader.read_line(&mut input)?;
        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    fs::create_dir_all(&base)
        .with_context(|| format!("failed to create directory {}", base.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&dest, pem.as_bytes())?;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&dest, pem.as_bytes())?;
    }

    println!("✓ Identity restored");
    println!("  DID:  {}", keypair.did());
    println!("  From: {}", src.display());
    println!("  To:   {}", dest.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_cmd_new_creates_pem() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        assert!(dir.path().join("identity.pem").exists());
    }

    #[tokio::test]
    async fn test_cmd_new_force_overwrites_on_confirm() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        let pem1 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        // Simulate user typing "y" at the --force prompt
        let mut reader = std::io::Cursor::new(b"y\n");
        cmd_new_with_reader(Some(dir.path().to_path_buf()), true, &mut reader)
            .await
            .unwrap();
        let pem2 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        assert_ne!(pem1, pem2);
    }

    #[tokio::test]
    async fn test_cmd_new_force_aborts_on_n() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        let pem1 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        // Simulate user typing "n" — should abort even with --force
        let mut reader = std::io::Cursor::new(b"n\n");
        cmd_new_with_reader(Some(dir.path().to_path_buf()), true, &mut reader)
            .await
            .unwrap();
        let pem2 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        assert_eq!(pem1, pem2);
    }

    #[tokio::test]
    async fn test_cmd_new_no_force_aborts_on_n() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        let pem1 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        let mut reader = std::io::Cursor::new(b"n\n");
        cmd_new_with_reader(Some(dir.path().to_path_buf()), false, &mut reader)
            .await
            .unwrap();
        let pem2 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        assert_eq!(pem1, pem2);
    }

    #[tokio::test]
    async fn test_cmd_show_succeeds() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        cmd_show(Some(dir.path().to_path_buf())).await.unwrap();
    }

    #[tokio::test]
    async fn test_cmd_export_produces_did_document() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        cmd_export(Some(dir.path().to_path_buf())).await.unwrap();
    }

    #[tokio::test]
    async fn test_cmd_sign_succeeds() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        cmd_sign("hello gitlawb".to_string(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
    }

    #[test]
    fn test_load_keypair_missing_returns_error() {
        let dir = TempDir::new().unwrap();
        let result = load_keypair_from_dir(Some(dir.path()));
        assert!(result.is_err());
        let msg = result.err().unwrap().to_string();
        assert!(msg.contains("no identity found") || msg.contains("identity.pem"));
    }

    #[tokio::test]
    async fn test_pem_roundtrip() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        // Loading the keypair back should succeed and produce a valid DID
        let kp = load_keypair_from_dir(Some(dir.path())).unwrap();
        let did = kp.did().to_string();
        assert!(did.starts_with("did:key:"));
    }

    #[tokio::test]
    async fn test_cmd_restore_success() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        // Create an identity and back it up
        cmd_new(Some(src_dir.path().to_path_buf()), false)
            .await
            .unwrap();
        let backup_path = src_dir.path().join("identity.pem.bak");
        cmd_backup(
            Some(backup_path.clone()),
            Some(src_dir.path().to_path_buf()),
        )
        .await
        .unwrap();

        // Restore to a fresh directory
        cmd_restore(backup_path, Some(dst_dir.path().to_path_buf()), false)
            .await
            .unwrap();

        // The restored DID should match the original
        let orig = load_keypair_from_dir(Some(src_dir.path())).unwrap();
        let restored = load_keypair_from_dir(Some(dst_dir.path())).unwrap();
        assert_eq!(orig.did(), restored.did());
    }

    #[tokio::test]
    async fn test_cmd_restore_invalid_pem_fails() {
        let dir = TempDir::new().unwrap();
        let bad_pem = dir.path().join("bad.pem");
        std::fs::write(&bad_pem, b"this is not a valid PEM file").unwrap();

        let err = cmd_restore(bad_pem, Some(dir.path().to_path_buf()), false).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("valid identity PEM"));
    }

    #[tokio::test]
    async fn test_cmd_restore_missing_file_fails() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does_not_exist.pem");

        let err = cmd_restore(missing, Some(dir.path().to_path_buf()), false).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("backup file"));
    }

    #[tokio::test]
    async fn test_cmd_restore_force_overwrites_on_confirm() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        cmd_new(Some(src_dir.path().to_path_buf()), false)
            .await
            .unwrap();
        cmd_new(Some(dst_dir.path().to_path_buf()), false)
            .await
            .unwrap();

        let backup = src_dir.path().join("identity.pem.bak");
        cmd_backup(Some(backup.clone()), Some(src_dir.path().to_path_buf()))
            .await
            .unwrap();

        // Simulate user typing "y" at the --force prompt
        let mut reader = std::io::Cursor::new(b"y\n");
        cmd_restore_with_reader(
            backup,
            Some(dst_dir.path().to_path_buf()),
            true,
            &mut reader,
        )
        .await
        .unwrap();

        let src_kp = load_keypair_from_dir(Some(src_dir.path())).unwrap();
        let dst_kp = load_keypair_from_dir(Some(dst_dir.path())).unwrap();
        assert_eq!(src_kp.did(), dst_kp.did());
    }

    #[tokio::test]
    async fn test_cmd_restore_force_aborts_on_n() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        cmd_new(Some(src_dir.path().to_path_buf()), false)
            .await
            .unwrap();
        cmd_new(Some(dst_dir.path().to_path_buf()), false)
            .await
            .unwrap();
        let original_did = load_keypair_from_dir(Some(dst_dir.path())).unwrap().did();

        let backup = src_dir.path().join("identity.pem.bak");
        cmd_backup(Some(backup.clone()), Some(src_dir.path().to_path_buf()))
            .await
            .unwrap();

        // Simulate user typing "n" — should abort
        let mut reader = std::io::Cursor::new(b"n\n");
        cmd_restore_with_reader(
            backup,
            Some(dst_dir.path().to_path_buf()),
            true,
            &mut reader,
        )
        .await
        .unwrap();

        let dst_kp = load_keypair_from_dir(Some(dst_dir.path())).unwrap();
        assert_eq!(original_did, dst_kp.did());
    }
}

/// Scoped `GITLAWB_KEY` for tests, shared crate-wide.
///
/// The process environment is global and more than one suite in this crate
/// depends on it — the resolver's own cases here, and `gl register`'s check that
/// the bootstrap token lands beside the key. They take one lock rather than each
/// declaring its own, which would not serialise them against each other.
#[cfg(test)]
pub(crate) mod test_env {
    use std::ffi::{OsStr, OsString};
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Restores the previous value and releases the lock on drop.
    pub(crate) struct KeyEnv {
        _guard: MutexGuard<'static, ()>,
        restore: Option<OsString>,
    }

    impl Drop for KeyEnv {
        fn drop(&mut self) {
            match self.restore.take() {
                Some(v) => std::env::set_var("GITLAWB_KEY", v),
                None => std::env::remove_var("GITLAWB_KEY"),
            }
        }
    }

    /// Run `f` with `GITLAWB_KEY` set, restoring it afterwards.
    pub(crate) fn with_key<T, V: AsRef<OsStr>>(value: Option<V>, f: impl FnOnce() -> T) -> T {
        let _guard = set_key(value);
        f()
    }

    /// Set `GITLAWB_KEY` (or remove it, for `None`) until the guard drops.
    pub(crate) fn set_key<V: AsRef<OsStr>>(value: Option<V>) -> KeyEnv {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let restore = std::env::var_os("GITLAWB_KEY");
        match value {
            Some(v) => std::env::set_var("GITLAWB_KEY", v),
            None => std::env::remove_var("GITLAWB_KEY"),
        }
        KeyEnv {
            _guard: guard,
            restore,
        }
    }
}

#[cfg(test)]
mod gitlawb_dir_tests {
    use super::{gitlawb_dir, load_keypair_from_dir};
    use std::ffi::OsString;
    use std::path::PathBuf;

    /// Run `f` with `GITLAWB_KEY` set to `value` (or removed for `None`), restoring
    /// whatever was there before.
    fn with_key_env<T>(value: Option<OsString>, f: impl FnOnce() -> T) -> T {
        let _env = crate::identity::test_env::set_key(value);
        f()
    }

    /// An explicit --dir always wins and is never validated against GITLAWB_KEY.
    #[test]
    fn explicit_override_wins() {
        let d = PathBuf::from("/tmp/explicit");
        assert_eq!(gitlawb_dir(Some(d.clone())).unwrap(), d);
    }

    /// A relative GITLAWB_KEY must fail loudly. `gl` and `git-remote-gitlawb` run
    /// from different working directories, so resolving one relatively sends the
    /// import and the lookup to different stores; a one-component value yields an
    /// empty parent and puts the store in `./delegations`.
    #[test]
    fn relative_key_paths_are_refused() {
        for raw in ["identity.pem", "keys/identity.pem"] {
            let result = with_key_env(Some(OsString::from(raw)), || gitlawb_dir(None));
            assert!(result.is_err(), "{raw} is relative and must be refused");
        }
    }

    /// An empty value is what a shell leaves behind for `FOO=` and for an unset
    /// variable expanded into a wrapper script. Treated as unset, not as an error.
    #[test]
    fn an_empty_key_path_is_treated_as_unset() {
        let result = with_key_env(Some(OsString::new()), || gitlawb_dir(None));
        assert_eq!(
            result.unwrap(),
            dirs::home_dir().unwrap().join(".gitlawb"),
            "an empty value selects the default directory"
        );
    }

    /// The reason `gitlawb_dir` reads through `var_os`: `env::var` folds a non-UTF-8
    /// value into the same `Err` as unset, so a bad path would silently resolve to
    /// `~/.gitlawb` instead of being reported. Byte 0xFF is not valid UTF-8 in any
    /// position, so this value is unreachable through `env::var`.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_key_path_is_not_mistaken_for_unset() {
        use std::os::unix::ffi::OsStringExt;

        let raw = OsString::from_vec(b"keys/\xFF/identity.pem".to_vec());
        let result = with_key_env(Some(raw), || gitlawb_dir(None));

        let err = result.expect_err("a non-UTF-8 relative path must be refused");
        assert!(
            err.to_string().contains("absolute"),
            "the error must name the real problem, not fall back to the default: {err}"
        );

        let mut absolute = OsString::from("/data/");
        absolute.push(OsString::from_vec(vec![0xFF]));
        absolute.push("/identity.pem");
        let resolved = with_key_env(Some(absolute.clone()), || gitlawb_dir(None)).unwrap();
        assert_eq!(
            resolved,
            PathBuf::from(&absolute).parent().unwrap(),
            "an absolute non-UTF-8 path resolves to its own parent, not to ~/.gitlawb"
        );
    }

    /// `gl identity new` writes the key wherever `GITLAWB_KEY` points, so every
    /// other command has to read it back from there. `load_keypair_from_dir(None)`
    /// used to hardcode `~/.gitlawb`, which made `gl ucan delegate` sign with a
    /// stale DID — or fail outright — for exactly the operators who moved the key.
    #[test]
    fn load_keypair_from_dir_honours_the_key_env() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("identity.pem");
        let expected = gitlawb_core::identity::Keypair::generate();
        std::fs::write(&key, expected.to_pem().unwrap()).unwrap();

        let loaded = with_key_env(Some(key.into_os_string()), || load_keypair_from_dir(None))
            .expect("the identity beside GITLAWB_KEY must be found");

        assert_eq!(loaded.did(), expected.did());
    }
}

#[cfg(test)]
mod key_basename_tests {
    use super::*;

    /// `GITLAWB_KEY` names a FILE. `gl` used to keep only its parent and re-append
    /// `identity.pem`, while `git-remote-gitlawb` opened the configured path — so
    /// with `GITLAWB_KEY=/data/keys/ci-agent.pem` the CLI and the push path loaded
    /// different files, and owner enforcement and the delegation proof both key off
    /// whichever identity that was.
    #[test]
    fn a_non_default_key_basename_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("ci-agent.pem");
        let expected = gitlawb_core::identity::Keypair::generate();
        std::fs::write(&key, expected.to_pem().unwrap()).unwrap();

        let (resolved, loaded) = crate::identity::test_env::with_key(Some(key.clone()), || {
            (key_path_for(None).unwrap(), load_keypair_from_dir(None))
        });

        assert_eq!(resolved, key, "the configured basename must survive");
        assert_eq!(
            loaded.expect("the key at GITLAWB_KEY must load").did(),
            expected.did(),
            "gl must load the same file the helper opens"
        );
    }

    /// An explicit --dir keeps the conventional layout.
    #[test]
    fn an_explicit_dir_still_uses_identity_pem() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            key_path_for(Some(dir.path())).unwrap(),
            dir.path().join("identity.pem")
        );
    }
}

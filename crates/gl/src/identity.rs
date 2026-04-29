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
        /// Output directory for key files (default: ~/.gitlawb)
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

fn gitlawb_dir(override_dir: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(d) = override_dir {
        return Ok(d);
    }
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".gitlawb"))
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join("identity.pem")
}

fn load_keypair(dir: Option<PathBuf>) -> Result<Keypair> {
    load_keypair_from_dir(dir.as_deref())
}

/// Load keypair from an optional directory override.
/// Used by other modules (register, repo, mcp).
pub fn load_keypair_from_dir(dir: Option<&std::path::Path>) -> Result<Keypair> {
    let base = if let Some(d) = dir {
        d.to_path_buf()
    } else {
        dirs::home_dir()
            .context("could not determine home directory")?
            .join(".gitlawb")
    };
    let path = key_path(&base);
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
    let dir = gitlawb_dir(dir)?;
    let path = key_path(&dir);

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
    let base = gitlawb_dir(dir)?;
    let src = key_path(&base);

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

    let base = gitlawb_dir(dir)?;
    let dest = key_path(&base);

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

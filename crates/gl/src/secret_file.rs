//! Writes and directories that hold key material or bearer tokens.

use std::io::Write;
use std::path::Path;

/// Write `contents` to `path` with owner-only permissions.
///
/// On unix the mode is pinned at creation, so the file never exists with a
/// permissive mode between open and chmod. `O_NOFOLLOW` refuses to write
/// through a pre-planted symlink. `mode()` applies only when the file is
/// created, so the mode is pinned on the descriptor before the file is
/// truncated: a pre-existing loose file is tightened before, not after, the
/// new contents land in it.
pub(crate) fn write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.set_len(0)?;
        f.write_all(contents)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, contents)?;
    Ok(())
}

/// Write `contents` to a `path` that must not already exist.
///
/// `create_new` makes the existence check and the create one atomic open, so
/// there is no check-then-write window where an attacker or a second `gl init`
/// could slip a file in between. Same owner-only mode and `O_NOFOLLOW` as
/// [`write`]. `AlreadyExists` means the key was present, never that it was
/// touched.
pub(crate) fn write_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        f.write_all(contents)?;
    }
    #[cfg(not(unix))]
    {
        if path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "refusing to overwrite existing file",
            ));
        }
        std::fs::write(path, contents)?;
    }
    Ok(())
}

/// Create `path` (and missing parents) as an owner-only directory.
///
/// An existing directory is also re-pinned: a `~/.gitlawb` created before
/// this helper stays group- and world-listable otherwise. A symlinked
/// `path` is left alone rather than chmodded through, which would strip
/// group and world access from whatever the link points at.
pub(crate) fn create_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        // Re-pin through the opened directory, not the path: O_NOFOLLOW
        // refuses a swapped-in symlink and fchmod acts on the checked inode,
        // so a final-component swap between check and chmod cannot retarget
        // the mode change at whatever the link points at.
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(dir) => {
                use std::os::unix::io::AsRawFd;
                let fd = dir.as_raw_fd();
                // Re-pin only a leaf this process owns. A --dir the caller
                // can write but cannot chmod (foreign-owned 0775 leaf, ACL
                // grant) is adopted unchanged: create_dir_all allowed the
                // write before, and aborting turns a usable directory into
                // a command failure. An owned directory that still refuses
                // chmod (EPERM) is adopted the same way.
                let owned = unsafe {
                    let mut st: libc::stat = std::mem::zeroed();
                    libc::fstat(fd, &mut st) == 0 && st.st_uid == libc::geteuid()
                };
                if owned && unsafe { libc::fchmod(fd, 0o700) } != 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() != Some(libc::EPERM) {
                        return Err(e);
                    }
                }
            }
            // ELOOP: the path is a symlink and is left alone per contract.
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {}
            Err(e) => return Err(e),
        }
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    #[test]
    #[cfg(unix)]
    fn create_dir_adopts_writable_leaf_it_cannot_chmod() {
        use std::os::unix::fs::PermissionsExt;
        // /tmp is root-owned 1777: writable by this euid, not chmod-able.
        // The pre-helper create_dir_all allowed the write; the re-pin must
        // adopt the leaf unchanged rather than abort on EPERM.
        let before = std::fs::metadata("/tmp").unwrap().permissions().mode();
        super::create_dir(std::path::Path::new("/tmp")).unwrap();
        let after = std::fs::metadata("/tmp").unwrap().permissions().mode();
        assert_eq!(before, after);
    }

    #[test]
    #[cfg(unix)]
    fn write_creates_file_with_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("key.pem");
        super::write(&path, b"secret").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_tightens_preexisting_loose_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        super::write(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_refuses_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.pem");
        std::fs::write(&target, b"planted").unwrap();
        let link = dir.path().join("link.pem");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(super::write(&link, b"secret").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"planted");
    }

    #[test]
    #[cfg(unix)]
    fn create_dir_modes_0700_and_tightens_existing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a").join("b");
        super::create_dir(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        super::create_dir(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    #[cfg(unix)]
    fn create_dir_does_not_chmod_through_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("shared");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        super::create_dir(&link).unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}

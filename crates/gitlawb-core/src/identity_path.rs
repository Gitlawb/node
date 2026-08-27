//! Where the identity key and the delegation store live.
//!
//! `gl` and `git-remote-gitlawb` have to agree on this. `gl ucan import` writes a
//! delegation to `<dir>/delegations/`, and the helper reads it back from the same
//! place when it builds the `X-Ucan` header on push. If the two resolve
//! `GITLAWB_KEY` differently the push goes out with no header and the node refuses
//! the delegate, with nothing on either side to say why — so the rules live here
//! once, in the crate both binaries already depend on, rather than being written
//! twice and drifting.
//!
//! The home directory is a parameter rather than something this module looks up.
//! `gitlawb-core` is embedded by every consumer and is held to an explicit
//! dependency allowlist (`ci/gitlawb-core-allowed-deps.txt`); the callers already
//! carry `dirs`, so taking `home` keeps the rules shared without widening core's
//! tree. It also makes every case below testable against a fixed home.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use crate::{Error, Result};

/// Environment variable naming the identity PEM.
pub const KEY_ENV: &str = "GITLAWB_KEY";

/// Name of the PEM file inside the identity directory.
pub const KEY_FILE_NAME: &str = "identity.pem";

/// Directory under the home directory used when `GITLAWB_KEY` is unset.
pub const DEFAULT_DIR_NAME: &str = ".gitlawb";

/// Absolute path of the identity PEM: `$GITLAWB_KEY`, else
/// `<home>/.gitlawb/identity.pem`.
///
/// An empty `GITLAWB_KEY` counts as unset. That is what a shell leaves behind for
/// `FOO=` and for an unset variable expanded into a wrapper script, and reading it
/// as a path would resolve against the process working directory instead.
pub fn identity_key_path(home: Option<&Path>) -> Result<PathBuf> {
    // `var_os`, not `var`: `var` folds a non-UTF-8 value into the same `Err` as
    // unset, so an operator whose key path is not valid UTF-8 would silently get
    // the default directory rather than theirs — or an error naming the real
    // problem.
    match std::env::var_os(KEY_ENV) {
        Some(raw) if !raw.is_empty() => resolve_key_value(Path::new(&raw), home),
        _ => Ok(require_home(home)?
            .join(DEFAULT_DIR_NAME)
            .join(KEY_FILE_NAME)),
    }
}

/// The directory holding `identity.pem` and `delegations/` — the parent of
/// [`identity_key_path`].
pub fn identity_dir(home: Option<&Path>) -> Result<PathBuf> {
    let key = identity_key_path(home)?;
    key.parent().map(Path::to_path_buf).ok_or_else(|| {
        Error::Key(format!(
            "{KEY_ENV} has no parent directory: {}",
            key.display()
        ))
    })
}

/// The home directory, demanded only where the value being resolved needs it.
///
/// An absolute `GITLAWB_KEY` never needs home, so requiring it up front would
/// discard a perfectly good key on a host where `dirs::home_dir()` returns `None`
/// — no `HOME` and no passwd entry, which is an ordinary container shape. The
/// helper would then push unsigned, blaming the home directory for a setting the
/// operator had configured correctly.
fn require_home(home: Option<&Path>) -> Result<&Path> {
    home.ok_or_else(|| {
        Error::Key(format!(
            "could not determine the home directory, which is needed to resolve this \
             {KEY_ENV} value. Set {KEY_ENV} to an absolute path to avoid needing it."
        ))
    })
}

/// Apply the `GITLAWB_KEY` rules to a raw value.
///
/// Split out from [`identity_key_path`] so the rules can be tested without setting
/// a process-global environment variable, which would make the tests race.
fn resolve_key_value(raw: &Path, home: Option<&Path>) -> Result<PathBuf> {
    let path = expand_tilde(raw, home)?;

    if !path.is_absolute() {
        return Err(Error::Key(format!(
            "{KEY_ENV} must be an absolute path (got {}). It also determines where \
             delegations are stored, and `gl` and `git-remote-gitlawb` do not share a \
             working directory, so a relative path sends them to different stores.",
            raw.display()
        )));
    }
    if path.parent().is_none() {
        return Err(Error::Key(format!(
            "{KEY_ENV} must name the key file, not the filesystem root (got {}). \
             Point it at the PEM, e.g. ~/{DEFAULT_DIR_NAME}/{KEY_FILE_NAME}.",
            raw.display()
        )));
    }
    Ok(path)
}

/// Expand a leading `~/`, and only that.
///
/// `~user` is shell syntax this does not implement; leaving its `~` in place makes
/// it fail the absolute-path check with a message that names the real problem,
/// which beats resolving it somewhere the operator did not ask for. A bare `~` or
/// `~/` is refused outright: it names a directory where a file is required, and
/// expanding it to the home directory would put the delegation store beside the
/// home directory rather than inside it, since the store is the key's *parent*.
///
/// Matched on the first path component rather than on a string prefix. That is
/// what lets the value stay an `OsStr` end to end: the helper's old
/// `str::strip_prefix("~/")` needed a `String` first, which is why it reached for
/// `env::var` and folded every non-UTF-8 path into "unset".
fn expand_tilde(path: &Path, home: Option<&Path>) -> Result<PathBuf> {
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(first)) if first == OsStr::new("~") => {
            let rest = components.as_path();
            if rest.as_os_str().is_empty() {
                return Err(Error::Key(format!(
                    "{KEY_ENV} must name the key file, not a directory (got {}). \
                     Point it at the PEM, e.g. ~/{DEFAULT_DIR_NAME}/{KEY_FILE_NAME}.",
                    path.display()
                )));
            }
            Ok(require_home(home)?.join(rest))
        }
        _ => Ok(path.to_path_buf()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A home that is absolute on the host running the tests. `/home/op` is not
    /// absolute on Windows — it has a root but no prefix — so a shared literal
    /// would make the absolute-path assertions test the wrong thing there.
    fn home() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\Users\op")
        } else {
            PathBuf::from("/home/op")
        }
    }

    #[test]
    fn absolute_value_is_taken_verbatim() {
        let raw = home().join("data").join("keys").join(KEY_FILE_NAME);
        assert_eq!(resolve_key_value(&raw, Some(&home())).unwrap(), raw);
    }

    #[test]
    fn tilde_slash_expands_to_the_home_directory() {
        let resolved = resolve_key_value(Path::new("~/keys/identity.pem"), Some(&home())).unwrap();
        assert_eq!(resolved, home().join("keys").join(KEY_FILE_NAME));
    }

    /// The shell-style spelling of the default resolves to the default. Worth
    /// pinning: this is the form an operator gets by copying a path out of their
    /// shell, and the two binaries used to reach it by different routes.
    #[test]
    fn the_tilde_spelling_of_the_default_resolves_to_the_default() {
        let resolved =
            resolve_key_value(Path::new("~/.gitlawb/identity.pem"), Some(&home())).unwrap();
        assert_eq!(resolved, home().join(DEFAULT_DIR_NAME).join(KEY_FILE_NAME));
    }

    /// A relative value resolves against the working directory, and `gl` and
    /// `git-remote-gitlawb` do not share one: the import would land where the helper
    /// never looks.
    #[test]
    fn relative_values_are_refused() {
        for raw in ["identity.pem", "keys/identity.pem", "./keys/identity.pem"] {
            assert!(
                resolve_key_value(Path::new(raw), Some(&home())).is_err(),
                "{raw} is relative and must be refused"
            );
        }
    }

    /// `~user` is shell syntax, not a path, and a bare `~` names a directory where
    /// a file is required. Refused rather than guessed at.
    #[test]
    fn unsupported_tilde_forms_are_refused() {
        for raw in ["~", "~/", "~someone/keys/identity.pem"] {
            assert!(
                resolve_key_value(Path::new(raw), Some(&home())).is_err(),
                "{raw} must be refused rather than resolved"
            );
        }
    }

    /// The root has no parent, so the delegation store would have nowhere to go.
    #[test]
    fn the_filesystem_root_is_refused() {
        assert!(resolve_key_value(Path::new("/"), Some(&home())).is_err());
    }

    /// The whole point of `var_os`: a non-UTF-8 value must reach the rules rather
    /// than being folded into "unset" by `var`. Byte 0xFF is not valid UTF-8 in any
    /// position, so this value is unreachable through `env::var`.
    #[cfg(unix)]
    #[test]
    fn non_utf8_values_reach_the_rules() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let relative = OsString::from_vec(b"keys/\xFF/identity.pem".to_vec());
        assert!(
            resolve_key_value(Path::new(&relative), Some(&home())).is_err(),
            "a non-UTF-8 relative path must be refused, not silently defaulted"
        );

        let mut absolute = OsString::from("/data/");
        absolute.push(OsString::from_vec(vec![0xFF]));
        absolute.push("/identity.pem");
        let resolved = resolve_key_value(Path::new(&absolute), Some(&home())).unwrap();
        assert_eq!(resolved.as_os_str(), absolute.as_os_str());
    }

    /// Unset and empty both mean "use the default", and the two accessors must stay
    /// consistent: the directory is the parent of the key, never a sibling of it.
    /// The process environment is global, so the two cases share one test and one
    /// lock rather than racing each other.
    #[test]
    fn unset_and_empty_both_select_the_default_directory() {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let restore = std::env::var_os(KEY_ENV);

        std::env::remove_var(KEY_ENV);
        let unset = (
            identity_key_path(Some(&home())),
            identity_dir(Some(&home())),
        );
        std::env::set_var(KEY_ENV, "");
        let empty = (
            identity_key_path(Some(&home())),
            identity_dir(Some(&home())),
        );

        match restore {
            Some(v) => std::env::set_var(KEY_ENV, v),
            None => std::env::remove_var(KEY_ENV),
        }

        for (label, (key, dir)) in [("unset", unset), ("empty", empty)] {
            assert_eq!(
                key.unwrap(),
                home().join(DEFAULT_DIR_NAME).join(KEY_FILE_NAME),
                "{label} key path"
            );
            assert_eq!(
                dir.unwrap(),
                home().join(DEFAULT_DIR_NAME),
                "{label} directory"
            );
        }
    }
}

#[cfg(test)]
mod no_home_tests {
    use super::*;

    /// An absolute key needs no home directory. Demanding one up front discarded a
    /// correctly-configured `GITLAWB_KEY` on any host where `dirs::home_dir()`
    /// returns `None` — no `HOME` and no passwd entry, an ordinary container shape —
    /// and the helper then pushed unsigned while blaming the home directory.
    #[test]
    fn an_absolute_key_resolves_without_a_home_directory() {
        let raw = if cfg!(windows) {
            r"C:\data\keys\identity.pem"
        } else {
            "/data/keys/identity.pem"
        };
        let resolved = resolve_key_value(Path::new(raw), None)
            .expect("an absolute key must not need a home directory");
        assert_eq!(resolved, PathBuf::from(raw));
        assert_eq!(resolved.parent().unwrap(), Path::new(raw).parent().unwrap());
    }

    /// The forms that genuinely need a home still say so, rather than resolving
    /// somewhere arbitrary.
    #[test]
    fn the_forms_that_need_a_home_report_its_absence() {
        let err = resolve_key_value(Path::new("~/keys/identity.pem"), None)
            .expect_err("a ~/ path cannot resolve without a home directory");
        assert!(
            err.to_string().contains("home directory"),
            "the error must name the missing home directory, got: {err}"
        );
    }
}

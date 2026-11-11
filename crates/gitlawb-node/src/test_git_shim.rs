//! Native Git fixtures shared by timing tests on Unix and Windows.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The fixture delays or hangs in its own process, so the production watchdog
/// can terminate it without depending on a shell or descendant process support.
pub(super) enum Behavior<'a> {
    Delay(u64),
    Hang,
    HangOid(&'a str),
    HangRepo(&'a str),
    LogTypes(&'a Path),
}

pub(super) struct GitShim {
    _directory: tempfile::TempDir,
    executable: PathBuf,
}

impl Deref for GitShim {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.executable
    }
}

pub(super) fn create(name: &str, behavior: Behavior<'_>) -> GitShim {
    static COMPILED: OnceLock<tempfile::TempDir> = OnceLock::new();
    let compiled = COMPILED.get_or_init(|| {
        let directory = tempfile::tempdir().expect("native Git fixture directory");
        let source = directory.path().join("git_shim.rs");
        std::fs::write(&source, include_str!("../tests/fixtures/git_shim.rs"))
            .expect("write native Git fixture source");
        let executable = directory
            .path()
            .join(format!("git-shim{}", std::env::consts::EXE_SUFFIX));
        let output =
            std::process::Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
                .arg("--edition=2021")
                .arg("-Dwarnings")
                .arg(&source)
                .arg("-o")
                .arg(executable)
                .output()
                .expect("compile native Git fixture with the installed Rust toolchain");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        directory
    });
    let directory = tempfile::Builder::new()
        .prefix(name)
        .tempdir()
        .expect("Git fixture instance");
    let file_name = format!("git-shim{}", std::env::consts::EXE_SUFFIX);
    let executable = directory.path().join(&file_name);
    std::fs::copy(compiled.path().join(file_name), &executable).expect("copy native Git fixture");
    let config = match behavior {
        Behavior::Delay(milliseconds) => format!("delay\n{milliseconds}"),
        Behavior::Hang => "hang\n".to_owned(),
        Behavior::HangOid(oid) => format!("hang-oid\n{oid}"),
        Behavior::HangRepo(repo) => format!("hang-repo\n{repo}"),
        Behavior::LogTypes(path) => format!("log-types\n{}", path.display()),
    };
    std::fs::write(directory.path().join("config"), config).expect("configure native Git fixture");
    GitShim {
        _directory: directory,
        executable,
    }
}

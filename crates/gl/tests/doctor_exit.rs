//! #357: pin the `gl doctor` exit-code wiring, not just the predicate.
//!
//! The unit tests for `has_failures` never touch `std::process::exit(1)` or
//! the `GITLAWB_NODE` Warn tier. Deleting the exit gate outright kept
//! `cargo test -p gl doctor::` green, so this binary probe is the only thing
//! that breaks when the wiring is gutted.

use std::process::Command;

#[test]
fn doctor_exits_nonzero_when_fail_rows_present() {
    let dir = tempfile::tempdir().expect("temp dir");
    // Use an unroutable node so the "node unreachable" check is Fail-class.
    // The temp dir has no identity.pem / ucan.json, so identity + registration
    // are also Fail — at least one Fail must flip the process to exit 1.
    let bin = env!("CARGO_BIN_EXE_gl");
    let output = Command::new(bin)
        .args([
            "doctor",
            "--dir",
            dir.path().to_str().unwrap(),
            "--node",
            "http://127.0.0.1:1",
        ])
        // Inherit PATH but neutralize GITLAWB_NODE so the test is deterministic
        // across machines that have it set (otherwise it would be Pass).
        .env_remove("GITLAWB_NODE")
        // iCaptcha probes a real URL by default; keep it unreachable too so
        // it stays Warn and does not affect the Fail gating.
        .env("GITLAWB_ICAPTCHA_URL", "http://127.0.0.1:1")
        .output()
        .expect("run gl doctor");

    // The command should have exited 1 because at least one Fail row exists.
    // If the `std::process::exit(1)` gate is removed, this becomes 0 and the
    // test fails — that is the regression it pins.
    assert!(
        !output.status.success(),
        "gl doctor must exit non-zero when Fail rows are present; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "exit code must be 1, not some other non-zero"
    );
}

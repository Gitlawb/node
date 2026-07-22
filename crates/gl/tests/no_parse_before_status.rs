//! INV-21 completeness gate for #186.
//!
//! The client handlers converted in #186 must read node responses through
//! `crate::http::read_json` — status-first, capped error read, sanitized message.
//! The bypass this fix removed is *parse-before-status*: a `resp.json().await`
//! whose result is only checked against the status AFTER parsing, which lets a
//! hostile node stream an unbounded JSON error and print its `message` unsanitized.
//!
//! This test scans the converted source files and fails if that idiom returns —
//! a `.json().await` call (not `read_json`) with an `.is_success()` check within a
//! few lines AFTER it. A status check BEFORE the parse (the `KEEP` probes in
//! repo.rs) reads as status-first and is not flagged. If a converted site is
//! reverted to the bypass, this goes RED.
//!
//! The gate does not hand-list the files to scan; it DERIVES them: every
//! `src/*.rs` that references `read_json` (except `http.rs`, where it is defined)
//! is a converted handler and is scanned for the bypass idiom.
//!
//! Derivation alone has a blind spot: it keys on the very `read_json` marker a
//! full revert deletes. A converted handler with a single node call (register.rs)
//! reverted to `resp.json().await` loses `read_json` entirely, drops out of the
//! derived set, and its bypass goes unscanned. So `CONVERTED_IN_186` is the
//! authoritative required set and the gate asserts the derived surface EQUALS it,
//! failing closed in both directions:
//!
//! - a pinned file missing from the derived set was reverted off `read_json`
//!   (the blind-spot escape), so the gate goes RED;
//! - a file that uses `read_json` but is not pinned is a conversion that was
//!   never enrolled, so its own later revert would escape unseen; RED until it
//!   is added to the pin.
//!
//! Equality is what extends the protection to handlers converted after #186, not
//! just the original sixteen: a conversion cannot ship unpinned, and a pinned
//! surface cannot be deconverted silently.
//!
//! Pre-existing bypasses in files this PR did not convert (e.g. init.rs,
//! mirror.rs, profile.rs) are known debt, tracked separately and out of scope.
//! They do not use `read_json`, so the derivation excludes them and they are not
//! pinned.

use std::path::Path;

/// Files that define/host `read_json` rather than consume it as a converted
/// handler. Excluded from the scanned set even though they reference the symbol.
const NOT_A_HANDLER: &[&str] = &["http.rs"];

/// The authoritative converted-handler surface: every non-`http.rs` file whose
/// node-response reads route through `read_json`. The gate asserts the derived
/// `read_json` set EQUALS this exactly, so a new conversion must be added here
/// (the gate is RED until it is) and a pinned surface cannot be reverted off
/// `read_json` without tripping the gate. Both directions fail closed, which is
/// what protects post-#186 conversions, not only the original sixteen.
const CONVERTED_IN_186: &[&str] = &[
    "agent.rs",
    "bounty.rs",
    "cert.rs",
    "changelog.rs",
    "issue.rs",
    "mcp.rs",
    "peer.rs",
    "pr.rs",
    "protect.rs",
    "register.rs",
    "repo.rs",
    "star.rs",
    "sync.rs",
    "task.rs",
    "visibility.rs",
    "webhook.rs",
];

/// Derive the converted-handler surface: every `src/*.rs` that references
/// `read_json`, minus the definition site(s). This is the set the equality check
/// compares against `CONVERTED_IN_186`; a newly-converted handler surfaces here
/// and must then be pinned (the gate is RED until it is).
fn scanned_handlers(src: &Path) -> Vec<(String, String)> {
    let mut handlers = Vec::new();
    for entry in std::fs::read_dir(src).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("file name")
            .to_string();
        if NOT_A_HANDLER.contains(&file_name.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        if text.contains("read_json") {
            handlers.push((file_name, text));
        }
    }
    handlers.sort();
    handlers
}

/// Does `line` open a JSON parse — `.json().await`, or a turbofish
/// `.json::<T>().await`, or the head of a split-line chain (`.json(` /
/// `.json::<T>(` whose `()` / `.await` continue on following lines)?
///
/// Lines routed through `read_json` are never parse sites (that IS the fix).
fn opens_json_parse(line: &str) -> bool {
    if line.contains("read_json") {
        return false;
    }
    // A `.json(` token starts every reqwest JSON parse, bare or turbofished,
    // single- or split-line. We anchor on it and let the window below confirm
    // the `.await` / status check; anchoring on `.json(` alone is what catches
    // `resp.json::<Value>().await` and `resp\n    .json()\n    .await` chains
    // that the old bare-`.json().await` substring missed.
    line.contains(".json()") || line.contains(".json::<")
}

/// Within `window` (the parse-site line joined with the few lines after it), is
/// the parse actually completed with `.await` and then checked against the
/// status? A completed parse whose `.is_success()` lands AFTER it is the
/// parse-before-status bypass. A status check BEFORE the parse (KEEP probes)
/// never appears in this after-the-parse window, so it is not flagged.
fn window_is_bypass(window: &str) -> bool {
    // The parse must actually resolve — guards against matching a `.json`-shaped
    // token that never awaits. Split-line chains put `.await` a line or two down,
    // which the joined window still contains.
    let completes = window.contains(".await");
    completes && window.contains(".is_success()")
}

#[test]
fn converted_handlers_never_parse_before_status() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let handlers = scanned_handlers(&src);

    // Deriving the set is the whole point of the fix; if the tree ever stops
    // using `read_json` the gate would silently pass on an empty set.
    assert!(
        !handlers.is_empty(),
        "derived no converted handlers from src/*.rs read_json usage — the gate \
         would vacuously pass; check the derivation"
    );

    // The pin is the authoritative required set: the derived `read_json` surface
    // must EQUAL it, failing closed in both directions. A pinned file that drops
    // out was reverted off `read_json` (register.rs, its single call, is the
    // motivating case) and its bypass would escape the derived scan. A derived
    // file that is not pinned is a conversion nobody enrolled, so ITS later revert
    // would escape the same way; force it into the pin now. Equality is what
    // extends the protection to handlers converted after #186.
    let derived: Vec<&str> = handlers.iter().map(|(n, _)| n.as_str()).collect();
    let deconverted: Vec<&str> = CONVERTED_IN_186
        .iter()
        .copied()
        .filter(|f| !derived.contains(f))
        .collect();
    assert!(
        deconverted.is_empty(),
        "pinned handler(s) no longer route node responses through read_json: a \
         parse-before-status revert would otherwise escape the derived scan. \
         Re-route through crate::http::read_json (or drop from CONVERTED_IN_186 if \
         the surface was intentionally deconverted): {deconverted:?}"
    );
    let unpinned: Vec<&str> = derived
        .iter()
        .copied()
        .filter(|f| !CONVERTED_IN_186.contains(f))
        .collect();
    assert!(
        unpinned.is_empty(),
        "handler(s) use read_json but are absent from CONVERTED_IN_186: add them so \
         the gate protects them against a later parse-before-status revert (an \
         unpinned conversion drops out of both the scan and this check when \
         reverted): {unpinned:?}"
    );

    let mut offenders = Vec::new();
    for (name, text) in &handlers {
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !opens_json_parse(line) {
                continue;
            }
            // Join the parse-site line with the following lines so a split-line
            // chain's `.await` and an after-the-parse `.is_success()` are both in
            // view. Status-first probes put `.is_success()` on an EARLIER line, so
            // it is outside this window and stays green.
            let window = lines[i..(i + 6).min(lines.len())].join("\n");
            if window_is_bypass(&window) {
                offenders.push(format!("{name}:{}", i + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "parse-before-status bypass present in converted handler(s) — route the read \
         through crate::http::read_json (status-first, capped, sanitized): {offenders:?}"
    );
}

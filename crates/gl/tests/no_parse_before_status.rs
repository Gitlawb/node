//! Completeness gate for #186, itself proven load-bearing by reverting a
//! converted handler and watching this go red.
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
    "status.rs",
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
        if has_read_json_call_site(&text) {
            handlers.push((file_name, text));
        }
    }
    handlers.sort();
    handlers
}

/// Does this file actually CALL `read_json`, as opposed to merely mentioning it?
///
/// Membership in the derived set must key on a call site, never on the text of
/// the file. A textual `contains("read_json")` matched prose too, so a handler
/// fully reverted off `read_json` kept its membership on the strength of a
/// leftover comment ("previously routed through read_json"). Still-derived means
/// the pinned-vs-derived equality below never fired, and the reverted file went
/// on being scanned as though it were converted, so the deconversion — which
/// drops the cap and the sanitizer — shipped green. Requiring the trailing `(`
/// on a non-comment line also drops test names and doc references.
fn has_read_json_call_site(text: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim_start();
        !t.starts_with("//") && t.contains("read_json(")
    })
}

/// How far above a parse site to look for its status check.
///
/// The widest legitimate gap in the tree is `sync.rs`'s hand-rolled status-first
/// `Trigger` arm, whose `.status()` sits 19 lines above its parse; 24 leaves a
/// little headroom. Wider is weaker, so this should shrink if that arm is ever
/// routed through `read_json` like its siblings.
const STATUS_LOOKBACK: usize = 24;

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

/// Is there a FULL non-success guard ABOVE this parse site — one that exits for
/// every non-2xx status, not merely a bespoke branch for one code?
///
/// `window_is_bypass` only recognises a status check that lands AFTER the parse,
/// so it describes one specific bypass and says nothing about a parse with no
/// status check anywhere. That shape is the more dangerous revert (it renders a
/// denial body as a successful result with no check at all). Requiring positive
/// evidence of a guard first turns the rule from "detect one bad ordering" into
/// "require the good ordering".
///
/// The evidence must cover the whole non-success range. "Any `.status()`
/// nearby" is not enough: agent.rs legitimately keeps a 404-only hint
/// (`resp.status() == StatusCode::NOT_FOUND`) ahead of its `read_json` call,
/// and a revert that swaps that call for `resp.json().await?` would still see
/// the 404 check in the lookback — while a 500's JSON denial body renders as an
/// empty agent list again. A single-status equality (or a `matches!(…, 404 |
/// 501)` enumeration) guards its own arm and nothing else, so it does not
/// count. What counts:
///
/// - `.is_success()` — the canonical spelling; sync.rs binds the status to a
///   variable first, so this token is matched on its own rather than as a
///   `.status()` suffix;
/// - a RANGE comparison over `as_u16()` (`>= 400` and friends), which reads the
///   whole class rather than enumerating codes.
///
/// The `special_404_hint_is_not_a_guard` mutation test below keeps this
/// distinction honest against the real agent.rs source.
fn has_full_status_guard_above(lookback: &str) -> bool {
    if lookback.contains(".is_success()") {
        return true;
    }
    lookback.contains("as_u16() >=")
        || lookback.contains("as_u16() >")
        || lookback.contains("as_u16() <=")
        || lookback.contains("as_u16() <")
}

/// The scan shared by the gate and the mutation regression: every raw parse
/// site in `text` is classified as an after-the-parse bypass (`offenders`) or a
/// parse with no full status guard above it (`unguarded`). Factored out so the
/// mutation test exercises EXACTLY the logic the gate runs, not a paraphrase of
/// it.
fn scan_handler(name: &str, text: &str) -> (Vec<String>, Vec<String>) {
    let mut offenders = Vec::new();
    let mut unguarded = Vec::new();
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
            continue;
        }
        // A parse that never resolves is not a read; only a completed parse
        // can render a denial body as a result.
        if !window.contains(".await") {
            continue;
        }
        let lookback = lines[i.saturating_sub(STATUS_LOOKBACK)..i].join("\n");
        if !has_full_status_guard_above(&lookback) {
            unguarded.push(format!("{name}:{}", i + 1));
        }
    }
    (offenders, unguarded)
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
    let mut unguarded = Vec::new();
    for (name, text) in &handlers {
        let (o, u) = scan_handler(name, text);
        offenders.extend(o);
        unguarded.extend(u);
    }

    assert!(
        offenders.is_empty(),
        "parse-before-status bypass present in converted handler(s) — route the read \
         through crate::http::read_json (status-first, capped, sanitized): {offenders:?}"
    );
    assert!(
        unguarded.is_empty(),
        "node response parsed with NO full status guard above it in a converted \
         handler — the denial body is being rendered as a result. Route the read \
         through crate::http::read_json (status-first, capped, sanitized): {unguarded:?}"
    );
}

/// Mutation regression for the special-404 escape: agent.rs (and the agent-show
/// / repo-info paths shaped like it) keeps a legitimate 404-only hint ahead of
/// its `read_json` call. Revert that call to a raw `resp.json().await?` and the
/// 404 equality is the only status evidence in the lookback — under the old
/// "any `.status()` nearby" rule the fence stayed green while a 500's denial
/// body rendered as an empty agent list. This test performs that exact revert
/// on the REAL agent.rs source and requires the scan to flag the mutant, so the
/// full-guard distinction in `has_full_status_guard_above` cannot regress to a
/// mere proximity check without going red here.
#[test]
fn special_404_hint_is_not_a_guard() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let text = std::fs::read_to_string(src.join("agent.rs")).expect("read agent.rs");

    // The mutation must stay real: it requires the idiom it reverts. If
    // agent.rs drops the 404 hint or the read_json call, this needs re-basing
    // on whichever handler carries the special-404 idiom then.
    assert!(
        text.contains("StatusCode::NOT_FOUND"),
        "agent.rs no longer carries the special-404 hint this mutation reverts; \
         re-anchor the mutation on the handler that does"
    );
    let lines: Vec<&str> = text.lines().collect();
    let not_found_line = lines
        .iter()
        .position(|l| l.contains("StatusCode::NOT_FOUND"))
        .unwrap();
    let read_json_line = lines[not_found_line..]
        .iter()
        .position(|l| l.contains("read_json"))
        .map(|off| not_found_line + off)
        .expect(
            "agent.rs has no read_json call after its 404 hint; re-anchor the \
             mutation on the handler that carries the idiom",
        );

    // The revert under test: the guarded helper call becomes a raw parse.
    let mut mutant: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    mutant[read_json_line] = "    let body: serde_json::Value = resp.json().await?;".to_string();
    let mutant = mutant.join("\n");

    let (_, unguarded) = scan_handler("agent.rs[mutant]", &mutant);
    assert!(
        unguarded
            .iter()
            .any(|hit| hit.starts_with("agent.rs[mutant]:")),
        "the special-404 revert was not flagged: a 404-only equality upstream is \
         being accepted as a full status guard, which reopens the escape this \
         mutation pins (expected an unguarded hit, got {unguarded:?})"
    );

    // Positive control: the unmutated file must stay green, or the fence is
    // flagging the legitimate hint rather than the revert.
    let (offenders, unguarded) = scan_handler("agent.rs", &text);
    assert!(
        offenders.is_empty() && unguarded.is_empty(),
        "unmutated agent.rs trips the fence; the guard classifier is wrong, not \
         the handler: offenders={offenders:?} unguarded={unguarded:?}"
    );
}

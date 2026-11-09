//! Text sanitization predicates shared across the workspace.
//!
//! Untrusted peer/remote bytes that reach an operator's terminal (node error
//! bodies, node-advertised strings) must be stripped of BOTH `Cc` control bytes
//! (`char::is_control()`) AND `Cf` bidi/format controls before display: a
//! right-to-left override or directional isolate can visually reorder the line
//! and spoof the text (Trojan Source, CWE-451). This is INV-6.
//!
//! `is_bidi_format` is the single workspace definition of the second half of
//! that obligation. It was split out of `gl`'s local copy so the two terminal
//! sanitizers that shipped with only the `Cc` half (#183) — and any future
//! sanitizer — reuse one audited predicate instead of re-deriving the set.

/// True for the Unicode bidirectional/directional-isolate format characters
/// (the reordering subset of category `Cf`) that can visually reorder a terminal
/// line. These are NOT matched by [`char::is_control()`], which covers `Cc` only.
///
/// This is deliberately the reordering subset, not the whole `Cf` category:
/// legitimate `Cf` characters such as ZWJ (`U+200D`, emoji sequences) and the
/// soft hyphen (`U+00AD`) are NOT matched, so honest international text passes
/// through unchanged. Widening this set is a behavior change for every consumer.
///
/// Pair it with `!c.is_control()` in a terminal-bound sanitizer (INV-6); see the
/// wrappers in `gl`, `git-remote-gitlawb`, and `icaptcha-client`.
pub fn is_bidi_format(c: char) -> bool {
    matches!(c,
        '\u{200E}' | '\u{200F}' | '\u{061C}'   // LRM, RLM, ALM
        | '\u{202A}'..='\u{202E}'              // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}'              // LRI, RLI, FSI, PDI
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_every_reordering_code_point() {
        // Asserted individually so a partial predicate (e.g. one that covers the
        // marks but not the isolates) fails loudly rather than passing.
        for c in [
            '\u{200E}', '\u{200F}', '\u{061C}', // LRM, RLM, ALM
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{202E}', // LRE, RLE, PDF, LRO, RLO
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // LRI, RLI, FSI, PDI
        ] {
            assert!(
                is_bidi_format(c),
                "U+{:04X} must be a bidi-format char",
                c as u32
            );
        }
    }

    #[test]
    fn passes_legitimate_and_control_chars() {
        // Must NOT over-strip: plain text, a genuine RTL SCRIPT letter (Lo, not a
        // format char), ZWJ (legitimate Cf), and soft hyphen (legitimate Cf) are
        // not bidi-format. ESC is a Cc control char — owned by is_control(), not
        // this predicate, which is bidi-only.
        for c in ['a', '\u{0627}', '\u{200D}', '\u{00AD}', '\u{1b}'] {
            assert!(
                !is_bidi_format(c),
                "U+{:04X} must NOT be a bidi-format char",
                c as u32
            );
        }
    }
}

//! Display helpers for strings that come off the wire unchecked.

/// Truncate `s` to at most `max` bytes, cutting at a char boundary.
///
/// `&s[..max]` panics when `s` is shorter than `max` bytes and when `max`
/// lands inside a multi-byte char; `s.len().min(max)` guards only the first
/// case. Node-supplied timestamps and ids hit both.
pub(crate) fn truncate(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Keep at most the last `max` bytes of `s`, cutting at a char boundary.
///
/// `&s[s.len().saturating_sub(max)..]` panics when the start index lands
/// inside a multi-byte char; node-supplied ids hit that case.
pub(crate) fn truncate_suffix(s: &str, max: usize) -> &str {
    let mut start = s.len().saturating_sub(max);
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

#[cfg(test)]
mod tests {
    use super::{truncate, truncate_suffix};

    #[test]
    fn cuts_ascii_at_max() {
        assert_eq!(truncate("2026-08-15T12:34:56Z", 10), "2026-08-15");
    }

    #[test]
    fn short_and_empty_inputs_return_whole() {
        assert_eq!(truncate("2026", 10), "2026");
        assert_eq!(truncate("", 10), "");
    }

    #[test]
    fn multibyte_cut_does_not_panic() {
        // Byte index 10 lands inside 'é'; the cut must land on the boundary
        // before it (9 bytes) rather than panic or exceed the byte limit.
        assert_eq!(truncate("2026-08-1\u{e9}5T12:34:56Z", 10), "2026-08-1");
        // A string that is entirely multi-byte and shorter than max.
        assert_eq!(truncate("\u{e9}\u{e9}", 10), "\u{e9}\u{e9}");
    }

    #[test]
    fn suffix_cut_does_not_panic() {
        // 'é' is two bytes; a start index of len-8 lands inside it.
        assert_eq!(truncate_suffix("did:key:\u{e9}1234567", 8), "1234567");
    }

    #[test]
    fn suffix_short_input_returns_whole() {
        assert_eq!(truncate_suffix("short", 8), "short");
        assert_eq!(truncate_suffix("", 8), "");
    }
}

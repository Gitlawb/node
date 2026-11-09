//! Deterministic solvers for the computational iCaptcha challenge types.
//!
//! Prompt/answer formats mirror the iCaptcha service generators
//! (`icaptcha/src/generators/{arithmetic,algebra,sequence}.ts`). The service
//! grades numerics by value (`Number(a) === Number(b)`), so returning the plain
//! integer string is sufficient. Anagram/logic (need a dictionary/parser) and
//! the LLM types are intentionally NOT solved here — the client requests only
//! these three types and falls back to a hook/interactive prompt otherwise.

/// Solve a challenge of the given `type` from its prompt. Returns `None` for
/// types we don't solve locally or when the prompt can't be parsed.
pub fn solve(challenge_type: &str, prompt: &str) -> Option<String> {
    match challenge_type {
        "arithmetic" => solve_arithmetic(prompt).map(|n| n.to_string()),
        "algebra" => solve_algebra(prompt).map(|n| n.to_string()),
        "sequence" => solve_sequence(prompt).map(|n| n.to_string()),
        _ => None,
    }
}

/// `What is 12 + 7 - 3?` -> evaluate the additive chain left to right.
fn solve_arithmetic(prompt: &str) -> Option<i64> {
    let expr = prompt
        .trim()
        .strip_prefix("What is ")?
        .trim_end_matches('?')
        .trim();
    let mut tokens = expr.split_whitespace();
    let mut acc: i64 = tokens.next()?.parse().ok()?;
    while let Some(op) = tokens.next() {
        let n: i64 = tokens.next()?.parse().ok()?;
        match op {
            "+" => acc = acc.checked_add(n)?,
            "-" => acc = acc.checked_sub(n)?,
            _ => return None,
        }
    }
    Some(acc)
}

/// `Solve for x: 3x + 4 = 19` (and the `=`-both-sides and `a(x + b)` variants).
/// Parses each side into `coeff*x + const`, then x = (cR - cL) / (aL - aR).
fn solve_algebra(prompt: &str) -> Option<i64> {
    let eq = prompt.trim().strip_prefix("Solve for x:")?.trim();
    let (lhs, rhs) = eq.split_once('=')?;
    let (al, cl) = parse_linear(lhs.trim())?;
    let (ar, cr) = parse_linear(rhs.trim())?;
    let denom = al.checked_sub(ar)?;
    if denom == 0 {
        return None;
    }
    let num = cr.checked_sub(cl)?;
    if num.checked_rem(denom)? != 0 {
        return None;
    }
    num.checked_div(denom)
}

/// Parse a linear expression in `x` into `(coeff_of_x, constant)`.
/// Handles `Nx`, `x`, integer constants, and a single `N(x ± M)` product,
/// with `+`/`-` separators (the formats the generator emits).
fn parse_linear(s: &str) -> Option<(i64, i64)> {
    let s = s.trim();
    // Parenthesized product: a(x ± b)  ->  coeff a, const a*(±b).
    if let Some(open) = s.find('(') {
        let a: i64 = s[..open].trim().parse().ok()?;
        let close = s.find(')')?;
        let inner = &s[open + 1..close]; // "x + 4" / "x - 4"
        let mut it = inner.split_whitespace();
        if it.next()? != "x" {
            return None;
        }
        let (coeff_inner, const_inner) = match it.next() {
            None => (1, 0),
            Some(op) => {
                let m: i64 = it.next()?.parse().ok()?;
                match op {
                    "+" => (1, m),
                    "-" => (1, m.checked_neg()?),
                    _ => return None,
                }
            }
        };
        return Some((a.checked_mul(coeff_inner)?, a.checked_mul(const_inner)?));
    }

    // Sum of `±`-separated terms.
    let mut coeff = 0i64;
    let mut konst = 0i64;
    let mut sign = 1i64;
    for tok in s.split_whitespace() {
        match tok {
            "+" => sign = 1,
            "-" => sign = -1,
            t => {
                if let Some(cpart) = t.strip_suffix('x') {
                    let c: i64 = match cpart {
                        "" | "+" => 1,
                        "-" => -1,
                        _ => cpart.parse().ok()?,
                    };
                    coeff = coeff.checked_add(sign.checked_mul(c)?)?;
                } else {
                    let n: i64 = t.parse().ok()?;
                    konst = konst.checked_add(sign.checked_mul(n)?)?;
                }
                sign = 1;
            }
        }
    }
    Some((coeff, konst))
}

/// `What is the next number in this sequence? 2, 4, 6, 8, 10, ?`
fn solve_sequence(prompt: &str) -> Option<i64> {
    let tail = prompt.split_once("sequence?")?.1;
    let nums: Vec<i64> = tail
        .split(',')
        .filter_map(|t| t.trim().parse::<i64>().ok())
        .collect();
    if nums.len() < 3 {
        return None;
    }
    next_in_sequence(&nums)
}

fn next_in_sequence(n: &[i64]) -> Option<i64> {
    let last = *n.last()?;

    // Arithmetic: constant first difference. An overflowing difference means
    // the pattern doesn't fit, not that the answer wraps.
    if let Some(d) = n[1].checked_sub(n[0]) {
        if n.windows(2).all(|w| w[1].checked_sub(w[0]) == Some(d)) {
            return last.checked_add(d);
        }
    }

    // Geometric: constant integer ratio.
    if n.iter().all(|&v| v != 0) && n[1].checked_rem(n[0]) == Some(0) {
        if let Some(r) = n[1].checked_div(n[0]) {
            if r != 0 && n.windows(2).all(|w| w[0].checked_mul(r) == Some(w[1])) {
                return last.checked_mul(r);
            }
        }
    }

    // Fibonacci-like: each term is the sum of the two before it.
    if n.len() >= 3 && (2..n.len()).all(|i| n[i - 1].checked_add(n[i - 2]) == Some(n[i])) {
        return n[n.len() - 1].checked_add(n[n.len() - 2]);
    }

    // Squares: all perfect squares with consecutive roots.
    let roots: Option<Vec<i64>> = n.iter().map(|&v| isqrt_exact(v)).collect();
    if let Some(roots) = roots {
        if roots.windows(2).all(|w| w[1] == w[0] + 1) {
            let nr = roots[roots.len() - 1] + 1;
            return nr.checked_mul(nr);
        }
    }

    // Alternating sign over an arithmetic magnitude (generator starts positive).
    let signs_alternate = n
        .iter()
        .enumerate()
        .all(|(i, &v)| if i % 2 == 0 { v >= 0 } else { v < 0 });
    let mags: Option<Vec<i64>> = n.iter().map(|v| v.checked_abs()).collect();
    if signs_alternate {
        if let Some(mags) = mags {
            if let Some(md) = mags[1].checked_sub(mags[0]) {
                if mags.windows(2).all(|w| w[1].checked_sub(w[0]) == Some(md)) {
                    let next_sign: i64 = if last >= 0 { -1 } else { 1 };
                    return next_sign.checked_mul(mags[mags.len() - 1].checked_add(md)?);
                }
            }
        }
    }

    None
}

/// Exact integer square root, or `None` if `v` isn't a perfect square.
fn isqrt_exact(v: i64) -> Option<i64> {
    if v < 0 {
        return None;
    }
    let r = (v as f64).sqrt().round() as i64;
    [r - 1, r, r + 1]
        .into_iter()
        .find(|&cand| cand >= 0 && cand.checked_mul(cand) == Some(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_chains() {
        assert_eq!(
            solve("arithmetic", "What is 12 + 7 - 3?").as_deref(),
            Some("16")
        );
        assert_eq!(solve("arithmetic", "What is 5?").as_deref(), Some("5"));
        assert_eq!(
            solve("arithmetic", "What is 100 - 40 - 35 + 2?").as_deref(),
            Some("27")
        );
    }

    #[test]
    fn algebra_linear() {
        assert_eq!(
            solve("algebra", "Solve for x: 3x + 4 = 19").as_deref(),
            Some("5")
        );
        assert_eq!(
            solve("algebra", "Solve for x: 5x - 8 = 12").as_deref(),
            Some("4")
        );
        // both sides: 2x + 16 = 5x - 8  -> 3x = 24 -> x=8
        assert_eq!(
            solve("algebra", "Solve for x: 2x + 16 = 5x - 8").as_deref(),
            Some("8")
        );
        // parenthesized: 3(x - 4) = 9 -> x-4=3 -> x=7
        assert_eq!(
            solve("algebra", "Solve for x: 3(x - 4) = 9").as_deref(),
            Some("7")
        );
        // negative solution: 2x + 10 = 4  -> x=-3
        assert_eq!(
            solve("algebra", "Solve for x: 2x + 10 = 4").as_deref(),
            Some("-3")
        );
    }

    #[test]
    fn sequence_patterns() {
        assert_eq!(
            solve(
                "sequence",
                "What is the next number in this sequence? 2, 4, 6, 8, 10, ?"
            )
            .as_deref(),
            Some("12")
        );
        assert_eq!(
            solve(
                "sequence",
                "What is the next number in this sequence? 3, 6, 12, 24, 48, ?"
            )
            .as_deref(),
            Some("96")
        );
        assert_eq!(
            solve(
                "sequence",
                "What is the next number in this sequence? 1, 4, 9, 16, 25, ?"
            )
            .as_deref(),
            Some("36")
        );
        assert_eq!(
            solve(
                "sequence",
                "What is the next number in this sequence? 1, 1, 2, 3, 5, ?"
            )
            .as_deref(),
            Some("8")
        );
    }

    #[test]
    fn unsupported_types_return_none() {
        assert_eq!(solve("anagram", "Unscramble: tca"), None);
        assert_eq!(solve("riddle", "What has keys but no locks?"), None);
    }

    // #345: prompts are attacker/service-controlled and every literal can be a
    // valid i64 while the evaluation still overflows. Overflow must return
    // None (unsolvable), never a debug panic or a wrapped wrong answer.

    #[test]
    fn arithmetic_overflow_returns_none() {
        assert_eq!(
            solve("arithmetic", "What is 9223372036854775807 + 1?"),
            None
        );
        assert_eq!(
            solve("arithmetic", "What is -9223372036854775808 - 1?"),
            None
        );
        // Boundary-adjacent values still solve.
        assert_eq!(
            solve("arithmetic", "What is 9223372036854775806 + 1?").as_deref(),
            Some("9223372036854775807")
        );
    }

    #[test]
    fn algebra_overflow_returns_none() {
        // num = i64::MIN, denom = -1: the quotient overflows.
        assert_eq!(
            solve("algebra", "Solve for x: x + 1 = 2x + -9223372036854775807"),
            None
        );
        // sign * coefficient overflows at i64::MIN.
        assert_eq!(
            solve("algebra", "Solve for x: x - -9223372036854775808x = 1"),
            None
        );
        // A large but solvable equation still solves.
        assert_eq!(
            solve("algebra", "Solve for x: 4611686018427387904x + 0 = 0").as_deref(),
            Some("0")
        );
    }

    #[test]
    fn sequence_overflow_returns_none() {
        // First difference overflows (1 - i64::MIN).
        assert_eq!(
            solve(
                "sequence",
                "What is the next number in this sequence? -9223372036854775808, 1, 9223372036854775806, ?"
            ),
            None
        );
        // i64::MIN in an alternating-sign candidate: abs() overflows.
        assert_eq!(
            solve(
                "sequence",
                "What is the next number in this sequence? 1, -9223372036854775808, 3, ?"
            ),
            None
        );
        // Perfect-square check near i64::MAX: candidate root squared overflows.
        assert_eq!(
            solve(
                "sequence",
                "What is the next number in this sequence? 9223372036854775807, 9223372036854775800, 9223372036854775801, ?"
            ),
            None
        );
        // Geometric next term overflows (r = 2, last * 2 > i64::MAX).
        assert_eq!(
            solve(
                "sequence",
                "What is the next number in this sequence? 2305843009213693951, 4611686018427387902, 9223372036854775804, ?"
            ),
            None
        );
    }
}

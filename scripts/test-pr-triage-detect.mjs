#!/usr/bin/env node
// Case matrix for the inline-test detector embedded in
// .github/workflows/pr-triage.yml. The workflow runs on pull_request_target
// and deliberately never checks out PR code, so the detector cannot be tested
// where it runs; this script extracts the fenced TRIAGE_DETECTOR block from
// the committed workflow body and exercises it here, where pr-checks.yml DOES
// check out the proposed workflow. If the fence markers move or the block
// stops being self-contained, this script fails loudly rather than testing a
// stale copy.
//
// The matrix encodes the review contract for the detector
// (Gitlawb/node#277): legal Rust separators between the attribute path and
// its ]/( delimiter must be accepted (line comments, nested block comments,
// splits onto immediately following added lines), while unrelated patch
// records - delimiter-looking lines before the path, later in the hunk, or in
// another hunk - must never complete a path they do not adjoin. False
// positives here SUPPRESS the needs-tests label silently (they set
// touchedTests, which clears the label), while false negatives apply it
// (the loud, corrigible direction). So every uncertain path in the detector
// is required to answer "no inline test".

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const workflow = readFileSync(
  join(repoRoot, ".github/workflows/pr-triage.yml"),
  "utf8"
);

const BEGIN = "// TRIAGE_DETECTOR_BEGIN";
const END = "// TRIAGE_DETECTOR_END";
const begin = workflow.indexOf(BEGIN);
const end = workflow.indexOf(END);
if (begin === -1 || end === -1 || end <= begin) {
  console.error("FAIL: TRIAGE_DETECTOR fence not found in pr-triage.yml");
  process.exit(1);
}
const block = workflow.slice(begin + BEGIN.length, end);

let patchAddsInlineTest;
try {
  const factory = new Function(`${block}\nreturn patchAddsInlineTest;`);
  patchAddsInlineTest = factory();
} catch (err) {
  console.error(
    "FAIL: fenced detector block is not self-contained JavaScript:",
    err.message
  );
  process.exit(1);
}

// Each patch is the `patch` field GitHub's listFiles API returns: hunk
// headers plus +/-/space-prefixed lines, no ---/+++ file headers.
const cases = [
  // ── Accepted spellings ────────────────────────────────────────────────
  ["bare same-line", "@@ -1,0 +1,2 @@\n+#[test]\n+fn a() {}", true],
  ["cfg(test)", "@@ -1,0 +1,1 @@\n+#[cfg(test)]", true],
  ["indented with inner space", "@@ -1,0 +1,1 @@\n+    #[ test ]", true],
  [
    "namespaced with args",
    '@@ -1,0 +1,1 @@\n+#[tokio::test(flavor = "multi_thread")]',
    true,
  ],
  ["test_case harness", "@@ -1,0 +1,1 @@\n+#[test_case(1)]", true],
  ["wasm_bindgen_test harness", "@@ -1,0 +1,1 @@\n+#[wasm_bindgen_test]", true],
  ["raw identifier", "@@ -1,0 +1,1 @@\n+#[r#test]", true],
  [
    "line comment then closer on next added line",
    "@@ -1,0 +1,2 @@\n+#[test // rationale\n+]",
    true,
  ],
  [
    "nested block comment, same line",
    "@@ -1,0 +1,1 @@\n+#[test /* outer /* inner */ outer */]",
    true,
  ],
  [
    "block comment spanning added lines",
    "@@ -1,0 +1,3 @@\n+#[test /* why\n+   still why */ ]\n+fn a() {}",
    true,
  ],
  [
    "path-only line, ( on the immediately following added line",
    "@@ -1,0 +1,2 @@\n+#[test_case\n+(1)]",
    true,
  ],
  [
    "whitespace-only continuation before closer",
    "@@ -1,0 +1,3 @@\n+#[test\n+\t\n+]",
    true,
  ],
  // ── Rejected spellings and adversarial shapes ─────────────────────────
  ["rstest stays excluded", "@@ -1,0 +1,1 @@\n+#[rstest]", false],
  ["substring #[testable]", "@@ -1,0 +1,1 @@\n+#[testable]", false],
  ["substring #[contest]", "@@ -1,0 +1,1 @@\n+#[contest]", false],
  [
    "delimiter-looking line BEFORE the path",
    "@@ -1,0 +1,2 @@\n+(\n+#[test_case",
    false,
  ],
  [
    "raw-string fixture path + unrelated ( later in the same hunk",
    '@@ -1,0 +1,5 @@\n+let s = r#"\n+#[test_case\n+not a separator token\n+"#;\n+let t = (1);',
    false,
  ],
  [
    "path at end of one hunk, closer in another hunk",
    "@@ -1,0 +1,1 @@\n+#[test_case\n@@ -10,0 +11,1 @@\n+(1)]",
    false,
  ],
  [
    "closer only on a context line",
    "@@ -1,1 +1,1 @@\n+#[test_case\n (1)]",
    false,
  ],
  [
    "closer only on a removed line",
    "@@ -1,1 +1,1 @@\n+#[test_case\n-(1)]",
    false,
  ],
  [
    "unfinished block comment never closes",
    "@@ -1,0 +1,2 @@\n+#[test /*\n+ still open",
    false,
  ],
  [
    "continuation bound exceeded stays loud",
    "@@ -1,0 +1,40 @@\n+#[test /*\n" + "+ filler\n".repeat(30) + "+ */ ]",
    false,
  ],
  [
    "raw-string fixture with adjoining closer",
    '@@ -1,0 +1,4 @@\n+const FIXTURE: &str = r#"\n+#[test_case\n+(1)]\n+"#;',
    false,
  ],
  [
    "block comment with adjoining closer",
    '@@ -1,0 +1,4 @@\n+/* this is a comment\n+#[test_case\n+(1)]\n+end of comment */',
    false,
  ],
  [
    "raw string with no hash delimiters",
    '@@ -1,0 +1,4 @@\n+let s = r"\n+#[test_case\n+(1)]\n+";',
    false,
  ],
  [
    "raw string closes then real test attribute on next line",
    '@@ -1,0 +1,2 @@\n+let s = r#""#;\n+#[test_case(1)]',
    true,
  ],
  [
    "block comment closes then real test attribute on next line",
    '@@ -1,0 +1,2 @@\n+/* c */\n+#[test]',
    true,
  ],
  [
    "multiline regular string with test attribute inside",
    '@@ -1,0 +1,3 @@\n+const S: &str = "\n+#[test]\n+";',
    false,
  ],
  [
    "regular string closes then real test on next line",
    '@@ -1,0 +1,2 @@\n+let s = "text";\n+#[test]',
    true,
  ],
  [
    "char literal with double quote then real test",
    "@@ -1,0 +1,4 @@\n+const QUOTE: char = '\"';\n+#[test]\n+fn real_test() {\n+    assert_eq!(QUOTE as u32, 34);\n+}",
    true,
  ],
  [
    "byte char literal with double quote then real test",
    "@@ -1,0 +1,4 @@\n+const QUOTE: u8 = b'\"';\n+#[test]\n+fn real_test() {\n+    assert_eq!(QUOTE, 34);\n+}",
    true,
  ],
  [
    "char literal with escaped quote then real test",
    "@@ -1,0 +1,4 @@\n+const Q: char = '\\'';\n+#[test]\n+fn real_test() {\n+    assert_eq!(Q as u32, 39);\n+}",
    true,
  ],
  [
    "char literal with escaped backslash then real test",
    "@@ -1,0 +1,4 @@\n+const Q: char = '\\\\';\n+#[test]\n+fn real_test() {\n+    assert_eq!(Q as u32, 92);\n+}",
    true,
  ],
  [
    "char literal with unicode escape then real test",
    "@@ -1,0 +1,4 @@\n+const Q: char = '\\u{2764}';\n+#[test]\n+fn real_test() {\n+    assert_eq!(Q as u32, 10084);\n+}",
    true,
  ],
  [
    "lifetime in type then real test",
    "@@ -1,0 +1,3 @@\n+fn foo<'a>(x: &'a str) {}\n+#[test]\n+fn real_test() {}",
    true,
  ],
  [
    "label then real test",
    "@@ -1,0 +1,3 @@\n+'label: loop {}\n+#[test]\n+fn real_test() {}",
    true,
  ],
  [
    "static lifetime then real test",
    "@@ -1,0 +1,3 @@\n+const S: &'static str = \"hi\";\n+#[test]\n+fn real_test() {}",
    true,
  ],
  [
    "context line with stray closing quote then real test",
    '@@ -1,1 +1,2 @@\n  );"\n+#[test]',
    true,
  ],
  [
    "context line with stray opening quote then real test",
    '@@ -1,1 +1,2 @@\n  let s = "\n+#[test]',
    true,
  ],
  [
    "r# inside string on context line then real test",
    '@@ -1,1 +1,2 @@\n  let s = "r#";\n+#[test]',
    true,
  ],
  [
    "/* inside string on context line then real test",
    '@@ -1,1 +1,2 @@\n  let s = "/*";\n+#[test]',
    true,
  ],
  // Known limitation: a non-code region opened by a context line is invisible
  // to the pre-pass (context lines are not scanned). An added #[test] inside
  // an existing raw string or block comment is scanned as code and may match.
  // This is a false positive (silent direction), accepted because the old
  // detector had the same behavior, the pattern is rare, and needs-tests is
  // advisory. Scanning context lines to close this gap would re-introduce a
  // false negative on the far more common case of a context line with a stray
  // " from a string that opened before the visible window.
  [
    "known limitation: #[test] inside context-opened raw string (FP)",
    '@@ -1,1 +1,2 @@\n  const FIX: &str = r#"\n+#[test]\n  "#;',
    true,
  ],
  [
    "known limitation: #[test_case] inside context-opened raw string (FP)",
    '@@ -1,1 +1,3 @@\n  const FIX: &str = r#"\n+#[test_case\n+(1)]\n  "#;',
    true,
  ],
  [
    "known limitation: #[test] inside context-opened block comment (FP)",
    '@@ -1,1 +1,2 @@\n  /*\n+#[test]\n  */',
    true,
  ],
];

let failures = 0;
for (const [name, patch, expected] of cases) {
  const got = patchAddsInlineTest(patch);
  if (got !== expected) {
    failures += 1;
    console.error(`FAIL: ${name}: expected ${expected}, got ${got}`);
  }
}

// Runtime probe: the detector walks fork-controlled input on
// pull_request_target, so a pathological head must not stall the job. The
// long `_a` run is the historical exponential-backtracking shape for the
// attribute-path regex; the comment run exercises the scanner loop.
const probes = [
  ["long _a run", "@@ -1,0 +1,1 @@\n+#[test" + "_a".repeat(30000), false],
  [
    "long unclosed comment line",
    "@@ -1,0 +1,1 @@\n+#[test /*" + " *".repeat(30000),
    false,
  ],
];
for (const [name, patch, expected] of probes) {
  const t0 = process.hrtime.bigint();
  const got = patchAddsInlineTest(patch);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  if (got !== expected) {
    failures += 1;
    console.error(`FAIL: probe ${name}: expected ${expected}, got ${got}`);
  }
  if (ms > 1000) {
    failures += 1;
    console.error(`FAIL: probe ${name}: took ${ms.toFixed(0)}ms (>1000ms)`);
  }
}

if (failures) {
  console.error(`${failures} failure(s) across ${cases.length + probes.length} cases`);
  process.exit(1);
}
console.log(`ok: ${cases.length + probes.length} detector cases passed`);

#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
resolver="$repo_root/scripts/resolve-release-tag.sh"
test_tmp="$(mktemp -d)"
trap 'rm -r -- "$test_tmp"' EXIT

valid_output="$test_tmp/valid-output"
GITHUB_OUTPUT="$valid_output" "$resolver" "v1.2.3"

expected_output="$test_tmp/expected-output"
printf '%s\n' "tag=v1.2.3" "version=1.2.3" > "$expected_output"
cmp "$expected_output" "$valid_output"

newline_output="$test_tmp/newline-output"
if GITHUB_OUTPUT="$newline_output" "$resolver" $'v1.2.3\nname=owned'; then
  printf '%s\n' "newline-containing release tag unexpectedly passed" >&2
  exit 1
fi
test ! -s "$newline_output"

empty_output="$test_tmp/empty-output"
if GITHUB_OUTPUT="$empty_output" "$resolver" ""; then
  printf '%s\n' "empty release tag unexpectedly passed" >&2
  exit 1
fi
test ! -s "$empty_output"

resolver_count="$(grep -c 'scripts/resolve-release-tag.sh' "$repo_root/.github/workflows/release.yml")"
if [[ "$resolver_count" -ne 3 ]]; then
  printf '%s\n' "expected all 3 release tag steps to use the tested resolver; found $resolver_count" >&2
  exit 1
fi

printf '%s\n' "release tag resolver tests passed"

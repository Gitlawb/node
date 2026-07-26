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

build_output="$test_tmp/build-output"
GITHUB_OUTPUT="$build_output" "$resolver" "v1.2.3+build.5"

expected_build_output="$test_tmp/expected-build-output"
printf '%s\n' "tag=v1.2.3+build.5" "version=1.2.3+build.5" > "$expected_build_output"
cmp "$expected_build_output" "$build_output"

newline_output="$test_tmp/newline-output"
newline_stdout="$test_tmp/newline-stdout"
newline_stderr="$test_tmp/newline-stderr"
if GITHUB_OUTPUT="$newline_output" "$resolver" $'v1.2.3\nname=owned' \
  > "$newline_stdout" 2> "$newline_stderr"
then
  printf '%s\n' "newline-containing release tag unexpectedly passed" >&2
  exit 1
fi
test ! -s "$newline_output"
grep -qxF "::error::release tag is empty or contains invalid characters" "$newline_stdout"
test ! -s "$newline_stderr"

empty_output="$test_tmp/empty-output"
if GITHUB_OUTPUT="$empty_output" "$resolver" ""; then
  printf '%s\n' "empty release tag unexpectedly passed" >&2
  exit 1
fi
test ! -s "$empty_output"

invalid_output="$test_tmp/invalid-output"
for invalid_tag in \
  "v1.2.3 tag" \
  "v1.2.3;name=owned" \
  "release-1.2.3" \
  "v-1" \
  "vlatest" \
  "v" \
  "v1.2.3/../../x" \
  "V1.2.3"
do
  : > "$invalid_output"
  if GITHUB_OUTPUT="$invalid_output" "$resolver" "$invalid_tag"; then
    printf '%s\n' "invalid release tag unexpectedly passed: $invalid_tag" >&2
    exit 1
  fi
  test ! -s "$invalid_output"
done

workflows="$repo_root/.github/workflows"
steps="$(grep -c 'name: Resolve release tag' "$workflows/release.yml" || true)"
calls="$(grep -cE '^[[:space:]]*scripts/resolve-release-tag\.sh ' "$workflows/release.yml" || true)"

if [[ "$steps" -lt 1 || "$steps" -ne "$calls" ]]; then
  printf '%s\n' \
    "every 'Resolve release tag' step must call the tested resolver; steps=$steps calls=$calls" \
    >&2
  exit 1
fi

if grep -rqE '(echo|printf)[^|]*(tag|version)=.*>>[[:space:]]*"?\$GITHUB_OUTPUT' "$workflows"; then
  printf '%s\n' "a workflow writes a tag/version output without the tested resolver:" >&2
  grep -rnE '(echo|printf)[^|]*(tag|version)=.*>>[[:space:]]*"?\$GITHUB_OUTPUT' \
    "$workflows" >&2
  exit 1
fi

printf '%s\n' "release tag resolver tests passed"

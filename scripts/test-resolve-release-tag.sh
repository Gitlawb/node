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
  "v1.2.3+build.5" \
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

release_workflow="$repo_root/.github/workflows/release.yml"
resolver_steps="$test_tmp/resolver-steps"

check_resolver_steps() {
  local workflow_file="$1"
  local steps_file="$2"
  local resolver_call_re='(^|[[:space:]])scripts/resolve-release-tag\.sh([[:space:]]|$)'
  local direct_output_re='(echo|printf).*(tag|version)=.*>>?[[:space:]]*"?\$(GITHUB_OUTPUT|GITHUB_ENV)'
  local resolver_line
  local resolver_step
  local resolver_step_count=0

  awk '
    function indentation(line, spaces) {
      spaces = line
      sub(/[^ ].*$/, "", spaces)
      return length(spaces)
    }

    function emit_step() {
      if (!in_resolver_step) {
        return
      }

      gsub(/[[:space:]]+/, " ", resolver_step)
      sub(/^ /, "", resolver_step)
      sub(/ $/, "", resolver_step)
      printf "%d\t%s\n", resolver_line, resolver_step
      in_resolver_step = 0
      resolver_step = ""
    }

    /^[[:space:]]*- name:[[:space:]]*Resolve release tag[[:space:]]*$/ {
      emit_step()
      in_resolver_step = 1
      resolver_indent = indentation($0)
      resolver_line = NR
    }

    {
      if (in_resolver_step && NR != resolver_line &&
          $0 ~ /^[[:space:]]*-[[:space:]]/ &&
          indentation($0) == resolver_indent) {
        emit_step()
      }

      if (in_resolver_step) {
        resolver_step = resolver_step " " $0
      }
    }

    END {
      emit_step()
    }
  ' "$workflow_file" > "$steps_file"

  while IFS=$'\t' read -r resolver_line resolver_step; do
    resolver_step_count=$((resolver_step_count + 1))

    if [[ ! "$resolver_step" =~ $resolver_call_re ]]; then
      printf '%s\n' \
        "'Resolve release tag' step at ${workflow_file##*/}:$resolver_line does not call the tested resolver" \
        >&2
      return 1
    fi

    if [[ "$resolver_step" =~ $direct_output_re ]]; then
      printf '%s\n' \
        "'Resolve release tag' step at ${workflow_file##*/}:$resolver_line writes tag/version outputs directly" \
        >&2
      return 1
    fi
  done < "$steps_file"

  if [[ "$resolver_step_count" -lt 1 ]]; then
    printf '%s\n' "${workflow_file##*/} has no 'Resolve release tag' steps" >&2
    return 1
  fi
}

check_resolver_steps "$release_workflow" "$resolver_steps"

bypass_workflow="$test_tmp/release-bypass.yml"
awk '
  /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    in_docker_manifest = ($0 ~ /^  docker-manifest:/)
  }

  in_docker_manifest && !replaced && /scripts\/resolve-release-tag\.sh/ {
    print "          {"
    print "            echo \"tag=ghcr.io/attacker/evil\""
    print "            echo \"version=9.9.9\""
    print "          } >> \"$GITHUB_OUTPUT\""
    replaced = 1
    next
  }

  in_docker_manifest && replaced && !inserted_decoy &&
      /^      -[[:space:]]/ {
    print "      - name: Decoy resolver call"
    print "        run: scripts/resolve-release-tag.sh \"$TAG\""
    print ""
    inserted_decoy = 1
  }

  { print }

  END {
    if (!replaced || !inserted_decoy) {
      print "failed to build docker-manifest bypass fixture" > "/dev/stderr"
      exit 1
    }
  }
' "$release_workflow" > "$bypass_workflow"

if check_resolver_steps "$bypass_workflow" "$test_tmp/bypass-steps" 2> /dev/null; then
  printf '%s\n' "per-step workflow guard missed a decoy-call output-injection bypass" >&2
  exit 1
fi

direct_output_workflow="$test_tmp/release-direct-output.yml"
awk '
  {
    print
    if (!injected && $0 ~ /scripts\/resolve-release-tag\.sh/) {
      print "          {"
      print "            echo \"tag=ghcr.io/attacker/evil\""
      print "            echo \"version=9.9.9\""
      print "          } >> \"$GITHUB_OUTPUT\""
      injected = 1
    }
  }
' "$release_workflow" > "$direct_output_workflow"

if check_resolver_steps \
  "$direct_output_workflow" "$test_tmp/direct-output-steps" 2> /dev/null
then
  printf '%s\n' "per-step workflow guard missed a multiline direct output write" >&2
  exit 1
fi

printf '%s\n' "release tag resolver tests passed"

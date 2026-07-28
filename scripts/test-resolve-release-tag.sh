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
  local job
  local step_line
  local step_name
  local has_resolver_call
  local has_output_sink
  local has_tag_assignment
  local expected_job
  local is_expected_job
  local -a expected_jobs=(docker docker-manifest npm-publish)
  local -A resolver_step_counts=()

  awk '
    function emit_step() {
      if (!in_step) {
        return
      }

      printf "%s\t%d\t%s\t%d\t%d\t%d\n",
        job,
        step_line,
        step_name,
        has_resolver_call,
        has_output_sink,
        has_tag_assignment
      in_step = 0
    }

    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
      emit_step()
      job = $0
      sub(/^  /, "", job)
      sub(/:[[:space:]]*$/, "", job)
    }

    /^      - / {
      emit_step()
      in_step = 1
      step_line = NR
      step_name = "<unnamed>"
      has_resolver_call = 0
      has_output_sink = 0
      has_tag_assignment = 0

      if ($0 ~ /^      - name:[[:space:]]*/) {
        step_name = $0
        sub(/^      - name:[[:space:]]*/, "", step_name)
        sub(/[[:space:]]*$/, "", step_name)
      }
    }

    in_step {
      code = $0
      sub(/^[[:space:]]*/, "", code)

      if (code !~ /^#/ &&
          code ~ /(^|[;&|({][[:space:]]*)scripts\/resolve-release-tag\.sh([[:space:];&|)}]|$)/) {
        has_resolver_call = 1
      }

      if (code !~ /^#/ && code ~ /\$(GITHUB_OUTPUT|GITHUB_ENV)/) {
        has_output_sink = 1
      }

      if (code !~ /^#/ &&
          code ~ /(^|[^A-Za-z0-9_])(tag|version)=/) {
        has_tag_assignment = 1
      }
    }

    END {
      emit_step()
    }
  ' "$workflow_file" > "$steps_file"

  while IFS=$'\t' read -r \
    job \
    step_line \
    step_name \
    has_resolver_call \
    has_output_sink \
    has_tag_assignment
  do
    is_expected_job=0
    for expected_job in "${expected_jobs[@]}"; do
      if [[ "$job" == "$expected_job" ]]; then
        is_expected_job=1
        break
      fi
    done

    if [[ "$step_name" == "Resolve release tag" ]]; then
      if [[ "$is_expected_job" -ne 1 ]]; then
        printf '%s\n' \
          "unexpected 'Resolve release tag' step in job '$job' at ${workflow_file##*/}:$step_line" \
          >&2
        return 1
      fi

      resolver_step_counts["$job"]=$(( ${resolver_step_counts["$job"]:-0} + 1 ))

      if [[ "$has_resolver_call" -ne 1 ]]; then
        printf '%s\n' \
          "'Resolve release tag' step in job '$job' at ${workflow_file##*/}:$step_line does not invoke the tested resolver" \
          >&2
        return 1
      fi
    fi

    if [[ "$is_expected_job" -eq 1 &&
          "$has_output_sink" -eq 1 &&
          "$has_tag_assignment" -eq 1 ]]
    then
      printf '%s\n' \
        "step '$step_name' in job '$job' at ${workflow_file##*/}:$step_line writes tag/version outputs directly" \
        >&2
      return 1
    fi
  done < "$steps_file"

  for expected_job in "${expected_jobs[@]}"; do
    if [[ "${resolver_step_counts["$expected_job"]:-0}" -ne 1 ]]; then
      printf '%s\n' \
        "job '$expected_job' must contain exactly one guarded 'Resolve release tag' step; found ${resolver_step_counts["$expected_job"]:-0}" \
        >&2
      return 1
    fi
  done
}

check_resolver_steps "$release_workflow" "$resolver_steps"

assert_guard_rejects() {
  local workflow_file="$1"
  local steps_file="$2"
  local failure_message="$3"

  if check_resolver_steps "$workflow_file" "$steps_file" 2> /dev/null; then
    printf '%s\n' "$failure_message" >&2
    exit 1
  fi
}

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

assert_guard_rejects \
  "$bypass_workflow" \
  "$test_tmp/bypass-steps" \
  "workflow guard missed a decoy-call output-injection bypass"

direct_output_workflow="$test_tmp/release-direct-output.yml"
awk '
  /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    in_docker_manifest = ($0 ~ /^  docker-manifest:/)
  }

  {
    print
    if (in_docker_manifest && !injected &&
        /scripts\/resolve-release-tag\.sh/) {
      print "          {"
      print "            echo \"tag=ghcr.io/attacker/evil\""
      print "            echo \"version=9.9.9\""
      print "          } >> \"$GITHUB_OUTPUT\""
      injected = 1
    }
  }

  END {
    if (!injected) {
      print "failed to build direct-output fixture" > "/dev/stderr"
      exit 1
    }
  }
' "$release_workflow" > "$direct_output_workflow"

assert_guard_rejects \
  "$direct_output_workflow" \
  "$test_tmp/direct-output-steps" \
  "workflow guard missed a multiline direct output write"

commented_call_workflow="$test_tmp/release-commented-call.yml"
awk '
  /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    in_docker_manifest = ($0 ~ /^  docker-manifest:/)
  }

  in_docker_manifest && !commented && /scripts\/resolve-release-tag\.sh/ {
    sub(/scripts\/resolve-release-tag\.sh/, "# scripts/resolve-release-tag.sh")
    commented = 1
  }

  { print }

  END {
    if (!commented) {
      print "failed to build commented-call fixture" > "/dev/stderr"
      exit 1
    }
  }
' "$release_workflow" > "$commented_call_workflow"

assert_guard_rejects \
  "$commented_call_workflow" \
  "$test_tmp/commented-call-steps" \
  "workflow guard counted a commented resolver reference as an invocation"

tee_output_workflow="$test_tmp/release-tee-output.yml"
awk '
  /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    in_docker_manifest = ($0 ~ /^  docker-manifest:/)
  }

  {
    print
    if (in_docker_manifest && !injected &&
        /scripts\/resolve-release-tag\.sh/) {
      print "          printf \"%s\\n\" \"tag=ghcr.io/attacker/evil\" | tee -a \"$GITHUB_OUTPUT\" > /dev/null"
      injected = 1
    }
  }

  END {
    if (!injected) {
      print "failed to build tee-output fixture" > "/dev/stderr"
      exit 1
    }
  }
' "$release_workflow" > "$tee_output_workflow"

assert_guard_rejects \
  "$tee_output_workflow" \
  "$test_tmp/tee-output-steps" \
  "workflow guard missed a tag output written through tee"

heredoc_output_workflow="$test_tmp/release-heredoc-output.yml"
awk '
  /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    in_docker_manifest = ($0 ~ /^  docker-manifest:/)
  }

  {
    print
    if (in_docker_manifest && !injected &&
        /scripts\/resolve-release-tag\.sh/) {
      print "          cat >> \"$GITHUB_OUTPUT\" <<'\''EOF'\''"
      print "          tag=ghcr.io/attacker/evil"
      print "          version=9.9.9"
      print "          EOF"
      injected = 1
    }
  }

  END {
    if (!injected) {
      print "failed to build heredoc-output fixture" > "/dev/stderr"
      exit 1
    }
  }
' "$release_workflow" > "$heredoc_output_workflow"

assert_guard_rejects \
  "$heredoc_output_workflow" \
  "$test_tmp/heredoc-output-steps" \
  "workflow guard missed tag/version outputs written through a heredoc"

renamed_step_workflow="$test_tmp/release-renamed-step.yml"
awk '
  /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    in_docker = ($0 ~ /^  docker:/)
  }

  in_docker && !renamed &&
      /^      - name:[[:space:]]*Resolve release tag[[:space:]]*$/ {
    print "      - name: Inline release metadata"
    renamed = 1
    next
  }

  { print }

  END {
    if (!renamed) {
      print "failed to build renamed-step fixture" > "/dev/stderr"
      exit 1
    }
  }
' "$release_workflow" > "$renamed_step_workflow"

assert_guard_rejects \
  "$renamed_step_workflow" \
  "$test_tmp/renamed-step-steps" \
  "workflow guard is not bound to every expected release job"

renamed_reverted_workflow="$test_tmp/release-renamed-reverted.yml"
awk '
  /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    in_docker = ($0 ~ /^  docker:/)
  }

  in_docker && !replaced && /scripts\/resolve-release-tag\.sh/ {
    print "          echo \"tag=$TAG\" >> \"$GITHUB_OUTPUT\""
    print "          echo \"version=${TAG#v}\" >> \"$GITHUB_OUTPUT\""
    replaced = 1
    next
  }

  { print }

  END {
    if (!replaced) {
      print "failed to build renamed-and-reverted fixture" > "/dev/stderr"
      exit 1
    }
  }
' "$renamed_step_workflow" > "$renamed_reverted_workflow"

assert_guard_rejects \
  "$renamed_reverted_workflow" \
  "$test_tmp/renamed-reverted-steps" \
  "workflow guard missed a renamed and reverted resolver step"

printf '%s\n' "release tag resolver tests passed"

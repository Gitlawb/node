#!/usr/bin/env bash
# Fixture test for scripts/ci-surfaces.sh, which alone decides which PR Checks
# jobs and CodeQL languages run. Pins at least one must-not-skip case per
# surface row, the crate fan-out and widening rules, and paths that git would
# C-quote without -z. Run from pr-checks.yml before the mapper is used.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mapper="$repo_root/scripts/ci-surfaces.sh"
failures=0

# map PATH... : run the mapper on the paths as `git diff -z` would emit them.
map() {
  if [ "$#" -gt 0 ]; then printf '%s\0' "$@"; fi | "$mapper"
}

# check CASE OUTPUT KEY=VALUE... : each KEY must have exactly VALUE.
check() {
  local name="$1" out="$2" want key
  shift 2
  for want in "$@"; do
    key="${want%%=*}"
    if ! grep -qxF -- "$want" <<<"$out"; then
      printf 'FAIL %s: want %s, got %s\n' "$name" "$want" \
        "$(grep -E "^${key}=" <<<"$out" || echo '<missing>')" >&2
      failures=$((failures + 1))
    fi
  done
}

# has_packages CASE OUTPUT PKG... : rust_packages must include each -p PKG.
has_packages() {
  local name="$1" out="$2" pkgs pkg
  shift 2
  pkgs=" $(sed -n 's/^rust_packages=//p' <<<"$out") "
  for pkg in "$@"; do
    if [[ "$pkgs" != *" -p $pkg "* ]]; then
      printf 'FAIL %s: rust_packages lacks -p %s (got%s)\n' "$name" "$pkg" "$pkgs" >&2
      failures=$((failures + 1))
    fi
  done
}

nothing=(rust=false rust_packages= windows=false windows_packages= docker=false
  audit=false core_deps=false release_versioning=false release_tag=false
  codeql=false 'codeql_matrix={"include":[]}')
everything=(rust=true rust_packages=--workspace windows=true
  'windows_packages=-p gl -p git-remote-gitlawb' docker=true audit=true
  core_deps=true release_versioning=true release_tag=true codeql=true)
all_languages='codeql_matrix={"include":[{"language":"actions","build-mode":"none","runner":"ubuntu-latest"},{"language":"javascript-typescript","build-mode":"none","runner":"ubuntu-latest"},{"language":"rust","build-mode":"none","runner":"ubuntu-latest"},{"language":"swift","build-mode":"autobuild","runner":"macos-latest"}]}'
rust_only='codeql_matrix={"include":[{"language":"rust","build-mode":"none","runner":"ubuntu-latest"}]}'

# Docs-only and empty input run nothing.
check "docs only" "$(map README.md docs/x.md infra/x.tf)" "${nothing[@]}"
check "empty input" "$(map)" "${nothing[@]}"

# A crate change tests that crate and its reverse deps, nothing else.
check "gl source" "$(map crates/gl/src/main.rs)" \
  rust=true 'rust_packages=-p gl' windows=true 'windows_packages=-p gl' \
  docker=false audit=false "$rust_only"
out="$(map crates/gitlawb-core/src/lib.rs)"
check "gitlawb-core source" "$out" rust=true windows=true \
  'windows_packages=-p git-remote-gitlawb -p gl' "$rust_only"
has_packages "gitlawb-core fan-out" "$out" gitlawb-core icaptcha-client \
  gitlawb-attest git-remote-gitlawb gl gitlawb-node
check "icaptcha-client source" "$(map crates/icaptcha-client/src/lib.rs)" \
  'rust_packages=-p gl -p icaptcha-client' 'windows_packages=-p gl'

# Anything the Rust surface cannot attribute to known crates widens.
check "unknown crate dir" "$(map crates/no-such-crate/src/lib.rs)" \
  rust=true rust_packages=--workspace docker=false
check "root Cargo.lock" "$(map Cargo.lock)" \
  rust=true rust_packages=--workspace docker=true audit=true core_deps=true \
  release_versioning=false
check "toolchain file" "$(map rust-toolchain.toml)" rust=true rust_packages=--workspace

# Files compiled into a crate from outside crates/.
check "bootstrap-peers.json" "$(map bootstrap-peers.json)" \
  rust=true 'rust_packages=-p gitlawb-node' windows=false docker=true

# One must-not-skip trigger per non-Rust row.
check "Dockerfile" "$(map Dockerfile)" docker=true rust=false
check "crate manifest" "$(map crates/gl/Cargo.toml)" \
  docker=true release_versioning=true 'rust_packages=-p gl'
check "audit config" "$(map .cargo/audit.toml)" audit=true rust_packages=--workspace
check "core allowlist" "$(map ci/gitlawb-core-allowed-deps.txt)" core_deps=true rust=false
check "release-please config" "$(map release-please-config.json)" \
  release_versioning=true rust=false
check "release tag resolver" "$(map scripts/resolve-release-tag.sh)" release_tag=true rust=false
check "other workflow" "$(map .github/workflows/release.yml)" "${nothing[@]:0:9}" \
  codeql=true 'codeql_matrix={"include":[{"language":"actions","build-mode":"none","runner":"ubuntu-latest"}]}'
check "npm" "$(map npm/package.json)" codeql=true \
  'codeql_matrix={"include":[{"language":"javascript-typescript","build-mode":"none","runner":"ubuntu-latest"}]}'
check "swift" "$(map macos-app/Sources/App.swift)" rust=false codeql=true \
  'codeql_matrix={"include":[{"language":"swift","build-mode":"autobuild","runner":"macos-latest"}]}'

# Editing the CI wiring runs every surface, exactly like --all.
for wiring in .github/workflows/pr-checks.yml .github/workflows/codeql.yml scripts/ci-surfaces.sh; do
  check "wiring $wiring" "$(map "$wiring")" "${everything[@]}" "$all_languages"
done
check "--all" "$("$mapper" --all </dev/null)" "${everything[@]}" "$all_languages"

# Names git C-quotes without -z (non-ASCII, tab, quote, newline) still map.
for name in $'\xc3\xa9.rs' $'a\tb.rs' 'a"b.rs' $'a\nb.rs'; do
  check "quoted name $(printf %q "$name")" "$(map "crates/gl/src/$name")" \
    rust=true 'rust_packages=-p gl'
done
check "non-ASCII swift" "$(map $'macos-app/Sources/Caf\xc3\xa9.swift')" codeql=true \
  'codeql_matrix={"include":[{"language":"swift","build-mode":"autobuild","runner":"macos-latest"}]}'

# Newline-delimited input (git diff without -z) is rejected, not misread.
if printf 'crates/gl/src/main.rs\n' | "$mapper" >/dev/null 2>&1; then
  echo "FAIL newline-delimited input: mapper accepted it" >&2
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures ci-surfaces mapping check(s) failed" >&2
  exit 1
fi
echo "ci-surfaces mapping: all checks passed"

#!/usr/bin/env bash
#
# Map a pull request's changed paths to the CI surfaces they touch, so each
# check in pr-checks.yml and codeql.yml runs only when its inputs changed and
# Rust jobs test only the affected crates.
#
# Usage:
#   git diff --name-only --no-renames BASE HEAD | scripts/ci-surfaces.sh
#   scripts/ci-surfaces.sh --all      # every surface, whole workspace
#
# Prints GITHUB_OUTPUT lines (key=value). Fail-safe direction: anything this
# script cannot attribute precisely widens the run, never narrows it. A global
# Rust input or an unknown crate directory runs the Rust jobs on the whole
# workspace; the CI wiring itself (pr-checks.yml, codeql.yml, this script)
# runs every surface.
# Non-PR events (push to main, merge_group, workflow_dispatch, schedule) are
# expected to pass --all, so main and the merge queue keep full coverage.
#
# Runnable from anywhere in the repo.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"

all=false
if [ "${1:-}" = "--all" ]; then
  all=true
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--all] < changed-paths" >&2
  exit 2
fi

changed=()
if [ "$all" = false ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && changed+=("$line")
  done
fi

# Workspace crates, derived from crates/*/Cargo.toml so a new crate is picked
# up without editing this script. dir -> package name, and dir -> the crate
# dirs it depends on through `path = "../<dir>"` (normal, dev, or build deps).
declare -A pkg_of=() deps_of=()
for manifest in "$ROOT"/crates/*/Cargo.toml; do
  dir="$(basename "$(dirname "$manifest")")"
  pkg_of[$dir]="$(sed -n 's/^name *= *"\([^"]*\)".*/\1/p' "$manifest" | head -n1)"
  deps_of[$dir]="$(sed -n 's#.*path *= *"\.\./\([^"/]*\)".*#\1#p' "$manifest" | tr '\n' ' ')"
done

full_rust=false
rust=false
docker=false
audit=false
core_deps=false
release_versioning=false
release_tag=false
cq_actions=false
cq_js=false
cq_rust=false
cq_swift=false
declare -A touched=()

for path in "${changed[@]}"; do
  case "$path" in
    # The CI wiring itself: validate everything it gates.
    .github/workflows/pr-checks.yml | .github/workflows/codeql.yml | scripts/ci-surfaces.sh)
      all=true ;;
    # Workspace-wide Rust inputs.
    Cargo.toml | Cargo.lock | .cargo/* | rust-toolchain | rust-toolchain.toml \
      | rustfmt.toml | .rustfmt.toml | clippy.toml | .clippy.toml)
      full_rust=true ;;
    crates/*/*)
      dir="${path#crates/}"
      dir="${dir%%/*}"
      if [ -n "${pkg_of[$dir]:-}" ]; then
        touched[$dir]=1
      else
        # A crate dir this checkout does not know (removed or renamed crate).
        full_rust=true
      fi ;;
  esac

  case "$path" in
    Dockerfile | .dockerignore | bootstrap-peers.json | Cargo.toml | Cargo.lock \
      | .cargo/* | rust-toolchain | rust-toolchain.toml | crates/*/Cargo.toml)
      docker=true ;;
  esac
  case "$path" in
    Cargo.lock | .cargo/audit.toml) audit=true ;;
  esac
  case "$path" in
    Cargo.toml | Cargo.lock | crates/gitlawb-core/Cargo.toml \
      | ci/gitlawb-core-allowed-deps.txt | scripts/check-gitlawb-core-deps.sh)
      core_deps=true ;;
  esac
  case "$path" in
    Cargo.toml | crates/*/Cargo.toml | release-please-config.json \
      | .release-please-manifest.json | scripts/check-release-versioning.sh)
      release_versioning=true ;;
  esac
  case "$path" in
    scripts/resolve-release-tag.sh | scripts/test-resolve-release-tag.sh)
      release_tag=true ;;
  esac

  case "$path" in
    .github/workflows/* | .github/actions/*) cq_actions=true ;;
  esac
  case "$path" in
    npm/* | *.js | *.mjs | *.cjs | *.jsx | *.ts | *.mts | *.cts | *.tsx) cq_js=true ;;
  esac
  case "$path" in
    macos-app/* | *.swift) cq_swift=true ;;
  esac
done

if [ "$all" = true ]; then
  full_rust=true
  docker=true
  audit=true
  core_deps=true
  release_versioning=true
  release_tag=true
  cq_actions=true
  cq_js=true
  cq_swift=true
fi

# Affected crates: the touched ones plus everything that depends on them,
# transitively, so a gitlawb-core change still tests every consumer.
declare -A affected=()
for dir in "${!touched[@]}"; do affected[$dir]=1; done
grew=true
while [ "$grew" = true ]; do
  grew=false
  for dir in "${!deps_of[@]}"; do
    [ -n "${affected[$dir]:-}" ] && continue
    for dep in ${deps_of[$dir]}; do
      if [ -n "${affected[$dep]:-}" ]; then
        affected[$dir]=1
        grew=true
        break
      fi
    done
  done
done

if [ "$full_rust" = true ] || [ "${#affected[@]}" -gt 0 ]; then
  rust=true
  cq_rust=true
fi

rust_packages=""
windows_packages=""
if [ "$full_rust" = true ]; then
  rust_packages="--workspace"
  windows_packages="-p gl -p git-remote-gitlawb"
elif [ "$rust" = true ]; then
  for dir in $(printf '%s\n' "${!affected[@]}" | sort); do
    rust_packages+="${rust_packages:+ }-p ${pkg_of[$dir]}"
    case "${pkg_of[$dir]}" in
      gl | git-remote-gitlawb) windows_packages+="${windows_packages:+ }-p ${pkg_of[$dir]}" ;;
    esac
  done
fi

windows=false
[ -n "$windows_packages" ] && windows=true

languages=()
[ "$cq_actions" = true ] && languages+=('{"language":"actions","build-mode":"none","runner":"ubuntu-latest"}')
[ "$cq_js" = true ] && languages+=('{"language":"javascript-typescript","build-mode":"none","runner":"ubuntu-latest"}')
[ "$cq_rust" = true ] && languages+=('{"language":"rust","build-mode":"none","runner":"ubuntu-latest"}')
[ "$cq_swift" = true ] && languages+=('{"language":"swift","build-mode":"autobuild","runner":"macos-latest"}')
codeql_matrix="{\"include\":[$(IFS=,; echo "${languages[*]}")]}"
codeql=false
[ "${#languages[@]}" -gt 0 ] && codeql=true

cat <<EOF
rust=$rust
rust_packages=$rust_packages
windows=$windows
windows_packages=$windows_packages
docker=$docker
audit=$audit
core_deps=$core_deps
release_versioning=$release_versioning
release_tag=$release_tag
codeql=$codeql
codeql_matrix=$codeql_matrix
EOF

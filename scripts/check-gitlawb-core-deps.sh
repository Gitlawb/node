#!/usr/bin/env bash
#
# Dependency-purity gate for the `gitlawb-core` crate.
#
# gitlawb-core is embedded by every consumer (the gl CLI, git-remote-gitlawb,
# the node daemon), so it must stay lean. This script recomputes gitlawb-core's
# NORMAL (non-dev, non-build) transitive dependency set and fails if it contains
# any crate not present in ci/gitlawb-core-allowed-deps.txt.
#
# Hard-fail direction: a crate present now but NOT allowlisted. That is the case
# the gate exists to catch (core silently gaining a heavy dependency).
# Informational only: an allowlisted crate no longer present (stale entry) — a
# legitimate dependency removal should not red CI, so it is reported, not failed.
#
# Runnable from anywhere in the repo.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ALLOW="$ROOT/ci/gitlawb-core-allowed-deps.txt"

if [ ! -f "$ALLOW" ]; then
  echo "ERROR: allowlist not found at $ALLOW" >&2
  exit 1
fi

# `cargo tree` resolves like the build/test jobs (no --locked): the committed
# Cargo.lock can lag the manifests, and --locked would red this gate for
# lock-staleness reasons unrelated to gitlawb-core's dependencies. Resolving can
# refresh Cargo.lock as a side effect, so snapshot and restore it — this check
# must never leave the working tree dirty when run locally.
lock_backup="$(mktemp)"
cp "$ROOT/Cargo.lock" "$lock_backup"
restore_lock() { cp "$lock_backup" "$ROOT/Cargo.lock"; rm -f "$lock_backup"; }
trap restore_lock EXIT

# Current normal-dependency closure of gitlawb-core, one crate name per line.
# Must match the regen command documented in the allowlist header exactly.
current="$(
  cargo tree -p gitlawb-core --edges normal --prefix none --manifest-path "$ROOT/Cargo.toml" \
    | sed -E 's/ v[0-9].*$//' \
    | grep -v '^gitlawb-core$' \
    | sort -u
)"

# Allowlist with comments and blank lines stripped.
allowed="$(grep -vE '^[[:space:]]*(#|$)' "$ALLOW" | sort -u)"

# comm needs sorted input; both sides are sorted above.
offenders="$(comm -23 <(printf '%s\n' "$current") <(printf '%s\n' "$allowed"))"
stale="$(comm -13 <(printf '%s\n' "$current") <(printf '%s\n' "$allowed"))"

if [ -n "$stale" ]; then
  echo "NOTE: allowlisted crates no longer in gitlawb-core's dependency tree"
  echo "      (safe to prune from ci/gitlawb-core-allowed-deps.txt):"
  printf '  %s\n' $stale
  echo
fi

if [ -n "$offenders" ]; then
  {
    echo "ERROR: gitlawb-core gained dependencies not on the allowlist:"
    printf '  %s\n' $offenders
    echo
    echo "gitlawb-core must stay embeddable and lean. If a new dependency is"
    echo "intentional, add it to ci/gitlawb-core-allowed-deps.txt (regen command"
    echo "is in that file's header). Otherwise, drop the dependency."
  } >&2
  exit 1
fi

echo "gitlawb-core dependency purity: OK ($(printf '%s\n' "$current" | wc -l | tr -d ' ') normal deps, all allowlisted)."

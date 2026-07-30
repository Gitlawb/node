#!/usr/bin/env bash
#
# Release-versioning coverage gate for the workspace crates.
#
# release-please owns every crate's version. It rewrites a version line only
# when BOTH halves hold: the line carries an `# x-release-please-version`
# annotation, and the crate's manifest is listed under `extra-files` in
# release-please-config.json. A crate missing either half is silently skipped
# at release time and freezes at whatever version it was created with, which
# is exactly what happened to icaptcha-client (added as a workspace member
# after the config was last written, so it sat at 0.4.0 while the rest of the
# workspace walked to 0.7.1 across four releases).
#
# Exhaustive-by-construction: the required set is DERIVED from the workspace
# member list via `cargo metadata`, never from a hand-maintained list here. A
# newly added crate reds CI whether or not anyone remembered this gate exists,
# which is the property a hand list cannot have.
#
# Hard-fail directions, all three release-silent:
#   1. a workspace member absent from extra-files
#   2. a workspace member whose version line lacks the annotation
#   3. an extra-files entry pointing at a manifest that no longer exists
#
# Runnable from anywhere in the repo.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
CONFIG="$ROOT/release-please-config.json"

if [ ! -f "$CONFIG" ]; then
  echo "ERROR: release-please config not found at $CONFIG" >&2
  exit 1
fi

# Resolving can refresh Cargo.lock as a side effect, so snapshot and restore it:
# this check must never leave the working tree dirty when run locally. Same
# reasoning as scripts/check-gitlawb-core-deps.sh.
lock_backup="$(mktemp)"
cp "$ROOT/Cargo.lock" "$lock_backup"
restore_lock() { cp "$lock_backup" "$ROOT/Cargo.lock"; rm -f "$lock_backup"; }
trap restore_lock EXIT

# Workspace members as repo-relative manifest paths, one per line. This is the
# derived required set: whatever cargo considers a member must be release-managed.
members="$(
  cargo metadata --no-deps --format-version 1 --manifest-path "$ROOT/Cargo.toml" \
    | jq -r '.packages[].manifest_path' \
    | sed "s#^$ROOT/##" \
    | sort -u
)"

# Manifest paths release-please is configured to rewrite.
listed="$(jq -r '.packages["."]["extra-files"][] | .path' "$CONFIG" | sort -u)"

unlisted="$(comm -23 <(printf '%s\n' "$members") <(printf '%s\n' "$listed"))"
orphaned="$(comm -13 <(printf '%s\n' "$members") <(printf '%s\n' "$listed"))"

# Second half of the invariant: being listed does nothing without the marker,
# because the generic updater keys on the annotation to find the line.
unmarked=""
while IFS= read -r manifest; do
  [ -n "$manifest" ] || continue
  if ! grep -qE '^version = ".*" # x-release-please-version' "$ROOT/$manifest"; then
    unmarked="$unmarked$manifest"$'\n'
  fi
done <<< "$members"

failed=0

if [ -n "$unlisted" ]; then
  {
    echo "ERROR: workspace members missing from extra-files in release-please-config.json:"
    printf '  %s\n' $unlisted
    echo
    echo "release-please will never bump these crates, so they freeze at their"
    echo "current version while the rest of the workspace moves. Add each one as"
    echo '  { "type": "generic", "path": "<manifest path>" }'
  } >&2
  failed=1
fi

if [ -n "$unmarked" ]; then
  {
    echo "ERROR: workspace members whose version line lacks the release-please annotation:"
    printf '  %s\n' $unmarked
    echo
    echo 'The generic updater finds the line by its trailing `# x-release-please-version`'
    echo "comment. Without it the crate is listed but never rewritten."
  } >&2
  failed=1
fi

if [ -n "$orphaned" ]; then
  {
    echo "ERROR: extra-files entries pointing at manifests that are not workspace members:"
    printf '  %s\n' $orphaned
    echo
    echo "release-please fails the release when an extra-file path does not exist."
    echo "Drop the stale entry, or restore the crate to the workspace."
  } >&2
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "release versioning coverage: OK ($(printf '%s\n' "$members" | wc -l | tr -d ' ') workspace members, all annotated and listed)."

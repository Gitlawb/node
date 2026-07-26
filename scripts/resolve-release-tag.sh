#!/usr/bin/env bash
set -euo pipefail

tag="${1-}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"

case "$tag" in
  ""|*[!A-Za-z0-9._-]*)
    printf '%s\n' "::error::release tag is empty or contains invalid characters" >&2
    exit 1
    ;;
esac

case "$tag" in
  v[0-9]*) ;;
  *)
    printf '%s\n' "::error::'$tag' does not look like a release tag (vX.Y.Z)" >&2
    exit 1
    ;;
esac

printf '%s\n' "tag=$tag" >> "$GITHUB_OUTPUT"
printf '%s\n' "version=${tag#v}" >> "$GITHUB_OUTPUT"

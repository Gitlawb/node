#!/usr/bin/env bash
set -euo pipefail
shopt -s extglob

tag="${1-}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"

case "$tag" in
  ""|*[!A-Za-z0-9._-]*)
    printf '%s\n' "::error::release tag is empty or contains invalid characters"
    exit 1
    ;;
esac

# Right-anchored on purpose: v[0-9]* leaves the tail unbounded and accepts
# v1.2.3.4.5, v1_x, v1-any-branch-name, and bare v1. Every existing tag is
# plain vX.Y.Z (release-please, release-type: simple, no prerelease channel).
case "$tag" in
  v+([0-9]).+([0-9]).+([0-9])) ;;
  *)
    printf '%s\n' "::error::'$tag' does not look like a release tag (vX.Y.Z)"
    exit 1
    ;;
esac

# Provenance, enforced only in CI where a token is present. The environment
# gate restricts which REF a dispatch may run from; this restricts which TAG
# the input may name: it must be a tag the release flow already published,
# pointing at a commit main already contains. Otherwise a write-access user
# could plant a v99.99.99 tag on unreviewed content and backfill-publish it.
if [ -n "${GH_TOKEN:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  release_meta="$(gh release view "$tag" --repo "$GITHUB_REPOSITORY" \
    --json author,targetCommitish -q '.author.login + " " + .targetCommitish' \
    2>/dev/null)" || {
    printf '%s\n' "::error::no GitHub release exists for tag $tag"
    exit 1
  }
  release_author="${release_meta%% *}"
  release_target="${release_meta##* }"
  # A hand-created release on a valid tag does not qualify. Not a hard bound
  # (a workflow run can mint a bot-authored release), but it removes the
  # cheapest path to publishing attacker-uploaded release assets.
  if [ "$release_author" != "github-actions[bot]" ]; then
    printf '%s\n' "::error::release $tag was authored by $release_author, not the release automation"
    exit 1
  fi
  # Same boundary for the assets the npm backfill republishes: a release
  # asset replaced by a collaborator login is attacker-mutable content. The
  # captured name/id pairs go to GITHUB_OUTPUT so the download step fetches
  # by immutable asset id; a delete+reupload between here and the download
  # produces a new id and fails closed. Names are emitted base64-encoded:
  # an asset name is attacker-controlled text, and whitespace in it would
  # otherwise let a crafted name shift the positional fields.
  assets="$(gh api "repos/$GITHUB_REPOSITORY/releases/tags/$tag" \
    -q '.assets[] | (.name | @base64) + " " + (.id | tostring) + " " + (.uploader.login // "unknown")')"
  uploaders="$(printf '%s\n' "$assets" | awk 'NF {print $3}' | sort -u)"
  if [ -n "$uploaders" ] && [ "$uploaders" != "github-actions[bot]" ]; then
    printf '%s\n' "::error::release $tag has assets not uploaded by the release automation: $uploaders"
    exit 1
  fi
  {
    printf '%s\n' 'assets<<GHAE'
    printf '%s\n' "$assets" | awk 'NF {print $1, $2}'
    printf '%s\n' 'GHAE'
  } >> "$GITHUB_OUTPUT"
  # Resolve through the fully-qualified tag ref to a commit SHA: an
  # unqualified name can resolve to a same-named branch and vouch for the
  # wrong commit, the same shadowing the refs/tags/ checkout prefix avoids.
  # The SHA is emitted so checkouts pin the verified commit instead of
  # re-resolving a tag that could be moved between resolve and checkout.
  tag_commit="$(gh api "repos/$GITHUB_REPOSITORY/commits/refs/tags/$tag" -q .sha)"
  # The tag must still point at the commit the release was created against.
  # Reachable-from-main alone accepts a tag moved to any other main commit.
  if [ "$tag_commit" != "$release_target" ]; then
    printf '%s\n' "::error::tag $tag points at $tag_commit but release $tag was created against $release_target (tag moved)"
    exit 1
  fi
  status="$(gh api "repos/$GITHUB_REPOSITORY/compare/main...$tag_commit" -q .status)"
  case "$status" in
    identical|behind) ;;
    *)
      printf '%s\n' "::error::tag $tag is not reachable from main (compare: $status)"
      exit 1
      ;;
  esac
  printf '%s\n' "tag_commit=$tag_commit" >> "$GITHUB_OUTPUT"
fi

printf '%s\n' "tag=$tag" >> "$GITHUB_OUTPUT"
printf '%s\n' "version=${tag#v}" >> "$GITHUB_OUTPUT"

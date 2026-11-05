#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
resolver="$repo_root/scripts/resolve-release-tag.sh"
test_tmp="$(mktemp -d)"
trap 'rm -r -- "$test_tmp"' EXIT

# The non-stub invocations must not see ambient CI credentials: with GH_TOKEN
# and GITHUB_REPOSITORY exported, the resolver takes its provenance branch and
# calls the real gh, so the suite's outcome would depend on the environment.
valid_output="$test_tmp/valid-output"
env -u GH_TOKEN -u GITHUB_REPOSITORY GITHUB_OUTPUT="$valid_output" \
  "$resolver" "v1.2.3"

expected_output="$test_tmp/expected-output"
printf '%s\n' "tag=v1.2.3" "version=1.2.3" > "$expected_output"
cmp "$expected_output" "$valid_output"

newline_output="$test_tmp/newline-output"
newline_stdout="$test_tmp/newline-stdout"
newline_stderr="$test_tmp/newline-stderr"
if env -u GH_TOKEN -u GITHUB_REPOSITORY GITHUB_OUTPUT="$newline_output" \
  "$resolver" $'v1.2.3\nname=owned' \
  > "$newline_stdout" 2> "$newline_stderr"
then
  printf '%s\n' "newline-containing release tag unexpectedly passed" >&2
  exit 1
fi
test ! -s "$newline_output"
grep -qxF "::error::release tag is empty or contains invalid characters" "$newline_stdout"
test ! -s "$newline_stderr"

empty_output="$test_tmp/empty-output"
if env -u GH_TOKEN -u GITHUB_REPOSITORY GITHUB_OUTPUT="$empty_output" \
  "$resolver" ""; then
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
  "V1.2.3" \
  "v1atest" \
  "v1.2.3.4.5" \
  "v1_x" \
  "v1-any-branch-name" \
  "v1" \
  "v1.2." \
  "v1..3"
do
  : > "$invalid_output"
  if env -u GH_TOKEN -u GITHUB_REPOSITORY GITHUB_OUTPUT="$invalid_output" \
    "$resolver" "$invalid_tag"; then
    printf '%s\n' "invalid release tag unexpectedly passed: $invalid_tag" >&2
    exit 1
  fi
  test ! -s "$invalid_output"
done

# The resolver's provenance branch, exercised against a stubbed gh. With a
# token present the tag must name an existing GitHub release and its commit
# must already be reachable from main (compare status identical|behind).
# ahead/diverged or a missing release must fail closed: a write-access user
# could otherwise plant a vX.Y.Z tag on unreviewed content and backfill it.
stub_bin="$test_tmp/stub-bin"
mkdir -p "$stub_bin"
cat > "$stub_bin/gh" <<'STUB'
#!/usr/bin/env bash
# Match the full command line, not a path fragment: an unrecognized call exits
# 1 and names itself on stderr, so a new or mistyped gh call site fails loudly
# instead of receiving a silently stubbed answer.
# Every arm runs the resolver's own -q expression through real jq on a
# fixture response: a mutated or dropped field in the expression misparses
# the same way it would against the live API.
run_jq() {
  expr=""
  prev=""
  for a in "$@"; do
    if [ "$prev" = "-q" ]; then expr="$a"; fi
    prev="$a"
  done
  jq -r "$expr"
}
case "$*" in
  "release view "*" --repo Gitlawb/node --json author,targetCommitish "*)
    [ "${STUB_RELEASE_EXISTS:-0}" = "1" ] || exit 1
    printf '%s\n' '{"author":{"login":"'"${STUB_RELEASE_AUTHOR:-github-actions[bot]}"'"},"targetCommitish":"'"${STUB_TARGET:-0000000000000000000000000000000000000000}"'"}' \
      | run_jq "$@"
    ;;
  "api repos/Gitlawb/node/releases/tags/"*" "*)
    # STUB_EVIL_NAME simulates an attacker-crafted asset name carrying a fake
    # uploader inside it; base64 keeps it a single first field and the real
    # uploader stays in $3, while a raw name lets the smuggled field through.
    fixture='{"assets":[{"name":"gitlawb-node-9.9.9-x86_64-unknown-linux-musl.tar.gz","id":11,"uploader":{"login":"'"${STUB_UPLOADERS:-github-actions[bot]}"'"}}'
    if [ "${STUB_EVIL_NAME:-0}" = "1" ]; then
      fixture="$fixture"',{"name":"gitlawb-node-9.9.9-x86_64-unknown-linux-musl.tar.gz 999 github-actions[bot]","id":999,"uploader":{"login":"collaborator"}}'
    fi
    printf '%s\n' "$fixture"']}' | run_jq "$@"
    ;;
  "api repos/Gitlawb/node/commits/refs/tags/"*" "*)
    printf '%s\n' '{"sha":"0000000000000000000000000000000000000000"}' \
      | run_jq "$@"
    ;;
  "api repos/Gitlawb/node/commits/"*" "*)
    # A bare tag name resolves through refs/heads before refs/tags. Return a
    # different SHA so a resolver that dropped the refs/tags/ qualification
    # reads the same-named branch's commit and the tag-moved check fires.
    printf '%s\n' '{"sha":"1111111111111111111111111111111111111111"}' \
      | run_jq "$@"
    ;;
  "api repos/Gitlawb/node/compare/main..."*" "*)
    printf '%s\n' '{"status":"'"${STUB_STATUS:?STUB_STATUS unset}"'"}' \
      | run_jq "$@"
    ;;
  *)
    printf 'unexpected gh call: %s\n' "$*" >&2
    exit 1
    ;;
esac
STUB
chmod +x "$stub_bin/gh"

run_resolver_ci() {
  PATH="$stub_bin:$PATH" \
  GH_TOKEN=test-token \
  GITHUB_REPOSITORY=Gitlawb/node \
  STUB_STATUS="$1" STUB_RELEASE_EXISTS="$2" \
  STUB_RELEASE_AUTHOR="${4:-github-actions[bot]}" \
  STUB_UPLOADERS="${5:-github-actions[bot]}" \
  STUB_TARGET="${6:-0000000000000000000000000000000000000000}" \
  STUB_EVIL_NAME="${STUB_EVIL_NAME:-0}" \
  GITHUB_OUTPUT="$test_tmp/prov-output" \
    "$resolver" "$3" >"$test_tmp/prov-stdout" 2>"$test_tmp/prov-stderr"
}

if ! run_resolver_ci behind 1 v9.9.9; then
  cat "$test_tmp/prov-stderr" >&2
  printf '%s\n' "provenance: release tag reachable from main rejected" >&2
  exit 1
fi
# The resolved SHA and the captured asset name/id map must reach
# GITHUB_OUTPUT: checkouts pin the SHA, and the binary download step fetches
# by immutable asset id.
if ! grep -qx 'tag_commit=0000000000000000000000000000000000000000' \
    "$test_tmp/prov-output"; then
  printf '%s\n' "provenance: tag_commit output missing" >&2
  exit 1
fi
want_b64="$(printf '%s' 'gitlawb-node-9.9.9-x86_64-unknown-linux-musl.tar.gz' | base64 -w0)"
if ! grep -q 'assets<<GHAE' "$test_tmp/prov-output" \
    || ! grep -qx "$want_b64 11" "$test_tmp/prov-output"; then
  printf '%s\n' "provenance: assets output missing" >&2
  exit 1
fi
# An unterminated heredoc block would swallow tag_commit= into the multiline
# value and leave the checkout-pinning output empty.
if ! awk '
  /^assets<<GHAE$/ { open = 1; next }
  open && /^GHAE$/ { open = 0; term = 1; next }
  /^tag_commit=/ { if (open) bad = 1; seen = 1 }
  END { exit !(term && seen && !bad) }
' "$test_tmp/prov-output"; then
  printf '%s\n' "provenance: assets block missing its GHAE terminator" >&2
  exit 1
fi
if ! run_resolver_ci identical 1 v9.9.9; then
  cat "$test_tmp/prov-stderr" >&2
  printf '%s\n' "provenance: release tag at main tip rejected" >&2
  exit 1
fi
for bad_status in ahead diverged; do
  if run_resolver_ci "$bad_status" 1 v9.9.9; then
    printf '%s\n' "provenance: $bad_status tag unexpectedly passed" >&2
    exit 1
  fi
done
if run_resolver_ci behind 0 v9.9.9; then
  printf '%s\n' "provenance: tag with no GitHub release unexpectedly passed" >&2
  exit 1
fi
if run_resolver_ci behind 1 v9.9.9 collaborator; then
  printf '%s\n' "provenance: hand-created release unexpectedly passed" >&2
  exit 1
fi
if run_resolver_ci behind 1 v9.9.9 "github-actions[bot]" collaborator; then
  printf '%s\n' "provenance: release with collaborator-uploaded assets unexpectedly passed" >&2
  exit 1
fi
# A tag moved to a different main commit: compare would say behind, but the
# tag no longer matches the commit the release was created against.
if run_resolver_ci behind 1 v9.9.9 \
    "github-actions[bot]" "github-actions[bot]" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; then
  printf '%s\n' "provenance: moved tag unexpectedly passed" >&2
  exit 1
fi
# A crafted asset name smuggling a fake uploader string: the real uploader
# stays in the third field once names are base64-encoded.
if STUB_EVIL_NAME=1 run_resolver_ci behind 1 v9.9.9; then
  printf '%s\n' "provenance: crafted asset name unexpectedly passed" >&2
  exit 1
fi
# The stub's contract is loud failure: a call it does not recognize must exit
# non-zero and name the command line on stderr, so a resolver that gains a new
# gh call cannot pass on a silently empty stubbed answer.
if "$stub_bin/gh" api repos/Gitlawb/node/rate_limit >"$test_tmp/unexp-out" \
    2>"$test_tmp/unexp-err"; then
  printf '%s\n' "stub accepted an unrecognized gh call" >&2
  exit 1
fi
if ! grep -qF 'unexpected gh call: api repos/Gitlawb/node/rate_limit' \
    "$test_tmp/unexp-err"; then
  printf '%s\n' "stub's unrecognized-call stderr did not name the command line" >&2
  exit 1
fi

release_workflow="$repo_root/.github/workflows/release.yml"
actual_resolver_steps="$test_tmp/actual-resolver-steps"
expected_resolver_steps="$test_tmp/expected-resolver-steps"

# Pin each resolver step, the checkout step that supplies its script, and the
# steps that publish to an external registry or fetch the publish input. Any
# change to one of these reviewed blocks must be reflected here deliberately.
awk '
  function emit_step() {
    if (in_step && (is_rel || is_workflow_scripts_checkout || is_manifest || is_moving || is_npm_publish || is_layin || is_tag_checkout || is_regen)) {
      printf "job=%s\n%s", job, step
    }
    in_step = 0
    is_rel = 0
    is_workflow_scripts_checkout = 0
    is_manifest = 0
    is_moving = 0
    is_npm_publish = 0
    is_layin = 0
    is_tag_checkout = 0
    is_regen = 0
    step = ""
  }

  /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    emit_step()
    job = $0
    sub(/^  /, "", job)
    sub(/:[[:space:]]*$/, "", job)
    next
  }

  /^      - / {
    emit_step()
    in_step = 1
    is_workflow_scripts_checkout = ($0 ~ /^      - name:[[:space:]]*Check out workflow scripts[[:space:]]*$/)
    is_manifest = ($0 ~ /^      - name:[[:space:]]*Create and push multi-arch manifest[[:space:]]*$/)
    is_moving = ($0 ~ /^      - name:[[:space:]]*Move floating tags[[:space:]]*$/)
    is_npm_publish = ($0 ~ /^      - name:[[:space:]]*Publish[[:space:]]*$/)
    is_layin = ($0 ~ /^      - name:[[:space:]]*Lay in release binaries[[:space:]]*$/)
    is_tag_checkout = ($0 ~ /^      - name:[[:space:]]*Checkout release tag[[:space:]]*$/ || $0 ~ /^      - name:[[:space:]]*Checkout node \(release tag\)[[:space:]]*$/)
    is_regen = ($0 ~ /^      - name:[[:space:]]*Regenerate formula[[:space:]]*$/)
    step = $0 ORS
    next
  }

  in_step {
    step = step $0 ORS
    if ($0 ~ /^        id:[[:space:]]*rel[[:space:]]*$/) {
      is_rel = 1
    }
  }

  END {
    emit_step()
  }
' "$release_workflow" > "$actual_resolver_steps"

# The fixture embeds the formula step's own indented heredoc terminator;
# inside this quoted heredoc it is data, not a directive to bash.
# shellcheck disable=SC1039
cat > "$expected_resolver_steps" <<'EOF'
job=docker
      - name: Check out workflow scripts
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false

job=docker
      - name: Resolve release tag
        id: rel
        env:
          DISPATCH_TAG: ${{ inputs.docker_backfill_tag }}
          RELEASE_TAG: ${{ needs.release-please.outputs.tag_name }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail
          scripts/resolve-release-tag.sh "${DISPATCH_TAG:-$RELEASE_TAG}"
          # ghcr requires a lowercase repository path, and unlike metadata-action,
          # buildx's `--output name=` does no lowercasing — a mixed-case owner
          # makes the digest push fail with "invalid reference format".
          echo "image=ghcr.io/${GITHUB_REPOSITORY,,}" >> "$GITHUB_OUTPUT"

job=docker
      - name: Checkout release tag
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          # Pin the commit the resolver verified; a tag ref re-resolved here
          # could have been moved between resolve and checkout.
          ref: ${{ steps.rel.outputs.tag_commit || format('refs/tags/{0}', steps.rel.outputs.tag) }}
          persist-credentials: false

job=docker-manifest
      - name: Check out workflow scripts
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false

job=docker-manifest
      - name: Resolve release tag
        id: rel
        env:
          DISPATCH_TAG: ${{ inputs.docker_backfill_tag }}
          RELEASE_TAG: ${{ needs.release-please.outputs.tag_name }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail
          scripts/resolve-release-tag.sh "${DISPATCH_TAG:-$RELEASE_TAG}"
          # ghcr requires a lowercase repository path, and unlike metadata-action,
          # buildx's `--output name=` does no lowercasing, so a mixed-case owner
          # makes the digest push fail with "invalid reference format".
          echo "image=ghcr.io/${GITHUB_REPOSITORY,,}" >> "$GITHUB_OUTPUT"

job=docker-manifest
      - name: Create and push multi-arch manifest
        id: manifest
        env:
          VERSION: ${{ steps.rel.outputs.version }}
          IMAGE: ${{ steps.rel.outputs.image }}
        run: |
          set -euo pipefail
          # The docker matrix pushes one digest per arch leg; anything else is
          # a broken set, not a smaller multi-arch image.
          count="$(find /tmp/digests -maxdepth 1 -type f | wc -l)"
          if [ "$count" -ne 2 ]; then
            echo "::error::expected 2 arch digests in /tmp/digests, found $count"
            exit 1
          fi
          digests=""
          for f in /tmp/digests/*; do
            d="$(basename "$f")"
            case "$d" in
              *[!0-9a-f]*)
                echo "::error::digest filename is not lowercase sha256 hex: $d"
                exit 1
                ;;
            esac
            if [ "${#d}" -ne 64 ]; then
              echo "::error::digest is not 64 hex chars: $d"
              exit 1
            fi
            digests="$digests $IMAGE@sha256:$d"
          done
          # The immutable tag always publishes. The moving tags are applied by
          # the gated step below, which never runs on workflow_dispatch.
          # shellcheck disable=SC2086
          docker buildx imagetools create -t "$IMAGE:$VERSION" $digests
          docker buildx imagetools inspect "$IMAGE:$VERSION"
          echo "digests=${digests# }" >> "$GITHUB_OUTPUT"

job=docker-manifest
      - name: Move floating tags
        if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}
        env:
          VERSION: ${{ steps.rel.outputs.version }}
          IMAGE: ${{ steps.rel.outputs.image }}
          DIGESTS: ${{ steps.manifest.outputs.digests }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail
          MAJOR_MINOR="${VERSION%.*}"
          # :latest and :X.Y track the newest release. Only a push to main
          # carries a release-please-cut version, and release-please versions
          # are monotonic, so on this path the tags only ever advance. A
          # workflow_dispatch backfill republishes an existing tag and must
          # never move a pointer, so this step skips on dispatch. After a
          # backfill that is genuinely newest in its minor line, advance :X.Y
          # by hand: docker buildx imagetools create -t "$IMAGE:X.Y" <digests>.
          # The event gate alone does not bound a stale run: re-running an
          # older push run replays its stored needs outputs under the
          # original event and ref, and would move the pointers backward to
          # that run's version. Floor against live state instead: this run's
          # release already exists by now, so VERSION must be the newest
          # published release or the run is stale and the tags stay put.
          floor="$(gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100" -q '
            [ .[] | select(.draft == false) | .tag_name
              | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))
              | ltrimstr("v") | split(".") | map(tonumber) ]
            | if length == 0 then "" else max | join(".") end')" || {
            echo "::error::could not list releases to bound the moving tags"
            exit 1
          }
          if [ -n "$floor" ] && [ "$floor" != "$VERSION" ]; then
            echo "::error::release v$floor is newer than this run's v$VERSION; refusing to move the moving tags backward (stale re-run?)"
            exit 1
          fi
          # shellcheck disable=SC2086
          docker buildx imagetools create -t "$IMAGE:latest" -t "$IMAGE:$MAJOR_MINOR" $DIGESTS

job=release-binaries
      - name: Check out workflow scripts
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false

job=release-binaries
      - name: Resolve release tag
        id: rel
        env:
          RELEASE_TAG: ${{ needs.release-please.outputs.tag_name }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        shell: bash # matrix includes windows-latest, where run: defaults to pwsh
        run: |
          set -euo pipefail
          scripts/resolve-release-tag.sh "$RELEASE_TAG"

job=release-binaries
      - name: Checkout release tag
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          # Pin the commit the resolver verified; a tag ref re-resolved here
          # could have been moved between resolve and checkout.
          ref: ${{ steps.rel.outputs.tag_commit || format('refs/tags/{0}', steps.rel.outputs.tag) }}
          persist-credentials: false

job=npm-publish
      - name: Check out workflow scripts
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false

job=npm-publish
      - name: Resolve release tag
        id: rel
        env:
          DISPATCH_TAG: ${{ inputs.npm_backfill_tag }}
          RELEASE_TAG: ${{ needs.release-please.outputs.tag_name }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail
          scripts/resolve-release-tag.sh "${DISPATCH_TAG:-$RELEASE_TAG}"

job=npm-publish
      - name: Checkout release tag
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          # Pin the commit the resolver verified; a tag ref re-resolved here
          # could have been moved between resolve and checkout.
          ref: ${{ steps.rel.outputs.tag_commit || format('refs/tags/{0}', steps.rel.outputs.tag) }}
          persist-credentials: false

      # npm >= 11.5.1 performs the OIDC token exchange automatically when the
      # package has a trusted publisher configured; older npm silently falls
      # back to (absent) token auth and fails confusingly.
job=npm-publish
      - name: Lay in release binaries
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VERSION: ${{ steps.rel.outputs.version }}
          TAG: ${{ steps.rel.outputs.tag }}
          ASSETS: ${{ steps.rel.outputs.assets }}
        run: |
          set -euo pipefail
          # npm platform package -> Rust target triple (unix only; Windows is not
          # published to npm).
          MAP="
          gl-darwin-arm64:aarch64-apple-darwin
          gl-darwin-x64:x86_64-apple-darwin
          gl-linux-arm64:aarch64-unknown-linux-musl
          gl-linux-x64:x86_64-unknown-linux-musl
          "
          mkdir -p _dl
          for entry in $MAP; do
            pkg="${entry%%:*}"
            target="${entry#*:}"
            archive="gitlawb-node-${VERSION}-${target}.tar.gz"
            echo "==> $pkg <- $archive"
            # Download by the asset id the resolver captured and uploader-
            # checked, not by name: release assets are mutable, and an id can
            # only ever point at the exact blob captured at resolve time.
            # The map keys are base64-encoded asset names.
            want="$(printf '%s' "$archive" | base64 -w0)"
            asset_id="$(printf '%s\n' "$ASSETS" | awk -v n="$want" '$1 == n {print $2; exit}')"
            if [ -z "$asset_id" ]; then
              echo "::error::release $TAG has no asset $archive captured at resolve time"
              exit 1
            fi
            gh api "repos/$GITHUB_REPOSITORY/releases/assets/$asset_id" \
              -H 'Accept: application/octet-stream' > "_dl/$archive"
            tar -xzf "_dl/$archive" -C _dl
            src="_dl/gitlawb-node-${VERSION}-${target}"
            cp "$src/gl" "npm/packages/$pkg/gl"
            cp "$src/git-remote-gitlawb" "npm/packages/$pkg/git-remote-gitlawb"
            chmod +x "npm/packages/$pkg/gl" "npm/packages/$pkg/git-remote-gitlawb"
          done

job=npm-publish
      - name: Publish
        env:
          VERSION: ${{ steps.rel.outputs.version }}
        run: |
          set -euo pipefail
          # No token: npm exchanges this job's GitHub OIDC identity with the
          # registry (trusted publishing); provenance is attested automatically.
          # Platform packages first, then the wrapper (so its optionalDependencies resolve).
          # Skip versions already on the registry so a rerun after a partial publish
          # is idempotent instead of erroring on the first existing package.
          # npm publish moves the latest dist-tag to whatever it publishes, so a
          # backfilled older version would hand :latest to stale code. Decide
          # the dist-tag per package from that package's own registry latest:
          # a partial publish can leave the platform packages ahead of the
          # wrapper. E404 means the package has never been published, so this
          # release gets latest; any other lookup failure must fail closed
          # rather than guess at the dist-tag and risk moving latest backward.
          for pkg in gl-darwin-arm64 gl-darwin-x64 gl-linux-arm64 gl-linux-x64 gl; do
            name="@gitlawb/$pkg"
            if npm view "$name@$VERSION" version >/dev/null 2>&1; then
              echo "==> $name@$VERSION already published, skipping"
              continue
            fi
            registry_latest="$(npm view "$name" dist-tags.latest 2>&1)" || {
              if ! grep -q E404 <<<"$registry_latest"; then
                printf '%s\n' "$registry_latest" >&2
                echo "::error::npm dist-tags lookup failed for $name; not guessing the dist-tag"
                exit 1
              fi
              registry_latest=""
            }
            dist_tag="latest"
            if [ -n "$registry_latest" ] && \
               [ "$VERSION" != "$(printf '%s\n%s\n' "$registry_latest" "$VERSION" | sort -V | tail -1)" ]; then
              dist_tag="backfill"
              echo "::notice::$VERSION is older than $name@$registry_latest; publishing under dist-tag backfill"
            fi
            echo "==> npm publish $name@$VERSION (dist-tag $dist_tag)"
            npm publish "npm/packages/$pkg" --provenance --access public --tag "$dist_tag"
          done

job=homebrew-bump
      - name: Check out workflow scripts
        if: ${{ steps.guard.outputs.enabled == 'true' }}
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false

job=homebrew-bump
      - name: Resolve release tag
        if: ${{ steps.guard.outputs.enabled == 'true' }}
        id: rel
        env:
          RELEASE_TAG: ${{ needs.release-please.outputs.tag_name }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail
          scripts/resolve-release-tag.sh "$RELEASE_TAG"

job=homebrew-bump
      - name: Regenerate formula
        if: ${{ steps.guard.outputs.enabled == 'true' }}
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VERSION: ${{ steps.rel.outputs.version }}
          TAG: ${{ steps.rel.outputs.tag }}
          ASSETS: ${{ steps.rel.outputs.assets }}
        run: |
          set -euo pipefail
          base="https://github.com/${GITHUB_REPOSITORY}/releases/download/${TAG}"
          mkdir -p _sums
          # Hash the tarballs themselves, fetched by the asset id the resolver
          # captured and uploader-checked. The *.sha256 sidecars are mutable
          # release assets too; trusting them would trust the same surface.
          sha() {
            archive="gitlawb-node-${VERSION}-$1.tar.gz"
            want="$(printf '%s' "$archive" | base64 -w0)"
            asset_id="$(printf '%s\n' "$ASSETS" | awk -v n="$want" '$1 == n {print $2; exit}')"
            if [ -z "$asset_id" ]; then
              echo "::error::release $TAG has no asset $archive captured at resolve time" >&2
              exit 1
            fi
            # errexit is off inside the $(...) this runs under, so a failed
            # download must exit the function itself instead of hashing a
            # truncated file.
            gh api "repos/$GITHUB_REPOSITORY/releases/assets/$asset_id" \
              -H 'Accept: application/octet-stream' > "_sums/$archive" \
              || exit 1
            sha256sum "_sums/$archive" | awk '{print $1}'
          }
          SHA_MAC_ARM="$(sha aarch64-apple-darwin)"
          SHA_MAC_X64="$(sha x86_64-apple-darwin)"
          SHA_LNX_ARM="$(sha aarch64-unknown-linux-musl)"
          SHA_LNX_X64="$(sha x86_64-unknown-linux-musl)"

          mkdir -p tap/Formula
          cat > tap/Formula/gl.rb <<EOF
          class Gl < Formula
            desc "Twigpine CLI — decentralized git for AI agents and developers"
            homepage "https://twigpine.com"
            version "${VERSION}"
            license "MIT OR Apache-2.0"

            on_macos do
              on_arm do
                url "${base}/gitlawb-node-${VERSION}-aarch64-apple-darwin.tar.gz"
                sha256 "${SHA_MAC_ARM}"
              end
              on_intel do
                url "${base}/gitlawb-node-${VERSION}-x86_64-apple-darwin.tar.gz"
                sha256 "${SHA_MAC_X64}"
              end
            end

            on_linux do
              on_arm do
                url "${base}/gitlawb-node-${VERSION}-aarch64-unknown-linux-musl.tar.gz"
                sha256 "${SHA_LNX_ARM}"
              end
              on_intel do
                url "${base}/gitlawb-node-${VERSION}-x86_64-unknown-linux-musl.tar.gz"
                sha256 "${SHA_LNX_X64}"
              end
            end

            def install
              bin.install "gl"
              bin.install "git-remote-gitlawb"
            end

            def caveats
              <<~CAVEATS
                oh-my-zsh's git plugin aliases gl='git pull', which shadows this
                binary in interactive shells. If \`gl\` prints "fatal: not a git
                repository", run:
                  echo 'unalias gl 2>/dev/null' >> ~/.zshrc && source ~/.zshrc
              CAVEATS
            end

            test do
              assert_match version.to_s, shell_output("#{bin}/gl --version")
            end
          end
          EOF

job=web-sync
      - name: Check out workflow scripts
        if: ${{ steps.guard.outputs.enabled == 'true' }}
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false

job=web-sync
      - name: Resolve release tag
        if: ${{ steps.guard.outputs.enabled == 'true' }}
        id: rel
        env:
          RELEASE_TAG: ${{ needs.release-please.outputs.tag_name }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail
          scripts/resolve-release-tag.sh "$RELEASE_TAG"

job=web-sync
      - name: Checkout node (release tag)
        if: ${{ steps.guard.outputs.enabled == 'true' }}
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          # Pin the commit the resolver verified; a tag ref re-resolved here
          # could have been moved between resolve and checkout.
          ref: ${{ steps.rel.outputs.tag_commit || format('refs/tags/{0}', steps.rel.outputs.tag) }}
          path: node
          persist-credentials: false

EOF

if ! cmp "$expected_resolver_steps" "$actual_resolver_steps"; then
  printf '%s\n' \
    "release workflow resolver steps differ from the three reviewed blocks" >&2
  diff -u "$expected_resolver_steps" "$actual_resolver_steps" >&2 || true
  exit 1
fi

# The moving-tag freeze is a structural property of the whole workflow, so it
# must be checked over every step in `jobs:`, not only the pinned set above:
# a floating-tag push relocated into an unpinned step would otherwise iterate
# zero pinned steps and pass vacuously. The check keys on the outcome, not
# one argv spelling: any step whose code pairs a tag-pushing mechanism
# (imagetools create, docker push, a build-push-action tags: input, crane,
# regctl, skopeo, oras) with a mutable-tag reference (latest or MAJOR_MINOR)
# is a carrier, and exactly one may exist (the step named "Move floating
# tags"), gated on both the event and the ref. Matching on code text with
# comments stripped keeps a comment quoting either pattern from counting.
# The guard must sit on the step's if: line as a single && condition, so an
# ||-weakened or comment-borne condition cannot satisfy it. The carrier must
# also bound the move against live state: a re-run of an older push run
# replays stored outputs under the original event and ref, so the step must
# read the releases list and refuse (exit 1) rather than move the tags
# backward. No step may read the retired packages/container endpoint at all.
if ! awk '
  function decomment(s,   n, L, i, j, c, q, line, out) {
    n = split(s, L, "\n")
    out = ""
    for (i = 1; i <= n; i++) {
      line = ""
      q = 0
      for (j = 1; j <= length(L[i]); j++) {
        c = substr(L[i], j, 1)
        if (c == "\"") q = !q
        if (c == "#" && !q) break
        line = line c
      }
      out = out line "\n"
    }
    return out
  }
  function flush(  code, has_call, has_guard, has_floor, k, K) {
    if (!in_step) return
    code = decomment(step)
    has_call = (code ~ /imagetools[ \t]+create|docker[ \t]+push|docker[ \t]+buildx[ \t]+build|crane[ \t]|regctl[ \t]|skopeo[ \t]|oras[ \t]|tags:/ \
      && code ~ /latest|MAJOR_MINOR/)
    has_guard = 0
    k = split(code, K, "\n")
    for (i = 1; i <= k; i++) {
      if (K[i] ~ /^[ \t]+if:/ \
        && K[i] ~ /github\.event_name == .push.[ \t]*&&[ \t]*github\.ref == .refs\/heads\/main./) {
        has_guard = 1
      }
    }
    has_floor = (code ~ /releases[?\/]/ && code ~ /::error::/ \
      && code ~ /exit[ \t]+1/)
    if (has_call) {
      calls++
      if (!has_guard) ungated++
      if (!has_floor) unfloored++
    }
    if (code ~ /packages\/container/) endpoint++
  }
  /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
  in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { flush(); in_step = 0; next }
  in_jobs && /^      - / { flush(); in_step = 1; step = $0 ORS; next }
  in_jobs && in_step { step = step $0 ORS }
  END {
    flush()
    ok = 1
    if (calls != 1) {
      printf "expected exactly one moving-tag publish step, found %d\n", \
        calls > "/dev/stderr"
      ok = 0
    }
    if (ungated) {
      printf "%d moving-tag publish step(s) lack the push-to-main guard\n", \
        ungated > "/dev/stderr"
      ok = 0
    }
    if (unfloored) {
      printf "%d moving-tag publish step(s) lack the live release floor\n", \
        unfloored > "/dev/stderr"
      ok = 0
    }
    if (endpoint) {
      print "retired packages/container read present in a workflow step" \
        > "/dev/stderr"
      ok = 0
    }
    if (!ok) exit 1
  }
' "$release_workflow"; then
  exit 1
fi

# The gate is only as real as the trigger that can satisfy it: deleting the
# on.push.branches entry (or renaming the trigger) leaves "Move floating tags"
# unrunnable while every check above stays green, the silent-disable mirror
# of the defect this freeze fixes. Assert the triggers explicitly.
if ! awk '
  /^on:[ \t]*$/ { in_on = 1; next }
  in_on && /^[a-zA-Z]/ { in_on = 0 }
  in_on && /^  [A-Za-z_]+:/ {
    in_push = ($0 ~ /^  push:/)
    if ($0 ~ /^  workflow_dispatch:/) has_dispatch = 1
    next
  }
  in_on && in_push && /^      -[ \t]+main[ \t]*$/ { has_main = 1; has_push = 1 }
  END { exit !(has_push && has_main && has_dispatch) }
' "$release_workflow"; then
  printf '%s\n' \
    "release.yml no longer triggers on push to main with workflow_dispatch" >&2
  exit 1
fi

# Every job declares the protected environment, not only the registry publish
# jobs: workflow_dispatch runs the selected ref's YAML, so the environment's
# deployment-branch rule is the control that keeps a dispatch of unmodified
# YAML on a non-main ref from reaching any step in this workflow.
actual_job_environments="$test_tmp/actual-job-environments"
# Emit one line per job whether or not it declares an environment: a fixed
# list of environment lines would stay green if a new job were added without
# one, so completeness must come from the job set, not the declarations.
awk '
  /^jobs:[[:space:]]*$/ {
    in_jobs = 1
    next
  }
  in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    job = $0
    sub(/^  /, "", job)
    sub(/:[[:space:]]*$/, "", job)
    jobs[++n] = job
  }
  in_jobs && /^    environment:[[:space:]]*/ {
    env = $0
    sub(/^    environment:[[:space:]]*/, "", env)
    gsub(/[[:space:]]/, "", env)
    envs[job] = env
  }
  END {
    for (i = 1; i <= n; i++) {
      j = jobs[i]
      print j "=" ((j in envs) ? envs[j] : "MISSING")
    }
  }
' "$release_workflow" > "$actual_job_environments"

expected_job_environments="$test_tmp/expected-job-environments"
cat > "$expected_job_environments" <<'EOF'
release-please=release
sync-release-lock=release
docker=release
docker-manifest=release
release-binaries=release
npm-publish=release
homebrew-bump=release
web-sync=release
EOF

if ! cmp "$expected_job_environments" "$actual_job_environments"; then
  printf '%s\n' \
    "release workflow publish jobs differ on their environment gate" >&2
  diff -u "$expected_job_environments" "$actual_job_environments" >&2 || true
  exit 1
fi

# Every checkout of a release tag must qualify the ref as refs/tags/... :
# actions/checkout resolves an unqualified ref as a branch before a tag, so a
# same-named branch would shadow the release tag and the release would build
# from unreviewed branch content.
if grep -nE 'ref:[[:space:]]*\$\{\{[^}]*tag[^}]*\}\}' "$release_workflow" \
  | grep -v 'refs/tags/'; then
  printf '%s\n' "unqualified release-tag checkout ref (branch shadows tag)" >&2
  exit 1
fi

# The OIDC publish path must run on an exact npm version, not a range, and the
# pin must be proven, not only written: the install line could drift, be
# shadowed by a PATH entry, or install a resolved-otherwise version and
# nothing would notice. Every step that globally installs npm, under any
# spelling (`install` or `i`, `-g` or `--global`), must carry an exact
# npm@X.Y.Z spec, run `npm --version`, and compare something against that
# literal with `!=` or `==` outside the install spec itself. Comments are
# stripped first, so neither the spec nor the comparison can be satisfied by
# prose, and the required set derives from the workflow's own install lines,
# so a second install elsewhere cannot ride on the first step's assertion.
if ! awk '
  function decomment(s,   n, L, i, j, c, q, line, out) {
    n = split(s, L, "\n")
    out = ""
    for (i = 1; i <= n; i++) {
      line = ""
      q = 0
      for (j = 1; j <= length(L[i]); j++) {
        c = substr(L[i], j, 1)
        if (c == "\"") q = !q
        if (c == "#" && !q) break
        line = line c
      }
      out = out line "\n"
    }
    return out
  }
  function flush(  code, m, spec, v, ev, cmp, rest) {
    if (!in_step) return
    code = decomment(step)
    m = code
    while (match(m, /npm[ \t]+(i|install)[ \t]+(-g|--global)[ \t]+npm[^ \t\n"'"'"';&|]*/)) {
      spec = substr(m, RSTART, RLENGTH)
      installs++
      if (spec !~ /npm@[0-9]+\.[0-9]+\.[0-9]+$/) {
        printf "npm install spec is not an exact pinned version: %s\n", spec \
          > "/dev/stderr"
        bad = 1
      } else {
        v = spec
        sub(/^.*npm@/, "", v)
        ev = v
        gsub(/\./, "\\.", ev)
        cmp = "(!=|==)[ \t]*\"?" ev "\"?"
        rest = code
        gsub(/npm[ \t]+(i|install)[ \t]+(-g|--global)[ \t]+npm@[0-9]+\.[0-9]+\.[0-9]+/, "", rest)
        if (index(rest, "npm --version") == 0 || rest !~ cmp) {
          printf "step installs npm@%s without asserting the pin took\n", v \
            > "/dev/stderr"
          bad = 1
        }
      }
      m = substr(m, RSTART + RLENGTH)
    }
  }
  /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
  in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { flush(); in_step = 0; next }
  in_jobs && /^      - / { flush(); in_step = 1; step = $0 ORS; next }
  in_jobs && in_step { step = step $0 ORS }
  END {
    flush()
    if (!installs) {
      print "no npm install step found in release workflow" > "/dev/stderr"
      bad = 1
    }
    if (bad) exit 1
  }
' "$release_workflow"; then
  exit 1
fi

# Once a job's resolver step (id: rel) has run, nothing downstream may read
# needs.release-please.outputs.version/tag_name: the resolver is the boundary
# that proved the tag, and a second derivation of the same value can drift
# from what was verified. Every line of every step is scanned (including the
# - name:/if: line, where the first-line skip used to hide a read), every
# job-level line is scanned (an env: read there feeds all steps), and every
# job is in scope (a read in a job with no rel step is equally unverified).
# The only exemption is the rel step itself, which reads tag_name as its
# RELEASE_TAG input.
stale_reads="$test_tmp/stale-release-please-reads"
awk '
  function strip(line,   j, c, q, out) {
    out = ""
    q = 0
    for (j = 1; j <= length(line); j++) {
      c = substr(line, j, 1)
      if (c == "\"") q = !q
      if (c == "#" && !q) break
      out = out c
    }
    return out
  }
  function scan(line, where) {
    if (strip(line) ~ /needs\.release-please\.outputs\.(version|tag_name)/) {
      flagged[++nf] = job " :: " where " :: " line
    }
  }
  function flush(  n, L, i) {
    if (!in_step) return
    if (step ~ /\n        id:[[:space:]]*rel[[:space:]]*\n/) return
    n = split(step, L, "\n")
    for (i = 1; i <= n; i++) scan(L[i], L[1])
  }
  /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
  in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    flush()
    job = $0
    sub(/^  /, "", job)
    sub(/:[[:space:]]*$/, "", job)
    in_step = 0
    next
  }
  in_jobs && /^      - / { flush(); in_step = 1; step = $0 ORS; next }
  in_jobs && !in_step { scan($0, "(job level)") }
  in_jobs && in_step { step = step $0 ORS }
  END {
    flush()
    for (i = 1; i <= nf; i++) print flagged[i]
  }
' "$release_workflow" > "$stale_reads"

if [ -s "$stale_reads" ]; then
  printf '%s\n' \
    "post-resolve steps read release-please outputs instead of the resolver's:" \
    >&2
  cat "$stale_reads" >&2
  exit 1
fi

printf '%s\n' "release tag validation tests passed"

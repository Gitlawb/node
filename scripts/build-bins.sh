#!/bin/bash
# Build gl and git-remote-gitlawb binaries for all platforms.
# Output goes to web/public/bin/
#
# Usage:
#   ./scripts/build-bins.sh                       # linux-x86_64 + linux-arm64
#   ./scripts/build-bins.sh linux-x86_64          # single platform
#   ./scripts/build-bins.sh darwin-arm64          # native macOS build

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
OUT="$ROOT/web/public/bin"

mkdir -p "$OUT"

build_linux() {
  local PLATFORM="$1"
  local DOCKER_PLATFORM="$2"
  local RUST_TARGET="$3"

  echo ""
  echo "==> Building $PLATFORM (musl static, docker: $DOCKER_PLATFORM)..."

  docker build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg "TARGET=$RUST_TARGET" \
    -f "$ROOT/Dockerfile.bins" \
    -t "gitlawb-bins-$PLATFORM" \
    "$ROOT"

  local CONTAINER
  CONTAINER=$(docker create --platform "$DOCKER_PLATFORM" "gitlawb-bins-$PLATFORM")
  docker cp "$CONTAINER:/gl" "$OUT/gl-$PLATFORM"
  docker cp "$CONTAINER:/git-remote-gitlawb" "$OUT/git-remote-gitlawb-$PLATFORM"
  docker rm "$CONTAINER"

  chmod +x "$OUT/gl-$PLATFORM" "$OUT/git-remote-gitlawb-$PLATFORM"
  echo "  ✓ $OUT/gl-$PLATFORM"
  echo "  ✓ $OUT/git-remote-gitlawb-$PLATFORM"
}

build_darwin_arm64() {
  echo ""
  echo "==> Building darwin-arm64 (native cargo)..."
  cd "$ROOT"
  export PATH="$HOME/.cargo/bin:$PATH"
  cargo build --release -p gl -p git-remote-gitlawb
  cp target/release/gl "$OUT/gl-darwin-arm64"
  cp target/release/git-remote-gitlawb "$OUT/git-remote-gitlawb-darwin-arm64"
  chmod +x "$OUT/gl-darwin-arm64" "$OUT/git-remote-gitlawb-darwin-arm64"
  echo "  ✓ $OUT/gl-darwin-arm64"
  echo "  ✓ $OUT/git-remote-gitlawb-darwin-arm64"
}

PLATFORMS="${*:-linux-x86_64 linux-arm64}"

for PLATFORM in $PLATFORMS; do
  case "$PLATFORM" in
    linux-x86_64) build_linux linux-x86_64 linux/amd64 x86_64-unknown-linux-musl ;;
    linux-arm64)  build_linux linux-arm64  linux/arm64 aarch64-unknown-linux-musl ;;
    darwin-arm64) build_darwin_arm64 ;;
    *)
      echo "Unknown platform: $PLATFORM" >&2
      echo "Supported: linux-x86_64 linux-arm64 darwin-arm64" >&2
      exit 1
      ;;
  esac
done

echo ""
echo "Done. Binaries in $OUT:"
ls -lh "$OUT"

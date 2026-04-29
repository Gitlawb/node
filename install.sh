#!/usr/bin/env bash
# gitlawb installer — downloads pre-built binaries from GitHub Releases
# Usage:  curl -sSf https://gitlawb.com/install.sh | sh
#         curl -sSf https://gitlawb.com/install.sh | sh -s -- --version v0.1.2
set -euo pipefail

REPO="gitlawb/releases"
INSTALL_DIR="${GITLAWB_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${1:-latest}"  # pass --version vX.Y.Z or leave empty for latest

# ── Detect OS and arch ────────────────────────────────────────────────────
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Linux)  OS_NAME="linux" ;;
  Darwin) OS_NAME="darwin" ;;
  *)
    echo "error: unsupported OS: $OS"
    echo "       please build from source: cargo install --git https://github.com/$REPO gl"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)          ARCH_NAME="x86_64" ;;
  aarch64 | arm64) ARCH_NAME="aarch64" ;;
  *)
    echo "error: unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# Rust target triple
case "${OS_NAME}-${ARCH_NAME}" in
  linux-x86_64)   TARGET="x86_64-unknown-linux-musl" ;;
  linux-aarch64)  TARGET="aarch64-unknown-linux-musl" ;;
  darwin-x86_64)  TARGET="x86_64-apple-darwin" ;;
  darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
esac

# ── Resolve version ───────────────────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
  echo "Fetching latest release version..."
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  if [ -z "$VERSION" ]; then
    echo "error: could not determine latest release. Check https://github.com/${REPO}/releases"
    exit 1
  fi
fi

ARCHIVE="gitlawb-${VERSION}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

echo "Installing gitlawb ${VERSION} for ${OS_NAME}/${ARCH_NAME}"
echo "  Archive:  ${ARCHIVE}"
echo "  Into:     ${INSTALL_DIR}"
echo ""

# ── Download ──────────────────────────────────────────────────────────────
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading..."
if ! curl -fSL --progress-bar -o "$TMP_DIR/$ARCHIVE" "$DOWNLOAD_URL"; then
  echo ""
  echo "error: download failed: $DOWNLOAD_URL"
  echo "       Check https://github.com/${REPO}/releases for available builds."
  exit 1
fi

# ── Verify checksum ───────────────────────────────────────────────────────
if curl -fsSL -o "$TMP_DIR/$ARCHIVE.sha256" "$CHECKSUM_URL" 2>/dev/null; then
  echo "Verifying checksum..."
  EXPECTED=$(awk '{print $1}' "$TMP_DIR/$ARCHIVE.sha256")
  if command -v sha256sum &>/dev/null; then
    ACTUAL=$(sha256sum "$TMP_DIR/$ARCHIVE" | awk '{print $1}')
  elif command -v shasum &>/dev/null; then
    ACTUAL=$(shasum -a 256 "$TMP_DIR/$ARCHIVE" | awk '{print $1}')
  else
    echo "warning: no sha256 tool found, skipping checksum verification"
    ACTUAL="$EXPECTED"
  fi
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "error: checksum mismatch!"
    echo "  expected: $EXPECTED"
    echo "  actual:   $ACTUAL"
    exit 1
  fi
  echo "  ✓ checksum OK"
fi

# ── Extract and install ───────────────────────────────────────────────────
echo "Extracting..."
tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"

mkdir -p "$INSTALL_DIR"

# Write to a staging file then rename — rename(2) is atomic on POSIX so
# a concurrent `gl doctor` (or any running gl process) never sees a
# partially-written binary.
install -m 755 "$TMP_DIR/gl" "$INSTALL_DIR/gl.new"
mv -f "$INSTALL_DIR/gl.new" "$INSTALL_DIR/gl"
install -m 755 "$TMP_DIR/git-remote-gitlawb" "$INSTALL_DIR/git-remote-gitlawb.new"
mv -f "$INSTALL_DIR/git-remote-gitlawb.new" "$INSTALL_DIR/git-remote-gitlawb"

# ── PATH check ────────────────────────────────────────────────────────────
echo ""
echo "✓ Installed gitlawb ${VERSION}"
echo "  gl                   → ${INSTALL_DIR}/gl"
echo "  git-remote-gitlawb   → ${INSTALL_DIR}/git-remote-gitlawb"
echo ""

# Check if install dir is already on PATH
if echo ":$PATH:" | grep -q ":${INSTALL_DIR}:"; then
  echo "Run:"
  echo "  gl doctor       check your setup"
  echo "  gl quickstart   create your identity and first repo"
else
  SHELL_NAME=$(basename "${SHELL:-bash}")
  case "$SHELL_NAME" in
    zsh)  RC="$HOME/.zshrc" ;;
    fish) RC="$HOME/.config/fish/config.fish" ;;
    *)    RC="$HOME/.bashrc" ;;
  esac

  echo "Add ${INSTALL_DIR} to your PATH:"
  echo ""
  if [ "$SHELL_NAME" = "fish" ]; then
    echo "  fish_add_path ${INSTALL_DIR}"
  else
    echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ${RC}"
    echo "  source ${RC}"
  fi
  echo ""
  echo "Then run:"
  echo "  gl doctor       check your setup"
  echo "  gl quickstart   create your identity and first repo"
fi

echo ""
echo "Docs: https://docs.gitlawb.com"

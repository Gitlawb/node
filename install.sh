#!/usr/bin/env bash
# gitlawb installer - downloads pre-built binaries from GitHub Releases.
#
# Usage:
#   curl -fsSL https://gitlawb.com/install.sh | sh
#   curl -fsSL https://gitlawb.com/install.sh | sh -s -- --version v0.3.9
set -euo pipefail

REPO="${GITLAWB_RELEASE_REPO:-Gitlawb/node}"
INSTALL_DIR="${GITLAWB_INSTALL_DIR:-$HOME/.local/bin}"
VERSION_ARG="latest"

usage() {
  cat <<EOF
gitlawb installer

Options:
  --version <tag>   Install a specific release tag, for example v0.3.9.
  -h, --help        Show this help.

Environment:
  GITLAWB_INSTALL_DIR   Install directory (default: $HOME/.local/bin)
  GITLAWB_RELEASE_REPO  GitHub repo to download from (default: Gitlawb/node)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      if [ "$#" -lt 2 ]; then
        echo "error: --version requires a value" >&2
        exit 1
      fi
      VERSION_ARG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      VERSION_ARG="$1"
      shift
      ;;
  esac
done

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Linux)  OS_NAME="linux" ;;
  Darwin) OS_NAME="darwin" ;;
  *)
    echo "error: unsupported OS: $OS" >&2
    echo "       please build from source: cargo install --git https://github.com/${REPO} gl" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)          ARCH_NAME="x86_64" ;;
  aarch64 | arm64) ARCH_NAME="aarch64" ;;
  *)
    echo "error: unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

case "${OS_NAME}-${ARCH_NAME}" in
  linux-x86_64)   TARGET="x86_64-unknown-linux-musl" ;;
  linux-aarch64)  TARGET="aarch64-unknown-linux-musl" ;;
  darwin-x86_64)  TARGET="x86_64-apple-darwin" ;;
  darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
esac

if [ "$VERSION_ARG" = "latest" ]; then
  echo "Fetching latest release version..."
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  if [ -z "$TAG" ]; then
    echo "error: could not determine latest release. Check https://github.com/${REPO}/releases" >&2
    exit 1
  fi
else
  TAG="$VERSION_ARG"
fi

case "$TAG" in
  v*) VERSION="${TAG#v}" ;;
  *)  VERSION="$TAG"; TAG="v$TAG" ;;
esac

PACKAGE_NAME="gitlawb-node-${VERSION}-${TARGET}"
ARCHIVE="${PACKAGE_NAME}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

echo "Installing gitlawb ${TAG} for ${OS_NAME}/${ARCH_NAME}"
echo "  Archive:  ${ARCHIVE}"
echo "  Into:     ${INSTALL_DIR}"
echo ""

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading..."
if ! curl -fSL --progress-bar -o "$TMP_DIR/$ARCHIVE" "$DOWNLOAD_URL"; then
  echo ""
  echo "error: download failed: $DOWNLOAD_URL" >&2
  echo "       Check https://github.com/${REPO}/releases for available builds." >&2
  exit 1
fi

if curl -fsSL -o "$TMP_DIR/$ARCHIVE.sha256" "$CHECKSUM_URL" 2>/dev/null; then
  echo "Verifying checksum..."
  EXPECTED=$(awk '{print $1}' "$TMP_DIR/$ARCHIVE.sha256")
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$TMP_DIR/$ARCHIVE" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "$TMP_DIR/$ARCHIVE" | awk '{print $1}')
  else
    echo "warning: no sha256 tool found, skipping checksum verification"
    ACTUAL="$EXPECTED"
  fi
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "error: checksum mismatch!" >&2
    echo "  expected: $EXPECTED" >&2
    echo "  actual:   $ACTUAL" >&2
    exit 1
  fi
  echo "  checksum OK"
fi

echo "Extracting..."
tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"
PACKAGE_DIR="$TMP_DIR/$PACKAGE_NAME"
if [ ! -d "$PACKAGE_DIR" ]; then
  PACKAGE_DIR=$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)
fi
if [ ! -d "$PACKAGE_DIR" ]; then
  echo "error: could not find extracted package directory" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"

INSTALLED=()
for BIN in gl git-remote-gitlawb gitlawb-node; do
  if [ -f "$PACKAGE_DIR/$BIN" ]; then
    install -m 755 "$PACKAGE_DIR/$BIN" "$INSTALL_DIR/$BIN.new"
    mv -f "$INSTALL_DIR/$BIN.new" "$INSTALL_DIR/$BIN"
    INSTALLED+=("$BIN")
  fi
done

if [ "${#INSTALLED[@]}" -eq 0 ]; then
  echo "error: no installable binaries found in $ARCHIVE" >&2
  exit 1
fi

echo ""
echo "Installed gitlawb ${TAG}"
for BIN in "${INSTALLED[@]}"; do
  echo "  ${BIN} -> ${INSTALL_DIR}/${BIN}"
done
echo ""

if echo ":$PATH:" | grep -q ":${INSTALL_DIR}:"; then
  echo "Run:"
  echo "  gl doctor"
  echo "  gl quickstart"
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
  echo "  gl doctor"
  echo "  gl quickstart"
fi

# oh-my-zsh's default git plugin aliases gl='git pull', which silently shadows
# the gl binary in every interactive zsh (aliases beat PATH). Detect the common
# setup and say so now, at install time, instead of letting the first `gl`
# print git's baffling "fatal: not a git repository".
if [ -f "$HOME/.zshrc" ] && [ -d "$HOME/.oh-my-zsh/plugins/git" ] \
  && grep -Eq '^[[:space:]]*plugins=\(([^)]*[[:space:]])?git([[:space:]][^)]*)?\)' "$HOME/.zshrc" \
  && ! grep -Eq '^([^#]*[[:space:];&|])?unalias[[:space:]]+([^;&|#]*[[:space:]])?gl([[:space:]]|$)' "$HOME/.zshrc"; then
  echo ""
  echo "NOTE: oh-my-zsh's git plugin aliases gl='git pull', which will shadow"
  echo "the gl command in interactive shells. To use gl by name, run:"
  echo ""
  echo "  echo 'unalias gl' >> ~/.zshrc && source ~/.zshrc"
fi

echo ""
echo "Docs: https://docs.gitlawb.com"

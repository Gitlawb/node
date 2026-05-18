#!/usr/bin/env bash
set -euo pipefail

# Build the Gitlawb Node macOS menu bar app.
# Usage: ./scripts/build-macos-app.sh [--sign IDENTITY]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
APP_DIR="$ROOT_DIR/macos-app"
BUILD_DIR="$APP_DIR/.build/release"
OUTPUT_DIR="$ROOT_DIR/dist"
APP_NAME="Gitlawb Node"
APP_BUNDLE="$OUTPUT_DIR/${APP_NAME}.app"

SIGN_IDENTITY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sign)
            SIGN_IDENTITY="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "==> Building Gitlawb Node macOS app..."

# Ensure docker-compose.yml resource is up to date
mkdir -p "$APP_DIR/Sources/GitlawbNode/Resources"
cp "$ROOT_DIR/docker-compose.yml" "$APP_DIR/Sources/GitlawbNode/Resources/docker-compose.yml"

# Build with Swift Package Manager
cd "$APP_DIR"
swift build -c release

echo "==> Packaging .app bundle..."

# Create .app structure
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy binary
cp "$BUILD_DIR/GitlawbNode" "$APP_BUNDLE/Contents/MacOS/GitlawbNode"

# Copy Info.plist
cp "$APP_DIR/Sources/GitlawbNode/Info.plist" "$APP_BUNDLE/Contents/Info.plist"

# Copy bundled resources
cp "$ROOT_DIR/docker-compose.yml" "$APP_BUNDLE/Contents/Resources/docker-compose.yml"

# Copy app icon
cp "$APP_DIR/Sources/GitlawbNode/Resources/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"

# Copy menu bar icon
cp "$APP_DIR/Sources/GitlawbNode/Resources/MenuBarIcon.png" "$APP_BUNDLE/Contents/Resources/MenuBarIcon.png"
cp "$APP_DIR/Sources/GitlawbNode/Resources/MenuBarIcon@2x.png" "$APP_BUNDLE/Contents/Resources/MenuBarIcon@2x.png"

# Copy SPM-bundled resources if they exist
if [ -d "$BUILD_DIR/GitlawbNode_GitlawbNode.bundle" ]; then
    cp -R "$BUILD_DIR/GitlawbNode_GitlawbNode.bundle" "$APP_BUNDLE/Contents/Resources/"
fi

echo "==> App bundle created: $APP_BUNDLE"

# Codesign if identity provided
if [ -n "$SIGN_IDENTITY" ]; then
    echo "==> Signing with identity: $SIGN_IDENTITY"
    codesign --force --deep --sign "$SIGN_IDENTITY" \
        --options runtime \
        --entitlements /dev/stdin <<EOF "$APP_BUNDLE"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
</dict>
</plist>
EOF
    echo "==> Signed."
else
    # Remove quarantine attribute so unsigned builds work without Gatekeeper prompts
    echo "==> No signing identity provided — removing quarantine attribute for local use"
    xattr -cr "$APP_BUNDLE"
fi

# Create DMG
echo "==> Creating DMG..."
DMG_PATH="$OUTPUT_DIR/GitlawbNode-macOS.dmg"
rm -f "$DMG_PATH"

# Create a temporary directory for DMG contents
DMG_STAGING="$OUTPUT_DIR/dmg-staging"
rm -rf "$DMG_STAGING"
mkdir -p "$DMG_STAGING"
cp -R "$APP_BUNDLE" "$DMG_STAGING/"
ln -s /Applications "$DMG_STAGING/Applications"

hdiutil create -volname "Gitlawb Node" \
    -srcfolder "$DMG_STAGING" \
    -ov -format UDZO \
    "$DMG_PATH"

rm -rf "$DMG_STAGING"

echo "==> DMG created: $DMG_PATH"

echo "==> Done!"
echo "   App:  $APP_BUNDLE"
echo "   DMG:  $DMG_PATH"

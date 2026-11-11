#!/usr/bin/env bash
# Build Lockrail.app (menu bar shell + the lockrail binary) and a DMG.
#
#   bash scripts/build-macos-app.sh            # ad-hoc signed: runs on this Mac only
#   LOCKRAIL_SIGN_IDENTITY="Developer ID Application: ..." \
#   LOCKRAIL_NOTARY_PROFILE=lockrail-notary bash scripts/build-macos-app.sh
#                                              # distributable: hardened runtime, notarized, stapled
#
# Output: dist/Lockrail.app and dist/Lockrail-<version>.dmg (drag Lockrail to Applications).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
DIST=$ROOT/dist
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
IDENTITY=${LOCKRAIL_SIGN_IDENTITY:--}
APP=$DIST/Lockrail.app

echo "== building lockrail $VERSION"
cargo build --release -p lockrail
swift build -c release --package-path apps/macos
SHELL_BIN=$(swift build -c release --package-path apps/macos --show-bin-path)/Lockrail

echo "== assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$SHELL_BIN" "$APP/Contents/MacOS/Lockrail"
cp target/release/lockrail "$APP/Contents/Resources/lockrail"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Lockrail</string>
  <key>CFBundleDisplayName</key><string>Lockrail</string>
  <key>CFBundleIdentifier</key><string>dev.lockrail.app</string>
  <key>CFBundleExecutable</key><string>Lockrail</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHumanReadableCopyright</key><string>Lockrail</string>
</dict>
</plist>
PLIST
plutil -lint "$APP/Contents/Info.plist" >/dev/null

echo "== signing ($IDENTITY)"
SIGN=(codesign --force --sign "$IDENTITY")
if [ "$IDENTITY" != "-" ]; then
  SIGN+=(--options runtime --timestamp)
fi
# Inner binary first, then the bundle.
"${SIGN[@]}" "$APP/Contents/Resources/lockrail"
"${SIGN[@]}" "$APP"
codesign --verify --strict --deep "$APP"

echo "== DMG"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
DMG=$DIST/Lockrail-$VERSION.dmg
rm -f "$DMG"
hdiutil create -volname "Lockrail" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
if [ "$IDENTITY" != "-" ]; then
  codesign --sign "$IDENTITY" --timestamp "$DMG"
fi
if [ -n "${LOCKRAIL_NOTARY_PROFILE:-}" ]; then
  xcrun notarytool submit "$DMG" --keychain-profile "$LOCKRAIL_NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG"
  spctl --assess --type open --context context:primary-signature -v "$DMG"
fi
shasum -a 256 "$DMG" | tee "$DMG.sha256"
echo "== done: $DMG"

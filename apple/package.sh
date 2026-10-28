#!/bin/sh
# Builds Omnitun.app (menu bar app + omnitund + omnitun-engine + omnitunctl,
# arm64 + x86_64)
# and the installer package, into apple/dist/.
#
# Signing, all optional (without them: ad hoc app, unsigned package):
#   SIGN_ID="Developer ID Application: Name (TEAMID)"
#   INSTALLER_ID="Developer ID Installer: Name (TEAMID)"
#   NOTARY_PROFILE=name   (xcrun notarytool store-credentials name …)
# or the same lines in apple/signing.env, which stays out of git.
# REPO=owner/name: the GitHub repository whose Releases Sparkle reads
# (default GarageDeveloper/omnitun); apple/release.sh publishes there.
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
# Local signing settings (not in git): the same variables, one per line.
if [ -f apple/signing.env ]; then . apple/signing.env; fi

# Names come from crates/vpn-core/src/brand.rs, the only place they are spelled.
brand() { sed -n "s/^pub const $1: &str = \"\(.*\)\";/\1/p" crates/vpn-core/src/brand.rs; }
PRODUCT=$(brand PRODUCT)
ID=$(brand ID)
DAEMON=$(brand DAEMON)
CLI=$(brand CLI)
ENGINE=$(brand ENGINE)
ENGINE_USER=$(brand ENGINE_USER)
RDNS=$(brand REVERSE_DNS)
LABEL=$(brand LAUNCHD_LABEL)
BUNDLE_ID="$RDNS"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
# Sparkle compares build numbers: a UTC date, so they keep growing even
# when the history is rewritten (yymmddHHMM fits CFBundleVersion's 32 bits).
BUILD=$(date -u +%y%m%d%H%M)
# The commit built, shown next to the version (never compared): -modified
# when files differ from it.
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
  COMMIT="$COMMIT-modified"
fi
export OMNITUN_COMMIT="$COMMIT"
REPO=${REPO:-GarageDeveloper/omnitun}
FEED_URL="https://github.com/$REPO/releases/latest/download/appcast.xml"

dist=apple/dist
app="$dist/$PRODUCT.app"
rm -rf "$dist"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

# The C and assembly in Rust crates (ring) target the SDK's macOS unless
# told otherwise: build everything for the app's oldest macOS.
export MACOSX_DEPLOYMENT_TARGET=$(plutil -extract LSMinimumSystemVersion raw apple/Info.plist)
echo "== Rust: bindings, $DAEMON, $ENGINE, $CLI"
apple/build-bindings.sh
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --release -p "$DAEMON" -p "$ENGINE" -p "$CLI" --target "$target"
done
# The root daemon and its engine are not in the app: the package installs
# them straight into root-owned folders (see Package).
helpers="$dist/helpers"
mkdir -p "$helpers"
for bin in "$DAEMON" "$ENGINE" "$CLI"; do
  out="$app/Contents/MacOS/$bin"
  [ "$bin" = "$CLI" ] || out="$helpers/$bin"
  lipo -create "${CARGO_TARGET_DIR:-target}/aarch64-apple-darwin/release/$bin" "${CARGO_TARGET_DIR:-target}/x86_64-apple-darwin/release/$bin" -output "$out"
done

echo "== Swift: $PRODUCT"
swift build --package-path apple -c release --arch arm64 --arch x86_64 --product Omnitun
bin_path=$(swift build --package-path apple -c release --arch arm64 --arch x86_64 --show-bin-path)
cp "$bin_path/Omnitun" "$app/Contents/MacOS/$PRODUCT"
# Sparkle, without its XPC services: they serve sandboxed apps only.
mkdir -p "$app/Contents/Frameworks"
ditto "$bin_path/Sparkle.framework" "$app/Contents/Frameworks/Sparkle.framework"
rm -rf "$app/Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices" \
  "$app/Contents/Frameworks/Sparkle.framework/XPCServices"

echo "== Icon"
swiftc -O -o "$dist/make-icon" apple/Omnitun/HubIcon.swift apple/tools/MakeIcon/main.swift
"$dist/make-icon" "$dist/AppIcon.iconset"
iconutil -c icns -o "$app/Contents/Resources/AppIcon.icns" "$dist/AppIcon.iconset"
rm -rf "$dist/make-icon" "$dist/AppIcon.iconset"

subst() {
  sed -e "s|@PRODUCT@|$PRODUCT|g" -e "s|@ID@|$ID|g" -e "s|@RDNS@|$RDNS|g" -e "s|@DAEMON@|$DAEMON|g" -e "s|@CLI@|$CLI|g" \
      -e "s|@ENGINE@|$ENGINE|g" -e "s|@ENGINE_USER@|$ENGINE_USER|g" \
      -e "s|@LABEL@|$LABEL|g" -e "s|@BUNDLE_ID@|$BUNDLE_ID|g" -e "s|@VERSION@|$VERSION|g" -e "s|@BUILD@|$BUILD|g" \
      -e "s|@FEED_URL@|$FEED_URL|g" -e "s|@COMMIT@|$COMMIT|g" "$1"
}
subst apple/Info.plist > "$app/Contents/Info.plist"
cp -R apple/Resources/en.lproj apple/Resources/fr.lproj "$app/Contents/Resources/"
# The licenses of what we ship (Rust crates, Sparkle): Settings › About.
scripts/third-party-notices.sh > "$app/Contents/Resources/ThirdPartyNotices.txt"
subst apple/pkg/daemon.plist > "$dist/$LABEL.plist"
plutil -lint "$app/Contents/Info.plist" "$dist/$LABEL.plist" >/dev/null

echo "== Signing"
# Extended attributes would become ._ files in the package and break the seal.
xattr -cr "$app"
if [ -n "${SIGN_ID:-}" ]; then
  sign="--force --options runtime --timestamp --sign"
  # shellcheck disable=SC2086
  codesign $sign "$SIGN_ID" --identifier "$RDNS.daemon" "$helpers/$DAEMON"
  # shellcheck disable=SC2086
  codesign $sign "$SIGN_ID" --identifier "$RDNS.engine" "$helpers/$ENGINE"
  # shellcheck disable=SC2086
  codesign $sign "$SIGN_ID" --identifier "$RDNS.cli" "$app/Contents/MacOS/$CLI"
  # Sparkle's helpers, inside out, then the framework.
  for part in Versions/B/Autoupdate Versions/B/Updater.app ""; do
    # shellcheck disable=SC2086
    codesign $sign "$SIGN_ID" "$app/Contents/Frameworks/Sparkle.framework/$part"
  done
  # shellcheck disable=SC2086
  codesign $sign "$SIGN_ID" "$app"
else
  echo "   (ad hoc: set SIGN_ID to sign with Developer ID)"
  # The hardened runtime all the same: no code injected into the app,
  # which holds the Keychain's access and the prompt sockets.
  sign="--force --options runtime --sign -"
  # shellcheck disable=SC2086
  codesign $sign --identifier "$RDNS.daemon" "$helpers/$DAEMON"
  # shellcheck disable=SC2086
  codesign $sign --identifier "$RDNS.engine" "$helpers/$ENGINE"
  # shellcheck disable=SC2086
  codesign $sign --identifier "$RDNS.cli" "$app/Contents/MacOS/$CLI"
  for part in Versions/B/Autoupdate Versions/B/Updater.app ""; do
    # shellcheck disable=SC2086
    codesign $sign "$app/Contents/Frameworks/Sparkle.framework/$part"
  done
  # Library validation only loads code of the app's Team ID, which an ad hoc
  # signature has not: dyld would refuse Sparkle and the app die at launch.
  # Only that check is lifted; DYLD_* variables stay ignored.
  entitlements="$dist/adhoc.entitlements"
  cat > "$entitlements" <<'EOP'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.cs.disable-library-validation</key>
  <true/>
</dict>
</plist>
EOP
  # shellcheck disable=SC2086
  codesign $sign --entitlements "$entitlements" "$app"
  rm -f "$entitlements"
fi
codesign --verify --strict --deep "$app"
codesign --verify --strict "$helpers/$DAEMON" "$helpers/$ENGINE"

echo "== Package"
stage="$dist/stage"
scripts="$dist/scripts"
mkdir -p "$stage/Applications" "$stage/Library/PrivilegedHelperTools" "$stage/Library/LaunchDaemons" "$scripts"
chmod 755 "$stage/Library" "$stage/Library/PrivilegedHelperTools" "$stage/Library/LaunchDaemons"
ditto --norsrc --noextattr --noqtn "$app" "$stage/Applications/$PRODUCT.app"
# Installed root-owned by the package itself: never copied from a folder an
# administrator's process could change during the installation.
for bin in "$DAEMON" "$ENGINE"; do
  ditto --norsrc --noextattr --noqtn "$helpers/$bin" "$stage/Library/PrivilegedHelperTools/$bin"
  chmod 755 "$stage/Library/PrivilegedHelperTools/$bin"
done
cp "$dist/$LABEL.plist" "$stage/Library/LaunchDaemons/$LABEL.plist"
chmod 644 "$stage/Library/LaunchDaemons/$LABEL.plist"
for script in preinstall postinstall; do
  subst "apple/pkg/scripts/$script" > "$scripts/$script"
  chmod 755 "$scripts/$script"
done
pkg="$dist/$PRODUCT-$VERSION.pkg"
# The app must land in /Applications, never on top of a copy elsewhere.
pkgbuild --analyze --root "$stage" "$dist/component.plist" >/dev/null
plutil -replace 0.BundleIsRelocatable -bool NO "$dist/component.plist"
COPYFILE_DISABLE=1 pkgbuild --root "$stage" --install-location / --scripts "$scripts" \
  --component-plist "$dist/component.plist" \
  --identifier "$RDNS.pkg" --version "$VERSION" --ownership recommended "$dist/component.pkg" >/dev/null
subst apple/pkg/distribution.xml > "$dist/distribution.xml"
if [ -n "${INSTALLER_ID:-}" ]; then
  productbuild --distribution "$dist/distribution.xml" --package-path "$dist" --sign "$INSTALLER_ID" --timestamp "$pkg"
else
  productbuild --distribution "$dist/distribution.xml" --package-path "$dist" "$pkg"
fi
rm -rf "$stage" "$scripts" "$helpers" "$dist/$LABEL.plist" "$dist/component.pkg" "$dist/component.plist" "$dist/distribution.xml"

if [ -n "${NOTARY_PROFILE:-}" ]; then
  echo "== Notarization"
  xcrun notarytool submit "$pkg" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$pkg"
fi
# For apple/release.sh: the appcast names the build.
echo "$BUILD" > "$dist/build-number"
echo "$COMMIT" > "$dist/commit"
echo "done: $root/$pkg"

#!/bin/sh
# Builds the Rust core for the macOS app and generates its Swift bindings:
#   apple/Generated/Swift/VPNClientCore.swift        (SwiftPM target VPNClientCore)
#   apple/Generated/VPNClientCoreFFI.xcframework     (static library, arm64 + x86_64)
set -eu
cd "$(dirname "$0")/.."
# The C and assembly in Rust crates (ring) target the SDK's macOS unless
# told otherwise: build everything for the app's oldest macOS.
export MACOSX_DEPLOYMENT_TARGET=$(plutil -extract LSMinimumSystemVersion raw apple/Info.plist)
profile=${PROFILE:-release}
target_dir=${CARGO_TARGET_DIR:-target}
out=apple/Generated
work="$target_dir/apple-bindings"
rm -rf "$out" "$work"
mkdir -p "$out/Swift" "$work/headers"

cargo build --profile "$profile" -p vpn-ffi
cargo run -q --profile "$profile" -p vpn-ffi --bin uniffi-bindgen -- generate \
  --library "$target_dir/$profile/libvpn_ffi.dylib" --language swift --out-dir "$work"
mv "$work/VPNClientCore.swift" "$out/Swift/"
mv "$work/VPNClientCoreFFI.h" "$work/headers/"
mv "$work/VPNClientCoreFFI.modulemap" "$work/headers/module.modulemap"

libs=""
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  if rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    cargo build --profile "$profile" -p vpn-ffi --target "$target"
    libs="$libs $target_dir/$target/$profile/libvpn_ffi.a"
  fi
done
if [ -n "$libs" ]; then
  # shellcheck disable=SC2086
  lipo -create $libs -output "$work/libvpn_ffi.a"
else
  cp "$target_dir/$profile/libvpn_ffi.a" "$work/"
fi
xcodebuild -create-xcframework -library "$work/libvpn_ffi.a" -headers "$work/headers" \
  -output "$out/VPNClientCoreFFI.xcframework" >/dev/null
echo "bindings in $out"

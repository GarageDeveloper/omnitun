#!/bin/sh
# Writes the licenses of the third-party software shipped with Omnitun to
# stdout: the Rust crates (cargo about, see about.toml) and Sparkle, whose
# Swift package must have been resolved. Needs cargo-about.
set -eu
cd "$(dirname "$0")/.."
command -v cargo-about >/dev/null || {
  echo "cargo-about is missing: cargo install --locked cargo-about" >&2
  exit 1
}
cargo about generate --fail about.hbs
sparkle=apple/.build/checkouts/Sparkle/LICENSE
[ -f "$sparkle" ] || {
  echo "$sparkle is missing: resolve the Swift package (swift package --package-path apple resolve)" >&2
  exit 1
}
printf '\n================================================================================\n'
printf 'Sparkle (macOS app updates), MIT License and the licenses it includes\n'
printf -- '--------------------------------------------------------------------------------\n\n'
cat "$sparkle"

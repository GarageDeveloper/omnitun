#!/bin/sh
# Writes the licenses of the third-party software shipped with Omnitun to
# stdout: the Rust crates (cargo about, see about.toml) and, when the Swift
# package has been resolved, Sparkle. Needs cargo-about.
set -eu
cd "$(dirname "$0")/.."
command -v cargo-about >/dev/null || {
  echo "cargo-about is missing: cargo install --locked cargo-about" >&2
  exit 1
}
cargo about generate --fail about.hbs 2>/dev/null
sparkle=apple/.build/checkouts/Sparkle/LICENSE
if [ -f "$sparkle" ]; then
  printf '\n================================================================================\n'
  printf 'Sparkle (macOS app updates), MIT License and the licenses it includes\n'
  printf -- '--------------------------------------------------------------------------------\n\n'
  cat "$sparkle"
fi

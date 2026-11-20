#!/bin/sh
# Prepares the Windows app's updates (WinSparkle) for the GitHub Release of
# this version, on the Mac that has Sparkle's private key (login Keychain,
# account "omnitun", as apple/release.sh): downloads the Release's MSIs,
# which the "Windows installers" workflow attaches after the tag is pushed,
# signs them (EdDSA) and writes appcast-windows.xml, one enclosure per
# architecture. The app reads the appcast-windows.xml of the latest Release.
#
#   packaging/windows/appcast.sh             prepares, publishes nothing
#   packaging/windows/appcast.sh --publish   also attaches appcast-windows.xml
#                                            to the Release vVERSION in $REPO
#
# Waits for the MSIs (up to WAIT seconds, 2400 by default).
set -eu
cd "$(dirname "$0")/../.."
publish=no
[ "${1:-}" = "--publish" ] && publish=yes
REPO=${REPO:-GarageDeveloper/omnitun}
WAIT=${WAIT:-2400}

brand() { sed -n "s/^pub const $1: &str = \"\(.*\)\";/\1/p" crates/vpn-core/src/brand.rs; }
PRODUCT=$(brand PRODUCT)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
tag="v$VERSION"
sign_update=apple/.build/artifacts/sparkle/Sparkle/bin/sign_update
[ -x "$sign_update" ] || { echo "no $sign_update: build the macOS app once (apple/package.sh)" >&2; exit 1; }

msis="$PRODUCT-$VERSION-x64.msi $PRODUCT-$VERSION-arm64.msi"
waited=0
while :; do
  assets=$(gh release view "$tag" --repo "$REPO" --json assets -q '.assets[].name' 2>/dev/null || true)
  missing=""
  for msi in $msis; do
    printf '%s\n' "$assets" | grep -qx "$msi" || missing="$missing $msi"
  done
  [ -z "$missing" ] && break
  if [ "$waited" -ge "$WAIT" ]; then
    echo "release $tag in $REPO lacks$missing" >&2
    exit 1
  fi
  echo "waiting for$missing on release $tag…"
  sleep 30
  waited=$((waited + 30))
done

out=target/windows-release
rm -rf "$out"
mkdir -p "$out"
for msi in $msis; do
  gh release download "$tag" --repo "$REPO" -p "$msi" -D "$out"
done

notes=""
gh release view "$tag" --repo "$REPO" --json body -q .body > "$out/notes.md"
if grep -q "[^[:space:]]" "$out/notes.md"; then
  # WinSparkle shows the description as HTML: rendered by GitHub, as on
  # the Release's page.
  html=$(gh api -X POST markdown -f mode=markdown -F text=@"$out/notes.md")
  style='<style>body{font:13px "Segoe UI",sans-serif;margin:0 8px}h2{font-size:15px;margin:14px 0 6px}ul{padding-left:20px}li{margin:3px 0}code{font:12px Consolas,monospace}.anchor{display:none}</style>'
  notes="<description><![CDATA[$style$(printf '%s' "$html" | sed 's/]]>/]] >/g')]]></description>"
fi

enclosures=""
for arch in x64 arm64; do
  msi="$PRODUCT-$VERSION-$arch.msi"
  # sparkle:edSignature="…" length="…"
  signature=$("$sign_update" --account omnitun "$out/$msi")
  url="https://github.com/$REPO/releases/download/$tag/$msi"
  enclosures="$enclosures
      <enclosure url=\"$url\" sparkle:os=\"windows-$arch\" type=\"application/x-msi\" $signature/>"
done

cat > "$out/appcast-windows.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>$PRODUCT for Windows</title>
    <item>
      <title>$PRODUCT $VERSION</title>
      <pubDate>$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')</pubDate>
      <sparkle:version>$VERSION</sparkle:version>
      <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
      <link>https://github.com/$REPO/releases/tag/$tag</link>
      $notes$enclosures
    </item>
  </channel>
</rss>
XML
xmllint --noout "$out/appcast-windows.xml"
echo "prepared: $out/appcast-windows.xml ($PRODUCT $VERSION)"

if [ "$publish" = yes ]; then
  gh release upload "$tag" --repo "$REPO" --clobber "$out/appcast-windows.xml"
  echo "published: https://github.com/$REPO/releases/download/$tag/appcast-windows.xml"
fi

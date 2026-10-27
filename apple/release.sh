#!/bin/sh
# Prepares a release for Sparkle in apple/dist/release/: the notarized
# package (apple/package.sh), its EdDSA signature (private key in the
# login Keychain, account "omnitun") and appcast.xml, which lists this
# version. Sparkle reads the appcast.xml of the latest GitHub Release
# (SUFeedURL), so each release carries its own.
#
#   apple/release.sh                 builds and prepares, publishes nothing
#   apple/release.sh --publish       also creates the GitHub Release vVERSION
#                                    in $REPO (default GarageDeveloper/omnitun)
#                                    with the package and appcast.xml
#
# NOTES=file: release notes (Markdown) for the Release and the appcast.
set -eu
cd "$(dirname "$0")/.."
if [ -f apple/signing.env ]; then . apple/signing.env; fi
publish=no
[ "${1:-}" = "--publish" ] && publish=yes
REPO=${REPO:-GarageDeveloper/omnitun}
export REPO

brand() { sed -n "s/^pub const $1: &str = \"\(.*\)\";/\1/p" crates/vpn-core/src/brand.rs; }
PRODUCT=$(brand PRODUCT)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
MIN_OS=$(plutil -extract LSMinimumSystemVersion raw apple/Info.plist)
tag="v$VERSION"

if [ "$publish" = yes ] && gh release view "$tag" --repo "$REPO" >/dev/null 2>&1; then
  echo "release $tag exists already in $REPO: raise the version in Cargo.toml" >&2
  exit 1
fi
if [ "$publish" = yes ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "uncommitted changes: commit them before publishing" >&2
  exit 1
fi
[ -n "${NOTARY_PROFILE:-}" ] || { echo "NOTARY_PROFILE is needed: Sparkle only installs notarized packages" >&2; exit 1; }

apple/package.sh
pkg="apple/dist/$PRODUCT-$VERSION.pkg"
build=$(cat apple/dist/build-number)
commit=$(cat apple/dist/commit)
case "$commit" in
*-modified)
  [ "$publish" = yes ] && { echo "uncommitted changes: commit them before publishing" >&2; exit 1; }
  ;;
esac
out=apple/dist/release
mkdir -p "$out"
cp "$pkg" "$out/"

# sparkle:edSignature="…" length="…"
signature=$(apple/.build/artifacts/sparkle/Sparkle/bin/sign_update --account omnitun "$pkg")
notes=""
if [ -n "${NOTES:-}" ]; then
  notes="<description><![CDATA[$(sed 's/]]>/]] >/g' "$NOTES")]]></description>"
fi
url="https://github.com/$REPO/releases/download/$tag/$PRODUCT-$VERSION.pkg"
cat > "$out/appcast.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>$PRODUCT</title>
    <item>
      <title>$PRODUCT $VERSION ($commit)</title>
      <pubDate>$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')</pubDate>
      <sparkle:version>$build</sparkle:version>
      <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>$MIN_OS</sparkle:minimumSystemVersion>
      <link>https://github.com/$REPO/releases/tag/$tag</link>
      $notes
      <enclosure url="$url" type="application/octet-stream" sparkle:installationType="package" $signature/>
    </item>
  </channel>
</rss>
XML
xmllint --noout "$out/appcast.xml"
echo "prepared: $out ($PRODUCT $VERSION, build $build, commit $commit)"

if [ "$publish" = yes ]; then
  if [ -n "${NOTES:-}" ]; then
    set -- --notes-file "$NOTES"
  else
    set -- --notes ""
  fi
  gh release create "$tag" --repo "$REPO" --title "$PRODUCT $VERSION ($commit)" "$@" \
    "$out/$PRODUCT-$VERSION.pkg" "$out/appcast.xml"
  echo "published: https://github.com/$REPO/releases/tag/$tag"
fi

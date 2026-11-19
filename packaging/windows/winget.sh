#!/bin/sh
# Writes the winget manifests of a published release into
# target/winget/manifests/g/GarageDeveloper/Omnitun/<version>/, from the
# MSIs attached to its GitHub Release (.github/workflows/windows-msi.yml).
# Submitting them stays a manual step: a pull request to
# microsoft/winget-pkgs with that folder (or `wingetcreate submit <folder>`).
#
#   packaging/windows/winget.sh [version]     (default: Cargo.toml's)
set -eu
cd "$(dirname "$0")/../.."
REPO=${REPO:-GarageDeveloper/omnitun}
VERSION=${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}
id=GarageDeveloper.Omnitun
out=target/winget/manifests/g/GarageDeveloper/Omnitun/$VERSION
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

gh release download "v$VERSION" --repo "$REPO" --pattern "Omnitun-$VERSION-*.msi" --dir "$tmp"
installers=
for arch in x64 arm64; do
  msi=$tmp/Omnitun-$VERSION-$arch.msi
  [ -f "$msi" ] || { echo "Omnitun-$VERSION-$arch.msi is not in release v$VERSION" >&2; exit 1; }
  sha=$(shasum -a 256 "$msi" | cut -d' ' -f1 | tr 'a-f' 'A-F')
  installers="$installers
  - Architecture: $arch
    InstallerUrl: https://github.com/$REPO/releases/download/v$VERSION/Omnitun-$VERSION-$arch.msi
    InstallerSha256: $sha"
done

mkdir -p "$out"
cat > "$out/$id.yaml" <<YAML
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.version.1.6.0.schema.json
PackageIdentifier: $id
PackageVersion: $VERSION
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
YAML
cat > "$out/$id.installer.yaml" <<YAML
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.1.6.0.schema.json
PackageIdentifier: $id
PackageVersion: $VERSION
InstallerType: wix
Scope: machine
UpgradeBehavior: install
MinimumOSVersion: 10.0.22000.0
Installers:$installers
ManifestType: installer
ManifestVersion: 1.6.0
YAML
cat > "$out/$id.locale.en-US.yaml" <<YAML
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.1.6.0.schema.json
PackageIdentifier: $id
PackageVersion: $VERSION
PackageLocale: en-US
Publisher: GarageDeveloper
PublisherUrl: https://github.com/GarageDeveloper
PublisherSupportUrl: https://github.com/$REPO/issues
PackageName: Omnitun
PackageUrl: https://github.com/$REPO
License: MIT OR Apache-2.0
LicenseUrl: https://github.com/$REPO#license
ShortDescription: VPN client for FortiGate SSL VPN, IPsec IKEv2, L2TP/IPsec, OpenVPN and WireGuard, side by side.
Moniker: omnitun
Tags:
  - vpn
  - wireguard
  - openvpn
  - ipsec
  - fortinet
ReleaseNotesUrl: https://github.com/$REPO/releases/tag/v$VERSION
ManifestType: defaultLocale
ManifestVersion: 1.6.0
YAML
echo "$out"

# Builds the Omnitun installer for Windows: release binaries for one
# architecture, Wintun's DLL (downloaded, checked against its SHA-256), the
# license notices, then the MSI (WiX 5, see omnitun.wxs).
#
#   packaging\windows\build-msi.ps1 -Arch arm64     (or x64)
#
# Needs Rust with the target (rustup target add aarch64-pc-windows-msvc or
# x86_64-pc-windows-msvc), clang for ring on ARM64, cargo-about
# (cargo install --locked cargo-about --features cli) and WiX 5
# (dotnet tool install --global wix --version 5.0.2; -Wix names another).
# The MSI goes to target\msi\Omnitun-<version>-<arch>.msi. It is not signed.
param(
    [ValidateSet('x64', 'arm64')] [string] $Arch = $(if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }),
    [string] $Wix = 'wix'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $root

$wintunVersion = '0.14.1'
$wintunSha256 = '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'
$target = @{ x64 = 'x86_64-pc-windows-msvc'; arm64 = 'aarch64-pc-windows-msvc' }[$Arch]
$wintunArch = @{ x64 = 'amd64'; arm64 = 'arm64' }[$Arch]
$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.*)"' | Select-Object -First 1).Matches[0].Groups[1].Value

cargo build --release --locked --target $target -p omnitund -p omnitun-engine -p omnitunctl
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

$zip = "target\wintun-$wintunVersion.zip"
if (-not (Test-Path $zip)) {
    Invoke-WebRequest "https://www.wintun.net/builds/wintun-$wintunVersion.zip" -OutFile $zip
}
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash
if ($hash -ne $wintunSha256) { throw "$zip has SHA-256 $hash, not $wintunSha256" }
Expand-Archive -Force $zip "target\wintun-$wintunVersion"
$wintun = "target\wintun-$wintunVersion\wintun"

$stage = "target\$target\release\msi"
New-Item -ItemType Directory -Force $stage | Out-Null
foreach ($exe in 'omnitund', 'omnitun-engine', 'omnitunctl') {
    Copy-Item "target\$target\release\$exe.exe" $stage
}
Copy-Item "$wintun\bin\$wintunArch\wintun.dll" $stage
Copy-Item "$wintun\LICENSE.txt" "$stage\wintun-LICENSE.txt"
Copy-Item LICENSE-MIT "$stage\LICENSE-MIT.txt"
Copy-Item LICENSE-APACHE "$stage\LICENSE-APACHE.txt"

# Written by cargo-about itself: PowerShell would re-encode its output.
cargo about generate --fail -o "$stage\THIRD-PARTY-NOTICES.txt" about.hbs
if ($LASTEXITCODE -ne 0) { throw 'cargo about failed (cargo install --locked cargo-about --features cli)' }
$wintunNotice = "`n" + ('=' * 80) + "`nWintun $wintunVersion (wintun.dll), Prebuilt Binaries License`n" + ('-' * 80) + "`n`n" +
    (Get-Content -Raw "$wintun\LICENSE.txt")
[IO.File]::AppendAllText("$root\$stage\THIRD-PARTY-NOTICES.txt", $wintunNotice)

New-Item -ItemType Directory -Force target\msi | Out-Null
$msi = "target\msi\Omnitun-$version-$Arch.msi"
& $Wix build -arch $Arch -d "Version=$version" -d "Stage=$stage" -o $msi packaging\windows\omnitun.wxs
if ($LASTEXITCODE -ne 0) { throw 'wix build failed' }
Write-Output $msi

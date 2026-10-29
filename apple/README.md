# macOS app

A menu bar app (AppKit for the menu, SwiftUI for the windows) on top of
`vpn-client`, called through the UniFFI bindings (`crates/vpn-ffi`). It
is in English and French (`Resources/*.lproj`); Settings › General can
override the system language.

| File | Role |
|---|---|
| `Omnitun/App.swift` | Startup, opening files, quitting (disconnects the VPNs by default) |
| `Omnitun/Model.swift` | Profiles, live sessions, the service, errors explained |
| `Omnitun/ConnectionFlow.swift` | One connection: prompts, SAML browser, secrets saved after success |
| `Omnitun/StatusMenu.swift` | Menu bar icon and menu: one switch per VPN, folders as submenus |
| `Omnitun/PromptViews.swift` | Password or PSK, code and push, SAML, unknown or changed certificate |
| `Omnitun/WelcomeView.swift` | Welcome: service installed and running, notifications, open at login |
| `Omnitun/ManageView.swift` | Manage VPNs: editor, folders, import and export |
| `Omnitun/ImportView.swift` | Imports, and the first-launch assistant |
| `Omnitun/SettingsView.swift` | Settings, diagnostic report, About |
| `Omnitun/Updates.swift` | Sparkle updates |
| `Omnitun/Windows.swift` | Small floating windows: one per question, the menu closing at the first click elsewhere |
| `Omnitun/Notifier.swift` | User notifications (off when run outside the bundle) |
| `Omnitun/ReceivedView.swift` | A `.vpnprofile` opened from the Finder or Mail: server and fingerprints shown before adding |
| `Omnitun/HubIcon.swift` | The icon, drawn for the menu bar and the app icon |

## Build

```sh
apple/build-bindings.sh              # Swift bindings + universal Rust library
swift run --package-path apple Smoke # checks the bindings
swift build --package-path apple     # the app alone
apple/package.sh                     # apple/dist/Omnitun.app and Omnitun-<version>.pkg
```

Run `build-bindings.sh` again after any change to the public API of
`vpn-ffi` or `vpn-client`: until then the Swift side does not see it.

`package.sh` reads the names in `crates/vpn-core/src/brand.rs` and needs
`cargo-about` for the third-party notices it puts in the app
(`cargo install --locked cargo-about`). Signing: `SIGN_ID`, `INSTALLER_ID`
and `NOTARY_PROFILE`, as variables or in `apple/signing.env` (not in git);
without them the app is signed ad hoc and the package is not signed.

## Updates (Sparkle)

The app checks the `appcast.xml` of the latest GitHub Release of
`GarageDeveloper/omnitun` every day (`SUFeedURL`; the `REPO` variable
builds for another repository) and offers the new version; the package is
installed only if the user accepts, with an administrator password. Menu
“Check for Updates…”, setting in Settings › General.

```sh
apple/release.sh             # apple/dist/release/: notarized package, signed appcast.xml; publishes nothing
apple/release.sh --publish   # also creates the vVERSION Release with those two files
```

The package is signed with EdDSA: the private key is in the login
Keychain (account `omnitun`, made by
`apple/.build/artifacts/sparkle/Sparkle/bin/generate_keys --account omnitun`),
the public key in `Info.plist` (`SUPublicEDKey`). **Back up the private
key** (`generate_keys --account omnitun -x file`): without it, installed
copies accept no update any more. Forks must use their own key and feed.
The build number is the UTC date (`yymmddHHMM`), so it grows even when the
history is rewritten; the commit is shown next to it. A release must be
notarized (`NOTARY_PROFILE`) and its version (`Cargo.toml`) greater than
the previous one.

## What the package does

- `/Applications/Omnitun.app`, owned by `root:wheel`, with `omnitunctl`
  inside; `omnitund` and `omnitun-engine` in `/Library/PrivilegedHelperTools`;
- creates the `omnitun` group and adds the session's user to it, and the
  `_omnitun` user the engines run as;
- installs and loads `/Library/LaunchDaemons/com.root42.omnitun.daemon.plist`;
  links `/usr/local/bin/omnitunctl`, and its shell completions into
  `/usr/local/share/zsh/site-functions/_omnitunctl` and
  `/usr/local/share/bash-completion/completions/omnitunctl`;
- opens the app in the session at the end.

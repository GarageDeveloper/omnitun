# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Rust workspace (edition 2024, resolver 3, every crate under `crates/*`). CI runs exactly these (clippy and tests on Linux and macOS, fmt and cargo-deny on Linux only):

```sh
cargo fmt --all --check                                   # rustfmt.toml: max_width 120, use_small_heuristics "Max"
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked                           # unit tests + loopback tests against fake gateways
cargo deny check licenses                                 # allow-list in deny.toml
```

Single crate / single test: `cargo test -p vpn-ipsec ikev2::tests::<name>`, `cargo test -p vpn-fortissl --test fake_gateway`.

Linux builds need `pkg-config` and `libdbus-1-dev` (Secret Service keyring via D-Bus); the built `omnitunctl` then needs `libdbus-1-3` at run time.

Run the daemon locally without installing (the `_omnitun` user only exists after the package is installed):

```sh
sudo OMNITUN_SOCKET=/tmp/omnitund.sock target/debug/omnitund --group staff --engine-user nobody --allow-writable-binaries
OMNITUN_SOCKET=/tmp/omnitund.sock target/debug/omnitunctl connect <profile>
```

Interop tests against real servers in Docker (each folder has a README): `interop/{strongswan,openvpn,l2tp,wireguard}/run.sh [scenario…]`; `KEEP=1` keeps the server running, `RUST_LOG=debug` makes the client verbose. They drive the `examples/*interop*.rs` of the protocol crates, not the daemon.

macOS app (Xcode 16, see `apple/README.md`):

```sh
apple/build-bindings.sh              # UniFFI Swift bindings + universal static lib into apple/Generated/
swift run --package-path apple Smoke # checks the bindings
swift build --package-path apple --product Omnitun
apple/package.sh                     # .app and .pkg (needs cargo-about; signing via SIGN_ID/INSTALLER_ID/NOTARY_PROFILE)
```

`apple/build-bindings.sh` must be re-run after any change to the `vpn-ffi` / `vpn-client` public API, otherwise the Swift side does not see it.

## Architecture

Privilege-separated client/daemon/engine split; the README has the diagram and the crate table.

- **`omnitunctl` (crates/cli) and the macOS app** run as the user. Both sit on `vpn-client` (profiles in `~/.config/omnitun/profiles.toml`, Keychain/Secret Service secrets, imports from FortiClient/Viscosity/System Settings/`.ovpn`/WireGuard, the daemon client). The app reaches it through `vpn-ffi` (UniFFI). They talk to the daemon over a Unix socket with JSON lines (`vpn-core::ipc`); only members of the `omnitun` group may connect.
- **`omnitund` (crates/daemon)** runs as root and contains **no protocol code**. `Manager` owns the sessions, reconnection (5 attempts, exponential backoff) and the conflict registry; `vpn-platform` creates the tun interface, routes, per-session split DNS (`scutil` key on macOS, `resolvectl` on Linux) and the host route to each gateway. It refuses to start if its binaries live in a folder writable by non-root (`--allow-writable-binaries` overrides for local testing).
- **`omnitun-engine` (crates/engine)**: one process per session, spawned by the daemon as the unprivileged `_omnitun` user, sandboxed on macOS through `sandbox-exec` (`sandbox_profile`, `RemoteEngine::spawn` in `crates/daemon/src/engine.rs`). It receives three descriptors: a control socket (JSON lines, `vpn-core::engine_ipc`), a descriptor socket, and a prompt listener. The protocol is `ToEngine::Start { profile }` → `FromEngine::Connected { settings }` → the daemon creates the tun from those settings and sends `ToEngine::Tun` plus the fd over the descriptor socket (`vpn-platform::fdpass`) → `Stats` … `Ended`. The engine stays alive across attempts; `Stop` only logs out.
- **Prompts bypass the daemon**: the user's client (app or CLI) attaches directly to the engine's prompt socket (`PromptHub` in `crates/engine/src/prompts.rs`, accepting only the profile owner's uid or root). Passwords, OTP codes, push approvals and SAML `open_url` flow there; secrets never transit through the root daemon. Reconnections use `attach_wait_ms = 0`, i.e. cached answers or an already attached client, else they fail with `NeedsUser`.
- **Protocol crates** (`vpn-fortissl`, `vpn-ipsec` (IKEv1 + IKEv2 + user-space ESP), `vpn-openvpn`, `vpn-l2tp` (built on `vpn-ipsec`), `vpn-wireguard` (boringtun)) each implement the `vpn_core::Engine` trait: `connect` → `run` → `disconnect`, exchanging IP packets over channels with a `SessionContext` (prompter, cancel token, stats). They know nothing of tun interfaces, routes or DNS. `vpn-tls` holds the shared client-certificate logic where the private key stays with the user (the client signs on request).
- `crates/vpn-core/src/brand.rs` holds the product and binary names, the engine user, the launchd label / reverse-DNS id and the `OMNITUN_SOCKET` variable name; `apple/package.sh` reads it, so renames go there.
- `crates/utun-probe` is a standalone root probe checking that a utun handed to a sandboxed `nobody` process works and that the sandbox holds.

## Conventions observed in the code

- Secret-bearing buffers are wrapped in `zeroize::Zeroizing` and zeroized after parsing; IPC readers cap line length (`MAX_LINE`, `MAX_ANSWER_LINE`, `MAX_ENGINE_LINE`) and drop the peer on an oversized or invalid line. Keep both properties when touching IPC code.
- Failures that the UI must explain carry a `FailureKind` (`vpn-core::failure`), not just an `anyhow` message.
- Every protocol is implemented from RFCs/public docs; known gaps are listed under "Limitations" in the README (no IPv6 in tunnels, no IKEv2 rekey/fragmentation/MOBIKE, no OpenVPN CBC/tls-crypt-v2/`dev tap`, etc.). Update that list when closing or adding a gap.
- The app is localized in English and French (`apple/Resources/{en,fr}.lproj/Localizable.strings`): new user-facing strings go in both.
- Dependencies must stay within the license allow-list of `deny.toml`; third-party notices are generated by `scripts/third-party-notices.sh` (cargo-about).

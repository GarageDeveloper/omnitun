# Omnitun

[![CI](https://github.com/GarageDeveloper/omnitun/actions/workflows/ci.yml/badge.svg)](https://github.com/GarageDeveloper/omnitun/actions/workflows/ci.yml)

One VPN client for macOS and Linux, written in Rust, for the VPNs of many
vendors.

Vendor clients can be buggy and restrictive, and each vendor needs its
own, so connecting to several companies means installing several of them.
Omnitun aims to cover as many protocols as possible from a single
application, and to add the advanced features those clients lack.

Supported protocols:

- **Fortinet SSL VPN**: password, FortiToken (code or push), SAML in the
  browser, client certificates;
- **IPsec**: IKEv2, and IKEv1 main or aggressive mode with XAuth and
  Mode-Config, as FortiClient does;
- **OpenVPN** 2.4 to 2.6 servers;
- **L2TP over IPsec**, the one built into macOS and Windows (Meraki Client
  VPN, Windows Server and the like);
- **WireGuard**.

Beyond connecting:

- **VPN chaining**: a VPN can run through another one, which is connected
  first if needed;
- **several VPNs at once**, each with its own routes and DNS, with
  conflicts between them detected; a VPN can also be marked as a company
  VPN that never runs alongside another;
- automatic reconnection, folders to organize many VPNs, and a diagnostic
  report that leaves out secrets and addresses.

On macOS, a menu bar app (English and French) creates, imports and runs
the VPNs; `omnitunctl` does the same from a terminal, on macOS and Linux.
It imports the VPNs of FortiClient, Viscosity, System Settings (Cisco
IPSec and L2TP), `.ovpn` files and WireGuard `.conf` files.

> Omnitun is an independent project. It is not affiliated with or endorsed
> by Fortinet, Cisco, OpenVPN Inc., Jason A. Donenfeld (WireGuard) or any
> other vendor; their names are trademarks of their owners, used here only
> to say what Omnitun connects to. Every protocol is implemented from its
> RFCs and public documentation, and tested against open-source servers.

## Install

### Download (macOS)

Prebuilt packages, signed with a Developer ID and notarized by Apple, are
published on the GitHub Releases page:
**[download the latest release](https://github.com/GarageDeveloper/omnitun/releases/latest)**
(earlier versions are under [all releases](https://github.com/GarageDeveloper/omnitun/releases)).

The package (`Omnitun-<version>.pkg`) installs the app, the service and
`omnitunctl`; the app then offers updates (Sparkle) and the user decides.
macOS 14 or later.

### From source

Rust (stable) is needed; on Linux, also `pkg-config` and the D-Bus headers
(`libdbus-1-dev` on Debian and Ubuntu). The macOS app also needs Xcode 16.
See [apple/README.md](apple/README.md) for the app and the package.

```sh
cargo build --release
# The daemon and the engine in a folder only root can change (the daemon
# refuses to start otherwise).
sudo install -o root -m 755 target/release/omnitund target/release/omnitun-engine /Library/PrivilegedHelperTools/   # macOS
# Linux: sudo install -o root -m 755 target/release/omnitund target/release/omnitun-engine /usr/local/sbin/
install target/release/omnitunctl /usr/local/bin/

# Only members of the omnitun group drive the daemon.
sudo dseditgroup -o create omnitun && sudo dseditgroup -o edit -a "$USER" -t user omnitun   # macOS
# Linux: sudo groupadd --system omnitun && sudo usermod -aG omnitun "$USER" (then log in again)

# macOS
sudo cp packaging/com.root42.omnitun.daemon.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.root42.omnitun.daemon.plist
# Linux (systemd-resolved required)
sudo cp packaging/omnitund.service /etc/systemd/system/ && sudo systemctl enable --now omnitund
```

To try it without installing (the `_omnitun` user only exists after the
package):
`sudo OMNITUN_SOCKET=/tmp/omnitund.sock target/debug/omnitund --group staff --engine-user nobody --allow-writable-binaries`,
then `OMNITUN_SOCKET=/tmp/omnitund.sock target/debug/omnitunctl connect paris`.

## Use

Profiles live in `~/.config/omnitun/profiles.toml`; see
[examples/profiles.toml](examples/profiles.toml).

```sh
omnitunctl import forticlient --write      # FortiClient's VPNs (macOS)
omnitunctl secret set paris                # password in the Keychain (optional)
omnitunctl connect paris branch            # two tunnels side by side
omnitunctl status                          # uptime, gateway, DNS, drops, traffic
omnitunctl watch                           # follows state changes
omnitunctl log paris --since 2h -f         # the service log (administrators)
omnitunctl diagnose -o report.txt          # a report to share, without secrets or addresses
omnitunctl disconnect --all
```

## Architecture

```
 user                                 root
┌──────────────────┐  Unix socket   ┌────────────────────────────────────────┐
│ app, omnitunctl  │  JSON lines    │ omnitund                               │
│  TOML profiles   │ ─────────────▶ │  Manager ── Registry (conflicts)       │
│  Keychain        │ ◀───────────── │   │                                    │
│  browser (SAML)  │ prompts, state │   ├─ session "paris"  ─ omnitun-engine │
└──────────────────┘                │   │     utun4 · routes · split DNS     │
                                    │   ├─ session "branch" ─ omnitun-engine │
                                    │   │     utun5 · routes · split DNS     │
                                    │   └─ …                                 │
                                    └────────────────────────────────────────┘
```

| Crate | Role |
|---|---|
| `vpn-core` | `Engine` trait, `TunnelSettings`, profiles, `Prompter`, IPC protocol |
| `vpn-platform` | One tun interface per session, routes, split DNS, conflict registry |
| `vpn-fortissl` | Fortinet SSL VPN: portal login, XML configuration, PPP over TLS |
| `vpn-ipsec` | IKEv1 and IKEv2 initiators, ESP in user space (UDP 4500) |
| `vpn-openvpn` | OpenVPN client (TLS mode, `dev tun`): TLS control channel (tls-auth, tls-crypt), AES-GCM / ChaCha20-Poly1305 data channel, renegotiation |
| `vpn-l2tp` | L2TP over IPsec (RFC 3193): transport mode IPsec SA, L2TP tunnel and session, PPP (PAP, CHAP, MS-CHAPv2, IPCP) |
| `vpn-wireguard` | WireGuard client (one peer) on boringtun |
| `vpn-tls` | Client certificates whose key stays with the user (the client signs), shared by the TLS engines |
| `daemon` → `omnitund` | Root daemon: sessions, reconnection, conflicts, tunnel interfaces, routes and DNS; no protocol code |
| `engine` → `omnitun-engine` | One connection attempt (TLS, SAML, IKE, ESP…), started by the daemon as the `_omnitun` user, in a sandbox |
| `vpn-client` | Shared user side: profiles, Keychain, talking to the daemon, imports |
| `vpn-ffi` | Swift bindings of `vpn-client` (UniFFI) for the macOS app |
| `cli` → `omnitunctl` | Command-line client |

Principles:

- **Independent engines behind one trait.** Each protocol implements
  `connect → run → disconnect` and exchanges IP packets over channels; it
  knows nothing of tun interfaces or routes.
- **Privilege separation.** Only `omnitund` runs as root, and it contains
  no protocol code: engines run unprivileged and sandboxed. Secrets stay in
  the user's Keychain and reach an engine only when it asks; one-time codes
  are never stored. The SAML browser opens in the user's session.
- **Several VPNs at once.** Each session has its own tun interface, routes
  and DNS resolver (a dedicated `scutil` key on macOS, per-link DNS with
  `resolvectl` on Linux). The registry refuses what would divert another
  session's traffic (two full tunnels, the same route, the same DNS
  domain) and warns about partial overlaps. Each gateway keeps a host route
  through the physical interface. A VPN can also run *through* another one
  (chaining), or be marked as a company VPN that never runs alongside
  another.
- **Reconnection.** A tunnel that drops is started again (5 attempts,
  exponential backoff) with the secrets kept in memory for the session.

## Tests

`cargo test --workspace` runs the unit tests and the loopback tests against
fake gateways. The `interop/` folders run the engines against real servers
in Docker: strongSwan 5.9 (IKEv1, IKEv2), OpenVPN 2.6, strongSwan + xl2tpd
+ pppd (L2TP) and the Linux kernel's WireGuard; each has a README.

## Limitations

- No IPv6 inside the tunnels.
- IKEv1: pre-shared keys only (no certificates). Aggressive mode exposes
  the group PSK to an offline dictionary attack: it must be long and
  random.
- IKEv2: no IKE SA rekey (the client reconnects before it ends), no IKE
  fragmentation, no MOBIKE. With EAP and a gateway authenticated by a group
  PSK, anyone holding the PSK can capture MSCHAPv2 answers: prefer the
  gateway's certificate.
- Fortinet SSL VPN: no DTLS, no host check.
- OpenVPN: no tls-crypt-v2, no browser login (WEB_AUTH), no CBC ciphers, no
  static key mode, no `dev tap`; compressed packets from the server are
  dropped (VORACLE).
- L2TP: the group PSK authenticates the server; with PAP the password
  travels in clear inside IPsec.
- A reconnection that needs a client certificate signature, a code or a
  browser login needs the app running.
- Linux: command line only, and the engines are not sandboxed yet.

## Security

Please report vulnerabilities privately through GitHub's
[security advisories](https://github.com/GarageDeveloper/omnitun/security/advisories/new),
not in public issues.

## License

Free software, under the MIT license ([LICENSE-MIT](LICENSE-MIT)) or the
Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), at your option.
The licenses of the third-party components are produced by
`scripts/third-party-notices.sh` and shipped with the app.

Unless you state otherwise, any contribution you submit for inclusion in
Omnitun is dual licensed as above, without any additional terms.

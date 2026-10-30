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
- **split mode on demand**: a VPN that takes all traffic can also be
  connected with only a list of networks through it;
- **routes by domain**: `*.corp-saas.com` through a split tunnel, or
  `*.zoom.us` kept outside a full one, whatever addresses these names
  resolve to (see [Routes by domain](#routes-by-domain));
- **several VPNs at once**, each with its own routes and DNS, with
  conflicts between them detected; a VPN can also be marked as a company
  VPN that never runs alongside another;
- automatic reconnection, folders to organize many VPNs, and a diagnostic
  report that leaves out secrets and addresses.

On macOS, a menu bar app (English and French) creates, imports and runs
the VPNs; `omnitunctl` does the same from a terminal, on macOS and Linux.
It imports the VPNs of FortiClient, Viscosity, OpenVPN Connect, System
Settings (Cisco IPSec and L2TP), `.ovpn` files and WireGuard `.conf` files.

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
`omnitunctl` with its bash and zsh completions; the app then offers updates (Sparkle) and the user decides.
macOS 14 or later.

### From source

Rust 1.95 or later is needed; on Linux, also `pkg-config` and the D-Bus
headers (`libdbus-1-dev` on Debian and Ubuntu). At run time on Linux,
`omnitunctl` needs the D-Bus library (`libdbus-1-3` on Debian and Ubuntu,
installed with `libdbus-1-dev`) for the Secret Service keyring. The macOS
app also needs Xcode 16.
See [apple/README.md](apple/README.md) for the app and the package.

```sh
cargo build --release
# The daemon and the engine in a folder only root can change (the daemon
# refuses to start otherwise).
sudo install -o root -m 755 target/release/omnitund target/release/omnitun-engine /Library/PrivilegedHelperTools/   # macOS
# Linux: sudo install -o root -m 755 target/release/omnitund target/release/omnitun-engine /usr/local/sbin/
sudo install target/release/omnitunctl /usr/local/bin/

# Only members of the omnitun group drive the daemon.
sudo dseditgroup -o create omnitun && sudo dseditgroup -o edit -a "$USER" -t user omnitun   # macOS
# Linux: sudo groupadd --system omnitun && sudo usermod -aG omnitun "$USER" (then log in again)

# The engines run as the _omnitun account, without a shell or a home; the
# daemon does not start without it.
# macOS: create it as the package does (the dscl block of
# apple/pkg/scripts/postinstall).
# Linux: sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin _omnitun

# macOS. The log names servers and accounts: root and the administrators.
sudo touch /var/log/omnitund.log && sudo chown root:admin /var/log/omnitund.log && sudo chmod 640 /var/log/omnitund.log
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
omnitunctl app restart                     # relaunch the menu bar app; the VPNs stay up (macOS)
omnitunctl duplicate paris --name paris-test  # a copy to try other settings
```

### What goes through the VPN

The Network tab of Manage VPNs offers three modes; in `profiles.toml`:

| Mode | Keys |
| --- | --- |
| As the gateway decides | no `full_tunnel`; `extra_routes` add networks to those the gateway announces |
| Everything through the VPN | `full_tunnel = true`; `excluded_domains` stay outside |
| Only these networks (split tunnel) | `full_tunnel = false` and `routes = [...]`, which replace the gateway's networks, or `extra_routes = [...]` on top of them |

`split_routes` offer a split mode besides, chosen when connecting (the
menu's "Connect in Split Mode", `omnitunctl connect --split`): only those
networks go through the VPN for that connection.

```toml
# A split tunnel, whatever the gateway announces.
full_tunnel = false
routes = ["10.20.0.0/16", { domain = "*.corp.example", note = "Intranet" }]
```

### Routes by domain

A route list (`routes`, `split_routes`, `extra_routes`) may hold
domains besides networks; `excluded_domains` keeps names outside a full
tunnel. `crm.example` is that name only, `*.corp-saas.com` that domain and
every name under it.

```toml
split_routes = ["10.20.0.0/16", { domain = "*.corp-saas.com", note = "CRM" }]
excluded_domains = ["*.zoom.us", { domain = "*.teams.microsoft.com", note = "Teams" }]
```

Only a connection with such domains runs a DNS proxy (unprivileged, as
the engines): the system resolver sends it the names under those domains,
it relays them to the resolvers that answered before (the tunnel's for its
own domains, otherwise those in place before the VPN, so DNS filtering by
an antivirus goes on), and has the addresses of each answer routed before
returning it: through the tunnel, or outside it, for at least 10 minutes.
`omnitunctl status` counts them. If the proxy fails, the DNS goes back to
how it is without it. Limits:

- names resolved by an application on its own (DNS over HTTPS in a
  browser, iCloud Private Relay) get no route; the proxy tells Firefox to
  keep the system's DNS;
- an address shared by several names (a CDN) follows the first rule that
  routed it;
- IPv4 only: routed names get no IPv6 address;
- through the tunnel, the gateway must accept those destinations (a
  WireGuard peer with `AllowedIPs = 0.0.0.0/0`, IPsec traffic selectors
  that cover them); outside a full tunnel, only public addresses.

### Shell completions

`omnitunctl completions bash|zsh` prints a script that completes the
subcommands, the options, the files, and the profile names (read from the
profiles file, the one given with `--config` included). The macOS package
installs both: zsh finds `/usr/local/share/zsh/site-functions/_omnitunctl`
once `compinit` runs in `.zshrc`, and bash-completion 2 (Homebrew's
`bash-completion@2`) loads `/usr/local/share/bash-completion/completions/omnitunctl`.
From source, or on Linux:

```sh
omnitunctl completions zsh > "${fpath[1]}/_omnitunctl"   # a folder of your fpath you can write to
mkdir -p ~/.local/share/bash-completion/completions
omnitunctl completions bash > ~/.local/share/bash-completion/completions/omnitunctl
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
  the user's Keychain (OpenVPN keys excepted, see Limitations) and reach an
  engine only when it asks; one-time codes are never stored. The SAML browser opens in the user's session.
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

## Development

What CI checks (clippy and the tests on Linux and macOS):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check licenses
```

`cargo test -p vpn-ipsec` tests one crate, `cargo test -p vpn-ipsec eap`
the tests whose name contains `eap`. The app's text is in English and
French: a new string needs its entry in
`apple/Resources/fr.lproj/Localizable.strings`. See
[apple/README.md](apple/README.md) to build the app.

The tests are unit tests and loopback tests against fake gateways. The
`interop/` folders run the engines against real servers
in Docker: strongSwan 5.9 (IKEv1, IKEv2), OpenVPN 2.6, strongSwan + xl2tpd
+ pppd (L2TP) and the Linux kernel's WireGuard; `interop/service` installs
the service under systemd as described above and connects through it.
Each has a README.

## Limitations

- No IPv6 inside the tunnels. A full tunnel blocks IPv6 (reject routes for
  `::/1` and `8000::/1` on the tunnel interface), so applications fall back
  to IPv4 instead of leaving outside the tunnel; a split tunnel leaves IPv6
  on the local network.
- IKEv1: pre-shared keys only (no certificates). Aggressive mode exposes
  the group PSK to an offline dictionary attack: it must be long and
  random.
- IKEv2: no IKE SA rekey (the client reconnects before it ends), no IKE
  fragmentation, no MOBIKE. With EAP and a gateway authenticated by a group
  PSK, anyone holding the PSK can capture MSCHAPv2 answers: prefer the
  gateway's certificate.
- Certificates: no revocation check (CRL, OCSP).
- Fortinet SSL VPN: no DTLS, no host check. During a browser (SAML)
  login, up to 5 minutes, a web page open in the browser could send the
  local listener a session of another account; finish the login without
  browsing elsewhere.
- OpenVPN: no tls-crypt-v2, no browser login (WEB_AUTH), no CBC ciphers, no
  static key mode, no `dev tap`; compressed packets from the server are
  dropped (VORACLE). The client key and the tls-auth or tls-crypt key of a
  profile are kept in `profiles.toml` (readable by the user only), as in
  the `.ovpn` file it came from: do not sync or share that file.
- L2TP: the group PSK authenticates the server, and only MS-CHAPv2 proves
  that it knows the password. PAP (off unless the profile asks for it, as
  Meraki needs) sends the password in clear inside IPsec; once a server
  has proved itself with MS-CHAPv2, its profile accepts nothing weaker.
- A reconnection that needs a code or a browser login needs the app
  running. A client certificate signs each renegotiation and reconnection
  from the app, or from `omnitunctl connect`, which then stays in the
  foreground.
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

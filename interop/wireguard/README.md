# WireGuard interoperability tests

`./run.sh` builds a WireGuard server image (Alpine 3.22, the Linux
kernel's WireGuard set up with `wg`) and a Linux build of the `wg-interop`
example (`crates/vpn-wireguard/examples/wg-interop.rs`), then runs each
scenario: fresh keys for both sides, connect, ping the server's tunnel
address (10.9.0.1) through the tunnel, disconnect. `./run.sh split psk`
runs only those; `KEEP_LOGS=1` keeps the logs of the scenarios that
passed, `RUST_LOG=debug` makes the client verbose.

Both sides run in containers on the `omnitun-interop-wireguard` network,
the server at 172.33.0.10 (`--cap-add NET_ADMIN`: Docker Desktop's kernel
has WireGuard built in). The server reports each handshake in its log,
which `run.sh` checks.

| Scenario | What it tests |
|---|---|
| `split` | AllowedIPs 10.9.0.0/24: routed networks, DNS server and search domain in the settings |
| `full` | AllowedIPs 0.0.0.0/0: a full tunnel |
| `psk` | A pre-shared key on both sides |
| `rekey` | Pings for 140 s: the session is rekeyed after 120 s without losing packets |
| `reject-wrong-key` | A private key the server does not know: no handshake, a clear timeout |
| `reject-wrong-psk` | The wrong pre-shared key: same |

All of them pass against Linux 6.12 (Docker Desktop) with wireguard-tools
1.0.

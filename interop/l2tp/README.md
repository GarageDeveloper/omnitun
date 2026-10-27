# L2TP/IPsec interoperability tests

`./run.sh` builds an L2TP/IPsec server image (Alpine 3.22: strongSwan
5.9 in transport mode, xl2tpd 1.3, pppd 2.5) and a Linux build of the
`l2tp-interop` example (`crates/vpn-l2tp/examples/l2tp-interop.rs`), then
runs every scenario of `profiles.toml`: connect, ping the server's PPP
address through the tunnel, disconnect. `./run.sh pap rekey` runs only
those; `KEEP=1` keeps the servers running, `KEEP_LOGS=1` keeps the logs of
the scenarios that passed, `RUST_LOG=debug` makes the client verbose.

`CLIENT=stock ./run.sh` runs the same scenarios with the stock Linux
client instead (strongSwan, xl2tpd and pppd in a container of the server
image, driven by `stock-client.sh`): it checks the bench itself. All of
them pass with strongSwan 5.9.14, xl2tpd 1.3.18 and pppd 2.5.2.

Both sides run in containers on the `omnitun-interop-l2tp` network:
Docker Desktop's port forwarding from macOS loses UDP-encapsulated ESP.
The servers need `--cap-add NET_ADMIN --device /dev/ppp` (Docker
Desktop's kernel has PPP and L2TP built in; xl2tpd uses its L2TP
support), the omnitun client nothing: the engine is user space.

One container runs per server (`entrypoint.sh <server>`): server N listens
on 172.32.0.1N and its pppd, 10.9.N.1, answers ping; clients get
10.9.N.10 and up.

| N | Server | Scenarios | What it tests |
|---|---|---|---|
| 1 | mschapv2 | `psk-mschapv2`, `reject-wrong-psk`, `reject-wrong-password` | Main mode, PSK; pppd `require-mschap-v2`. The profile has no user name: it is asked |
| 2 | chap | `chap-md5`, `rekey-client` | pppd `require-chap` (CHAP-MD5); the profile prefers MS-CHAPv2. `rekey-client`: the profile's ESP SA lasts 120 s, so the client rekeys it after 108 s, keeps accepting the replaced one until its end, then deletes it; pings for 160 s (`REKEY_CLIENT_DURATION`) |
| 3 | pap | `pap`, `reject-auth-method` | pppd `require-pap`; refused by a profile with `ppp_auth = ["ms-chap-v2"]`, which also refuses a server that then drops its authentication |
| 4 | aggressive | `aggressive-group` | Aggressive mode, the group name `omnitun-group` as a KEY_ID identity (`local_id`) |
| 5 | legacy | `legacy-3des` | IKE 3des-sha1-modp1024 and ESP 3des-sha1 only (`legacy_algorithms = true`) |
| 6 | dns | `dns-ipcp` | IPCP gives DNS 10.9.6.53 and 10.9.6.54 (`ms-dns`) |
| 7 | rekey | `rekey` | The server rekeys the ESP SA after 60 s (rand 5 s) and lets the old one expire at 90 s; the client pings every second for 100 s (`REKEY_DURATION`) |
| 8 | reauth | `reauth` | The server re-authenticates after 60 s (rand 5 s): IKEv1 has no IKE SA rekey, so strongSwan starts a new main mode itself, then a Quick Mode on it, and deletes the previous IKE SA. The client answers as the responder; pings for 100 s (`REAUTH_DURATION`). A Meraki MX does the same about every hour |

The PSK is `omnitun-interop-psk`, the user `alice`, the password
`alice-password`. Scenarios named `reject-*` must fail, with an error
matching the pattern `run.sh` gives for each client, and the server's log
must say why (undecryptable messages for a wrong PSK, `Peer alice failed
CHAP authentication`, `peer refused to authenticate`). The patterns for
the omnitun client are guesses until the engine exists: adjust them to its
messages. Every other scenario checks in the server's log that it saw a
NAT (`remote host is behind NAT`: UDP-encapsulated ESP although there is
none) and a transport-mode SA for UDP 1701 on both sides, plus what the
scenario tests (the PPP authentication in pppd's LCP ConfReq, aggressive
mode, the 3DES proposals, the rekey and the expiry of the old SA).

The example answers the engine's questions (`psk`, `username`, `password`)
from `INTEROP_PSK`, `INTEROP_USERNAME` and `INTEROP_PASSWORD`, keeps the
tunnel up for `INTEROP_DURATION` seconds when set, and checks what the
server gave against `INTEROP_EXPECT` (`dns=<address>`).

## What the servers do

The engine must match these (checked with the stock client):

- IKEv1, PSK; proposals aes256-sha256-modp2048, aes256-sha1-modp2048,
  aes128-sha1-modp2048 (legacy server: 3des-sha1-modp1024), ESP
  aes256-sha256 (HMAC-SHA-256-128), aes256-sha1, aes128-sha1 (legacy:
  3des-sha1), no PFS. Main mode with any identity; the aggressive server
  only accepts the identity `keyid:omnitun-group`. The server's identity
  is its address. DPD every 30 s once the client sent the DPD vendor ID.
- The client's fake NAT-D payloads make charon float to port 4500 and use
  UDP-encapsulated transport mode. Quick Mode messages carry NAT-OA both
  ways (charon sends them in its responses and in its own rekey requests).
- Selectors: the server's side `dynamic[udp/1701]`, the client's
  `dynamic[udp]` (any source port), narrowed to the client's UDP 1701.
  charon answers a longer proposed lifetime with RESPONDER-LIFETIME (90 s
  on the rekey server); it starts the rekey itself (a Quick Mode it
  initiates, which the client answers as responder), then deletes the old
  SA with an INFORMATIONAL DELETE.
- xl2tpd on UDP 1701, host name `omnitun-l2tp`, length bit in data
  messages.
- pppd's LCP ConfReq: MRU 1400, ACCM 0, the authentication, magic number
  (no PFC or ACFC); LCP echo requests every 10 s (6 missed: link down).
  pppd also offers IPV6CP (reject it with a Protocol-Reject or negotiate
  it). IPCP: the server's address 10.9.N.1, the client's address by
  ConfNak of whatever it asks for, ms-dns1/ms-dns2 ConfRejected except on the dns
  server. No CCP (`noccp`). The CHAP name of the server is `omnitun-l2tp`;
  MS-CHAPv2 failures come as `E=691 R=1 ...`.

Logs of failed scenarios are left in `last-<name>.log` (client, then the
server's lines for that scenario), all the servers' in `last-server.log`.
Everything here is test material: the PSK and passwords are not secrets.

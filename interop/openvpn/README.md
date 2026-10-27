# OpenVPN interoperability tests

`./run.sh` builds an OpenVPN 2.6 server image (Alpine's `openvpn`
package) and a Linux build of the `interop` example
(`crates/vpn-openvpn/examples/openvpn-interop.rs`), then runs every scenario of
`profiles.toml`: connect, ping the server through the tunnel, disconnect.
`./run.sh tls-crypt reneg` runs only those; `KEEP=1` keeps the servers
running, `KEEP_LOGS=1` keeps the logs of the scenarios that passed,
`RUST_LOG=debug` makes the client verbose.

`CLIENT=openvpn ./run.sh` runs the same scenarios with the stock `openvpn`
client instead (in a container of the server image, driven through its
management interface by `stock-client.py`): it checks the bench itself.
All of them pass with OpenVPN 2.6.20 (OpenSSL 3.5).

Both sides run in containers on the `omnitun-interop-openvpn` network
(servers 172.31.0.2): Docker Desktop's port forwarding from macOS is not
reliable for UDP.

One container runs a server instance per scenario family
(`servers/NN-*.conf`, on top of `common.conf`): instance N listens on
port 2000+N and its tun address 10.8.N.1 answers ping.

| Instance | Scenarios | What it tests |
|---|---|---|
| 01-udp | `udp-cert-rsa`, `udp-cert-p256`, `udp-x509-name`, `reject-rogue-client`, `reject-x509-name` | Certificate only over UDP, RSA and ECDSA P-256 client keys, `verify-x509-name` |
| 02-tcp | `tcp-cert` | TCP |
| 03-password | `password`, `reject-password` | `auth-user-pass` only (`verify-client-cert none`) |
| 04-cert-password | `cert-password` | Certificate and password |
| 05-static-challenge | `static-challenge` | `static-challenge`: the password goes as `SCRV1:base64(password):base64(code)` |
| 06-dynamic-challenge | `dynamic-challenge` | CRV1: the password is answered with `AUTH_FAILED,CRV1:R,E:...`, the code goes on the next connection as `CRV1::<state>::<code>` |
| 07-tls-auth | `tls-auth` | `tls-auth` with key direction 1 on the client, HMAC SHA256 |
| 08-tls-crypt | `tls-crypt`, `reject-tls-crypt-key` | `tls-crypt` |
| 09 to 11 | `cipher-aes-256-gcm`, `cipher-aes-128-gcm`, `cipher-chacha20-poly1305` | One data cipher per server (`data-ciphers`) |
| 12, 13 | `compress-stub-v2`, `comp-lzo-no` | Compression framing pushed, without compression |
| 14-net30 | `topology-net30` | `topology net30` (the others use `subnet`) |
| 15-push-options | `push-options` | Pushed route 10.99.0.0/16 (10.99.0.1 is pinged), `redirect-gateway def1`, `dhcp-option DNS` and `DOMAIN` |
| 16-reneg | `reneg` | The server renegotiates every 60 s; the client pings every second for 80 s (`RENEG_DURATION`) |
| 17, 18 | `tls12`, `tls13` | TLS 1.2 at most, TLS 1.3 only |
| 19-no-eku | `no-eku-unchecked`, `reject-server-eku` | A server certificate without extended key usage: accepted without `remote-cert-tls server`, refused with it |

The user is `alice`, the password `alice-password`, the one-time code
`123456`; `auth.sh` checks them on the server. Scenarios named `reject-*`
must fail, with an error matching the pattern `run.sh` gives for each
client; where the server can tell why (wrong password, untrusted client
certificate, wrong tls-crypt key), its log must say so too. The patterns
for the omnitun client are guesses until the engine exists: adjust them to
its messages. Some scenarios also check the server's log (the negotiated
data cipher and TLS version, the renegotiation) or what was pushed
(`INTEROP_EXPECT`).

The interop example answers the engine's questions from `INTEROP_USERNAME`,
`INTEROP_PASSWORD` and `INTEROP_OTP` (both challenges), keeps the tunnel
up for `INTEROP_DURATION` seconds when set, and signs the TLS client
CertificateVerify with the client certificate's PKCS#8 key from the PKI
directory, where the app uses the Keychain: the profiles name the
certificate by its SHA-256 (`client_certificate`) and carry its chain, never
the key.

`make-pki.sh` makes the test certificates and keys once, in `pki/` (not in
git): a CA, the server certificate (EKU serverAuth), one without extended
key usage, RSA and ECDSA P-256 client certificates (EKU clientAuth), one
from another CA, the tls-auth and tls-crypt keys and a second tls-crypt
key. A server certificate with EKU clientAuth alone would not test
`remote-cert-tls`: OpenSSL already refuses it for a TLS server.

Logs of failed scenarios are left in `last-<name>.log` (client, then the
server's lines for that scenario), all the servers' in `last-server.log`.
Everything here is test material: the keys and passwords are not secrets.

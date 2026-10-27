# strongSwan interoperability tests

`./run.sh` builds a strongSwan gateway image and a Linux build of the
`interop` example (`crates/vpn-ipsec/examples/interop.rs`), then runs every
scenario of `profiles.toml`: connect, ping 10.99.1.1 through the tunnel,
disconnect. `./run.sh v2-chacha v1-3des` runs only those; `KEEP=1` keeps the
gateway running, `RUST_LOG=debug` makes the client verbose.

Both sides run in containers on the `omnitun-interop` network (gateway
172.30.0.2): Docker Desktop's port forwarding from macOS loses
UDP-encapsulated ESP (it changes the source port between datagrams).

`make-pki.sh` makes the test certificates once, in `pki/` (not in git): a
CA, gateway and client certificates with RSA, ECDSA P-256 and P-384 keys,
and one of each from another CA. The client keys are also written as
PKCS#8: the interop client signs with them where the app uses the
Keychain. The `cert-*` scenarios run three times: with the gateway's
default RFC 7427 signatures (RSA PKCS#1 v1.5, ECDSA), with the classic
methods (`-classic`: RSA, ECDSA-256/384, which the client then uses too)
and with RSA-PSS (`-pss`). Scenarios named `reject-*` must fail: an
untrusted CA on either side, a changed pinned certificate, a PSK where a
certificate is expected.

Logs of failed scenarios are left in `last-<name>.log`, the gateway's in
`last-gateway.log`. Everything here is test material: the PSK and passwords
are not secrets.

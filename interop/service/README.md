# Service tests (Linux, systemd)

`./run.sh` builds the Linux binaries (Debian bookworm), starts an Ubuntu
24.04 container that boots systemd (`--privileged`), and runs `test.sh` in
it:

1. installs the binaries, the `omnitun` group, the `_omnitun` account and
   `packaging/omnitund.service` with the commands of the main README
   (From source, Linux), starts the service and prints the exposure score
   of `systemd-analyze security`;
2. starts a WireGuard server (the kernel's) in its own network namespace;
3. as a member of the group, stores the client key in the Secret Service
   (gnome-keyring), connects through the service, pings the server's
   tunnel address (10.9.0.1), checks the split DNS domain in
   systemd-resolved, and disconnects;
4. checks that the server saw a handshake;
5. routes by domain (#37), with a resolver in place on this machine
   (dnsmasq on 127.0.0.2, as the system's) and the tunnel's in the
   server's namespace: a split tunnel including `*.saas.test` routes its
   address through the tunnel only once resolved, reaches it, keeps the
   tunnel's domain on its servers and gives the routed name no IPv6; with
   the DNS proxy killed, the DNS is back as without it; a full tunnel
   excluding `*.out.test` sends that address out through `eth0` once
   resolved (journaled), the rest through the tunnel; every route by
   domain is gone after disconnecting, and the service still runs.

It tests the unit's hardening against a real connection: the engines run
under the same restrictions as the daemon. `BINARIES=target/release
./run.sh` uses binaries built already (as the CI does,
`.github/workflows/service.yml`); `KEEP=1 ./run.sh` keeps the container
(`docker exec -it omnitun-interop-service bash`); on failure, the
service's journal is printed.

The server's address is the container's own, redirected to the namespace
(`iptables` DNAT): the daemon routes a gateway through the default
gateway, which the veth address would not survive.

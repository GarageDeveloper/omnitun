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
4. checks that the server saw a handshake and that the service still runs.

It tests the unit's hardening against a real connection: the engines run
under the same restrictions as the daemon. `KEEP=1 ./run.sh` keeps the
container (`docker exec -it omnitun-interop-service bash`); on failure,
the service's journal is printed.

The server's address is the container's own, redirected to the namespace
(`iptables` DNAT): the daemon routes a gateway through the default
gateway, which the veth address would not survive.

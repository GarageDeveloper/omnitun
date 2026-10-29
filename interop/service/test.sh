#!/bin/sh
# Runs inside the container (run.sh): installs from /target/release as
# README.md says, then connects a WireGuard VPN through the service.
set -eu
step() { echo "== $*"; }

step "install (README.md, From source, Linux)"
install -o root -m 755 /target/release/omnitund /target/release/omnitun-engine /usr/local/sbin/
install /target/release/omnitunctl /usr/local/bin/
useradd --create-home alice
groupadd --system omnitun && usermod -aG omnitun alice
useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin _omnitun
cp /src/packaging/omnitund.service /etc/systemd/system/ && systemctl enable --now omnitund
sleep 2
systemctl is-active omnitund
systemd-analyze security omnitund --no-pager | tail -1

step "WireGuard server"
# In its own network namespace behind a veth pair. The client's packets to
# this machine's address are redirected to it: a gateway gets a host route
# through the default gateway, which the veth address would not survive.
ip netns add server
ip link add veth0 type veth peer name veth1 netns server
ip address add 10.200.0.1/24 dev veth0 && ip link set veth0 up
ip -n server address add 10.200.0.2/24 dev veth1
ip -n server link set veth1 up && ip -n server link set lo up
ip -n server route add default via 10.200.0.1
server_key=$(wg genkey) client_key=$(wg genkey)
# In /etc/wireguard: the AppArmor profile of wg on Ubuntu hosts (the CI's)
# lets it read keys there only.
mkdir -p -m 700 /etc/wireguard
(umask 077 && echo "$server_key" > /etc/wireguard/server.key)
ip -n server link add wg0 type wireguard
ip netns exec server wg set wg0 listen-port 51820 private-key /etc/wireguard/server.key \
    peer "$(echo "$client_key" | wg pubkey)" allowed-ips 10.9.0.2/32
ip -n server address add 10.9.0.1/24 dev wg0 && ip -n server link set wg0 up
me=$(ip -4 -o address show eth0 | awk '{print $4}' | cut -d/ -f1)
iptables -t nat -A OUTPUT -d "$me" -p udp --dport 51820 -j DNAT --to-destination 10.200.0.2:51820

step "connect as alice"
mkdir -p /home/alice/.config/omnitun
cat > /home/alice/.config/omnitun/profiles.toml <<TOML
[[profile]]
name = "wg"
protocol = "wireguard"
endpoint = "$me"
public_key = "$(echo "$server_key" | wg pubkey)"
addresses = ["10.9.0.2/24"]
allowed_ips = ["10.9.0.0/24"]
dns_servers = ["10.9.0.53"]
dns_search = ["corp.test"]
TOML
chown -R alice:alice /home/alice/.config
echo "$client_key" > /home/alice/client.key && chown alice /home/alice/client.key
# The private key goes to the Secret Service (gnome-keyring: a password
# creates its default collection); omnitunctl reads secrets from a
# terminal.
sudo -u alice -i sh -s <<'ALICE'
set -eu
export XDG_RUNTIME_DIR=/tmp/alice-runtime
mkdir -p -m 700 "$XDG_RUNTIME_DIR"
exec dbus-run-session -- sh -eu -c '
  printf test | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  script -qec "omnitunctl secret set wg --key private_key" /dev/null < client.key >/dev/null
  omnitunctl connect wg
  omnitunctl status
  ping -c 3 -W 2 10.9.0.1
  resolvectl status | grep -q "corp.test" && echo "split DNS: corp.test set"
  omnitunctl disconnect --all
'
ALICE
ip netns exec server wg show wg0 latest-handshakes | awk '$2 != 0 {print "handshake seen by the server"}' | grep .

step "routes by domain (#37)"
# Each check stops the test when it fails.
expect() {
    if sh -c "$2"; then echo "$1"; else echo "FAILED: $1"; exit 1; fi
}
# The resolver in place before the VPN, on this machine: it knows the
# SaaS names and those to keep outside a full tunnel.
dnsmasq --listen-address=127.0.0.2 --bind-interfaces --no-resolv --no-hosts --pid-file=/run/dnsmasq-before.pid \
    --address=/saas.test/198.51.100.10 --address=/out.test/203.0.113.50 --address=/corp.test/192.0.2.99
resolvectl dns eth0 127.0.0.2
expect "resolver in place: app.saas.test" 'resolvectl query --cache=no app.saas.test | grep -q 198.51.100.10'
# The tunnel's DNS server, in the server's namespace; the SaaS address
# answers there only, so it is reached through the tunnel or not at all.
ip -n server address add 10.9.0.53/32 dev lo
ip -n server address add 198.51.100.10/32 dev lo
ip netns exec server dnsmasq --listen-address=10.9.0.53 --bind-interfaces --no-resolv --no-hosts \
    --pid-file=/run/dnsmasq-tunnel.pid --address=/corp.test/10.9.0.80
cat >> /home/alice/.config/omnitun/profiles.toml <<TOML

[[profile]]
name = "wg-saas"
protocol = "wireguard"
endpoint = "$me"
public_key = "$(echo "$server_key" | wg pubkey)"
addresses = ["10.9.0.2/24"]
allowed_ips = ["0.0.0.0/0"]
dns_servers = ["10.9.0.53"]
dns_search = ["corp.test"]
routes = ["10.9.0.0/24", { domain = "*.saas.test", note = "SaaS" }]

[[profile]]
name = "wg-full"
protocol = "wireguard"
endpoint = "$me"
public_key = "$(echo "$server_key" | wg pubkey)"
addresses = ["10.9.0.2/24"]
allowed_ips = ["0.0.0.0/0"]
dns_servers = ["10.9.0.53"]
full_tunnel = true
excluded_domains = [{ domain = "*.out.test", note = "Video" }]
TOML
chown alice:alice /home/alice/.config/omnitun/profiles.toml
# Commands as alice, her keyring unlocked; from a file, as sudo -i would
# expand them once more.
as_alice() {
    printf '%s\n' "printf test | gnome-keyring-daemon --unlock --components=secrets >/dev/null" "$1" > /tmp/as-alice.sh
    sudo -u alice -i env XDG_RUNTIME_DIR=/tmp/alice-runtime dbus-run-session -- sh -eu /tmp/as-alice.sh
}
tun_name() { ip -o link show type tun | awk -F': ' '{print $2}' | head -1; }
as_alice 'for p in wg-saas wg-full; do script -qec "omnitunctl secret set $p --key private_key" /dev/null < client.key >/dev/null; done'

echo "-- included through a split tunnel"
expect "no route before connecting" '! ip route get 198.51.100.10 | grep -q tun'
as_alice 'omnitunctl connect wg-saas'
export tun=$(tun_name)
expect "no route before resolving" '! ip route get 198.51.100.10 | grep -q "dev $tun"'
resolvectl query --cache=no eu.app.saas.test | grep -q 198.51.100.10
expect "routed through $tun once resolved" 'ip route get 198.51.100.10 | grep -q "dev $tun"'
expect "reached through the tunnel" 'ping -c 2 -W 2 198.51.100.10 >/dev/null'
as_alice 'omnitunctl status' | grep "by domain"
expect "the tunnel's domain still on its servers" 'resolvectl query --cache=no intranet.corp.test | grep -q 10.9.0.80'
expect "no IPv6 for a routed name" '! resolvectl query --cache=no -t AAAA app.saas.test 2>&1 | grep -q "2001:"'
echo "-- the proxy fails: the DNS as without it"
pkill -f -- "--dns-proxy"
sleep 1
expect "the tunnel's resolver back on $tun" 'resolvectl dns "$tun" | grep -q 10.9.0.53'
expect "DNS works without the proxy" 'resolvectl query --cache=no intranet.corp.test | grep -q 10.9.0.80'
as_alice 'omnitunctl disconnect --all'
expect "route by domain removed at disconnection" '! ip route show | grep -q 198.51.100.10'

echo "-- excluded from a full tunnel"
as_alice 'omnitunctl connect wg-full'
export tun=$(tun_name)
expect "inside the full tunnel before resolving" 'ip route get 203.0.113.50 | grep -q "dev $tun"'
resolvectl query --cache=no meet.out.test | grep -q 203.0.113.50
expect "kept outside once resolved" 'ip route get 203.0.113.50 | grep -q "dev eth0"'
expect "the rest still through the tunnel" 'ip route get 203.0.113.51 | grep -q "dev $tun"'
expect "other names through the tunnel's DNS" 'resolvectl query --cache=no intranet.corp.test | grep -q 10.9.0.80'
as_alice 'omnitunctl status' | grep "by domain"
expect "the exclusion journaled" 'grep -q 203.0.113.50 /run/omnitund.routes'
as_alice 'omnitunctl disconnect --all'
expect "exclusion removed at disconnection" '! ip route show | grep -q 203.0.113.50'
expect "route journal empty" '[ ! -s /run/omnitund.routes ]'
systemctl is-active omnitund
echo "PASSED"

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
echo "$server_key" > /root/server.key
ip -n server link add wg0 type wireguard
ip netns exec server wg set wg0 listen-port 51820 private-key /root/server.key \
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
systemctl is-active omnitund
echo "PASSED"

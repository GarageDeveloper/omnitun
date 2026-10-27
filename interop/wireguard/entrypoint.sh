#!/bin/sh
# One WireGuard server: wg0 at 10.9.0.1/24, listening on 51820, with one
# peer, the client, at 10.9.0.2. Keys come from the environment:
# SERVER_PRIVATE_KEY, CLIENT_PUBLIC_KEY, and PSK if the peer uses one.
set -eu
umask 077
echo "$SERVER_PRIVATE_KEY" >/etc/wireguard/server.key
ip link add wg0 type wireguard
wg set wg0 listen-port 51820 private-key /etc/wireguard/server.key
if [ -n "${PSK:-}" ]; then
    echo "$PSK" >/etc/wireguard/psk
    wg set wg0 peer "$CLIENT_PUBLIC_KEY" allowed-ips 10.9.0.2/32 preshared-key /etc/wireguard/psk
else
    wg set wg0 peer "$CLIENT_PUBLIC_KEY" allowed-ips 10.9.0.2/32
fi
ip address add 10.9.0.1/24 dev wg0
ip link set wg0 up
echo "wg0 up"
# Report the handshakes as they happen, for run.sh.
last=0
while true; do
    now=$(wg show wg0 latest-handshakes | awk '{print $2}')
    if [ "${now:-0}" != 0 ] && [ "$now" != "$last" ]; then
        echo "handshake with the client at $now"
        last=$now
    fi
    sleep 1
done

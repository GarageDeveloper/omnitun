#!/bin/sh
# Starts every server instance of servers/, each with its log in
# /var/log/openvpn. 10.99.0.1 is reachable through the routes pushed by
# the push-options server.
set -e
ip addr add 10.99.0.1/32 dev lo
mkdir -p /var/log/openvpn
for conf in /etc/openvpn/servers/*.conf; do
    name=${conf##*/}
    openvpn --cd /etc/openvpn --config "$conf" --log "/var/log/openvpn/${name%.conf}.log" &
done
wait

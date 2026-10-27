#!/bin/sh
# Starts one L2TP/IPsec server: charon (IKEv1, PSK, ESP in transport mode
# for UDP 1701), xl2tpd and the pppd it spawns for each session. The
# argument names the server (see the table below); server N's pppd has
# the address 10.9.N.1, which answers ping, and gives 10.9.N.10 and up to
# its clients. The logs of all three go to stdout.
set -e
psk=omnitun-interop-psk
ike="aes256-sha256-modp2048, aes256-sha1-modp2048, aes128-sha1-modp2048"
esp="aes256-sha256, aes256-sha1, aes128-sha1"
remote_id=%any aggressive=no lifetimes= ike_lifetimes= auth=require-mschap-v2 dns=
case ${1:-} in
mschapv2) n=1 ;;
chap) n=2 auth=require-chap ;;
pap) n=3 auth=require-pap ;;
# Aggressive mode: the client sends the group name as a KEY_ID identity.
aggressive) n=4 aggressive=yes remote_id=keyid:omnitun-group ;;
legacy) n=5 ike=3des-sha1-modp1024 esp=3des-sha1 ;;
dns) n=6 dns="ms-dns 10.9.6.53
ms-dns 10.9.6.54" ;;
# The server rekeys the ESP SA after 60 s (it expires after 90 s).
rekey) n=7 lifetimes="rekey_time = 60s
                life_time = 90s
                rand_time = 5s" ;;
# The server re-authenticates after 60 s: IKEv1 has no IKE SA rekey, so
# strongSwan starts a new main mode, then a Quick Mode on it, and deletes
# the previous IKE SA.
reauth) n=8 ike_lifetimes="reauth_time = 60s
        rand_time = 5s" ;;
*)
    echo "unknown server ${1:-}" >&2
    exit 2
    ;;
esac

cat >/etc/swanctl/swanctl.conf <<EOF
connections {
    l2tp {
        version = 1
        aggressive = $aggressive
        proposals = $ike
        dpd_delay = 30s
        $ike_lifetimes
        local {
            auth = psk
        }
        remote {
            auth = psk
            id = $remote_id
        }
        children {
            l2tp {
                mode = transport
                local_ts = dynamic[udp/1701]
                remote_ts = dynamic[udp]
                esp_proposals = $esp
                $lifetimes
            }
        }
    }
}
secrets {
    ike-l2tp {
        secret = $psk
    }
}
EOF

mkdir -p /var/run/xl2tpd
cat >/etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = 10.9.$n.10-10.9.$n.30
local ip = 10.9.$n.1
require authentication = yes
name = omnitun-l2tp
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

# pppd authenticates the client (xl2tpd adds no option of its own with
# these settings) and logs every packet (debug).
cat >/etc/ppp/options.xl2tpd <<EOF
$auth
$dns
name omnitun-l2tp
mtu 1400
mru 1400
noccp
nodefaultroute
lcp-echo-interval 10
lcp-echo-failure 6
logfile /var/log/ppp.log
debug
EOF
printf '"alice" * "alice-password" *\n' >/etc/ppp/chap-secrets
printf '"alice" * "alice-password" *\n' >/etc/ppp/pap-secrets
chmod 600 /etc/ppp/chap-secrets /etc/ppp/pap-secrets

/usr/lib/strongswan/charon &
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S /var/run/charon.vici ] && break
    sleep 0.5
done
swanctl --load-all
touch /var/log/ppp.log
tail -F /var/log/ppp.log 2>/dev/null &
exec xl2tpd -D

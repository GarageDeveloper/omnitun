#!/bin/sh
# Runs one scenario with the stock Linux client, to check the bench itself
# (CLIENT=stock ./run.sh): strongSwan (IKEv1, PSK, ESP in transport mode
# for UDP 1701, UDP encapsulation forced as the engine does it), xl2tpd
# and pppd. Connects, pings an address through the tunnel, disconnects.
#
#     stock-client.sh <ip to ping>
#
# From the environment: INTEROP_SERVER (its address), INTEROP_PSK,
# INTEROP_USERNAME, INTEROP_PASSWORD, INTEROP_IKE and INTEROP_ESP (the
# proposals), INTEROP_GROUP (aggressive mode with that KEY_ID identity),
# INTEROP_PPP (more pppd options: the refused authentications),
# INTEROP_DURATION (keep the tunnel up that many seconds, pinging every
# second; 90% must be answered), INTEROP_EXPECT (what IPCP must have
# given, separated by commas: dns=<ip>).
set -u
target=$1
server=$INTEROP_SERVER
duration=${INTEROP_DURATION:-0}
[ -n "$duration" ] || duration=0

say() { echo "stock-client: $*"; }
dump() {
    for log in charon xl2tpd ppp; do
        echo "--- $log"
        cat /var/log/$log.log 2>/dev/null
    done
}
fail() {
    dump
    say "$*"
    exit 1
}

aggressive=no local_id=
if [ -n "${INTEROP_GROUP:-}" ]; then
    aggressive=yes
    local_id="id = keyid:$INTEROP_GROUP"
fi
cat >/etc/swanctl/swanctl.conf <<EOF
connections {
    l2tp {
        version = 1
        aggressive = $aggressive
        remote_addrs = $server
        # Fake NAT-D payloads: UDP-encapsulated ESP on port 4500.
        encap = yes
        proposals = $INTEROP_IKE
        local {
            auth = psk
            $local_id
        }
        remote {
            auth = psk
        }
        children {
            l2tp {
                mode = transport
                local_ts = dynamic[udp/1701]
                remote_ts = dynamic[udp/1701]
                esp_proposals = $INTEROP_ESP
            }
        }
    }
}
secrets {
    ike-l2tp {
        secret = $INTEROP_PSK
    }
}
EOF

/usr/lib/strongswan/charon >/var/log/charon.log 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S /var/run/charon.vici ] && break
    sleep 0.5
done
swanctl --load-all >/dev/null || fail "swanctl --load-all failed"
if ! swanctl --initiate --child l2tp --timeout 20 >/dev/null 2>&1; then
    # A wrong PSK shows as messages the client cannot decrypt.
    reason=$(grep -E "decryption failed|AUTHENTICATION_FAILED|INVALID_|NO_PROPOSAL|no proposal|giving up|timed out" \
        /var/log/charon.log | head -1 | sed 's/^[0-9:]* [0-9]*\[[A-Z]*\] //')
    fail "IPsec failed: ${reason:-swanctl --initiate failed}"
fi
say "IPsec SA up"

mkdir -p /var/run/xl2tpd
cat >/etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lac server]
lns = $server
pppoptfile = /etc/ppp/options.client
length bit = yes
redial = no
EOF
cat >/etc/ppp/options.client <<EOF
user ${INTEROP_USERNAME:-alice}
password ${INTEROP_PASSWORD:-}
noauth
usepeerdns
ipcp-accept-local
ipcp-accept-remote
refuse-eap
noccp
nodefaultroute
mtu 1400
mru 1400
${INTEROP_PPP:-}
logfile /var/log/ppp.log
debug
EOF
xl2tpd -D >/var/log/xl2tpd.log 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -p /var/run/xl2tpd/l2tp-control ] && break
    sleep 0.5
done
echo "c server" >/var/run/xl2tpd/l2tp-control

# PPP up (an address on ppp0) or given up.
address=
for _ in $(seq 30); do
    address=$(ip -4 -o addr show dev ppp0 2>/dev/null | sed -n 's/.* inet \([0-9.]*\).*/\1/p')
    [ -n "$address" ] && break
    grep -qE "Connection terminated|Exit\.|LCP terminated" /var/log/ppp.log 2>/dev/null && break
    sleep 1
done
if [ -z "$address" ]; then
    reason=$(grep -iE "auth|refuse|fail|terminat" /var/log/ppp.log 2>/dev/null | grep -v "^rcvd\|^sent" | head -1)
    fail "PPP failed: ${reason:-no address on ppp0}"
fi
# The DNS servers IPCP gave ("primary DNS address ...", usepeerdns).
dns=$(sed -n 's/^[a-z]* *DNS address \([0-9.]*\)$/\1/p' /var/log/ppp.log | tr '\n' ' ')
say "connected: address $address, dns $dns"

# Every second for the duration, or until the first answer (five tries).
count=$duration
[ "$count" -gt 0 ] || count=5
sent=0 answered=0
for _ in $(seq "$count"); do
    sent=$((sent + 1))
    start=$(date +%s)
    if ping -c 1 -W 1 "$target" >/dev/null 2>&1; then
        answered=$((answered + 1))
        [ "$duration" -gt 0 ] || break
    fi
    [ "$(date +%s)" != "$start" ] || sleep 1
done

missing=
for item in $(echo "${INTEROP_EXPECT:-}" | tr ',' ' '); do
    case $item in
    dns=*) case " $dns " in *" ${item#dns=} "*) ;; *) missing="$missing $item" ;; esac ;;
    *) missing="$missing $item" ;;
    esac
done

echo "d server" >/var/run/xl2tpd/l2tp-control
sleep 1
swanctl --terminate --ike l2tp --timeout 5 >/dev/null 2>&1
[ -z "$missing" ] || fail "not given by IPCP:$missing"
if [ $answered -eq 0 ] || [ $((answered * 10)) -lt $((sent * 9)) ]; then
    fail "$answered of $sent pings to $target answered through the tunnel"
fi
dump
say "ping $target through the tunnel: ok ($answered of $sent answered)"

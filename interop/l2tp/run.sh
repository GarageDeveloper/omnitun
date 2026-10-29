#!/bin/sh
# Runs the L2TP engine against L2TP/IPsec servers in Docker (strongSwan,
# xl2tpd, pppd): every scenario of profiles.toml (or those named as
# arguments) connects, pings the server's PPP address through the tunnel
# and disconnects; reject-* scenarios must fail with the expected error.
# Keep the servers with KEEP=1, the logs of the scenarios that passed with
# KEEP_LOGS=1.
#
# CLIENT=stock runs the same scenarios with the stock Linux client
# (strongSwan, xl2tpd and pppd, driven by stock-client.sh) instead of the
# interop example: it checks the bench itself.
#
# Both sides run in containers on the omnitun-interop-l2tp network
# (server N at 172.32.0.1N): Docker Desktop's port forwarding from macOS
# loses UDP-encapsulated ESP.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
image=omnitun-interop-l2tp
prefix=omnitun-interop-l2tp
network=omnitun-interop-l2tp
client=${CLIENT:-omnitun}

case $client in
omnitun)
    echo "building the Linux client..."
    # The build directory is a volume: builds in the macOS shared folder
    # see their own intermediate files late.
    docker run --rm -v "$root:/src" -v omnitun-interop-cargo:/usr/local/cargo/registry -w /src \
        -v omnitun-interop-target:/target -e CARGO_TARGET_DIR=/target rust:1-alpine \
        sh -c 'apk add -q musl-dev >/dev/null && cargo build -q -p vpn-l2tp --example l2tp-interop' || exit 1
    ;;
stock) ;;
*)
    echo "CLIENT must be omnitun or stock" >&2
    exit 2
    ;;
esac

docker build -q -t "$image" "$here" >/dev/null || exit 1
docker network inspect "$network" >/dev/null 2>&1 ||
    docker network create --subnet 172.32.0.0/24 "$network" >/dev/null || exit 1

# The servers (entrypoint.sh): server N listens on 172.32.0.1N, its pppd
# answers ping on 10.9.N.1.
servers="mschapv2 chap pap aggressive legacy dns rekey reauth"
server_number() {
    n=1
    for s in $servers; do
        [ "$s" = "$1" ] && return
        n=$((n + 1))
    done
}

# What each scenario needs besides its profile: the server, the stock
# client's proposals and pppd options, the PSK and password given, what
# IPCP must give (INTEROP_EXPECT), the lines (regular expressions) the
# server must log, how long to keep the tunnel up, and for reject-* the
# error each client must report.
scenario() {
    server= ike=aes256-sha256-modp2048 esp=aes256-sha256 group= ppp= expect= duration=0
    psk=omnitun-interop-psk password=alice-password server_log= refused= stock_refused=
    case $1 in
    psk-mschapv2) server=mschapv2 server_log="auth chap MS-v2" ;;
    chap-md5) server=chap server_log="auth chap MD5" ;;
    pap) server=pap server_log="auth pap" ;;
    aggressive-group) server=aggressive group=omnitun-group server_log="parsed AGGRESSIVE request" ;;
    legacy-3des)
        server=legacy ike=3des-sha1-modp1024 esp=3des-sha1
        server_log="selected proposal: IKE:3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
selected proposal: ESP:3DES_CBC/HMAC_SHA1_96"
        ;;
    dns-ipcp) server=dns expect="dns=10.9.6.53,dns=10.9.6.54" ;;
    # The server rekeys the ESP SA after 60 s; the client pings across it.
    # The old SA ends either way: it expires, or the client deletes it.
    rekey)
        server=rekey duration=${REKEY_DURATION:-100}
        server_log="creating rekey job for CHILD_SA
CHILD_SA l2tp\{2\} established
closing (expired )?CHILD_SA l2tp\{1\}"
        ;;
    # The server re-authenticates (a new main mode it starts) after 60 s;
    # the client answers it and pings across.
    reauth)
        server=reauth duration=${REAUTH_DURATION:-100}
        server_log="reauthenticating IKE_SA
IKE_SA l2tp\[2\] established
CHILD_SA l2tp\{2\} established"
        ;;
    # The client rekeys after 108 s and deletes the replaced SA at its end.
    rekey-client)
        server=chap duration=${REKEY_CLIENT_DURATION:-160}
        server_log="CHILD_SA l2tp\{[0-9]+\} established
received DELETE for ESP CHILD_SA"
        ;;
    reject-wrong-psk)
        server=mschapv2 psk=not-the-interop-psk
        server_log="decryption failed"
        refused="psk|pre-shared|hash|authentication|timeout|no answer|did not answer"
        stock_refused="IPsec failed: .*decryption failed"
        ;;
    reject-wrong-password)
        server=mschapv2 password=not-the-password
        server_log="Peer alice failed CHAP authentication"
        refused="password|ms-chap|mschap|authentication"
        stock_refused="PPP failed: MS-CHAP authentication failed"
        ;;
    # The server wants PAP, the profile allows MS-CHAPv2 only.
    reject-auth-method)
        server=pap ppp="refuse-pap refuse-chap refuse-mschap"
        refused="pap|authentication|refuse|not allowed"
        stock_refused="PPP failed: .*refused to authenticate"
        server_log="peer refused to authenticate|ConfNak id=0x1 <auth chap MS-v2>"
        ;;
    *) return 1 ;;
    esac
    server_number $server
    address=172.32.0.1$n
    target=10.9.$n.1
    # Every connection: UDP-encapsulated ESP although there is no NAT, the
    # transport-mode SA for UDP 1701 on both sides.
    case $1 in
    reject-*) ;;
    *) server_log="$server_log
remote host is behind NAT
CHILD_SA l2tp\{[0-9]+\} established .* TS [0-9.]+/32\[udp/l2f\] === [0-9.]+/32\[udp/l2f\]" ;;
    esac
}

all=$(sed -n 's/^name = "\(.*\)"/\1/p' "$here/profiles.toml")
names=${*:-$all}
needed=
for name in $names; do
    scenario "$name" && case " $needed " in *" $server "*) ;; *) needed="$needed $server" ;; esac
done
stop_servers() {
    for s in $servers; do docker rm -f "$prefix-$s" >/dev/null 2>&1; done
}
trap '[ "${KEEP:-0}" = 1 ] || stop_servers' EXIT
stop_servers
for s in $needed; do
    server_number "$s"
    docker run -d --name "$prefix-$s" --network "$network" --ip "172.32.0.1$n" --cap-add NET_ADMIN \
        --device /dev/ppp "$image" "$s" >/dev/null || exit 1
done
sleep 3

run() { # scenario
    name=$1
    if ! scenario "$name"; then
        echo "FAILED  $name (not described in run.sh)"
        failed=1
        return
    fi
    seen=$(docker logs "$prefix-$server" 2>&1 | wc -l)
    env="-e INTEROP_USERNAME=alice -e INTEROP_PASSWORD=$password -e INTEROP_PSK=$psk"
    env="$env -e INTEROP_DURATION=$duration -e INTEROP_EXPECT=$expect"
    if [ $client = stock ]; then
        pattern=$stock_refused
        docker run --rm --network "$network" --cap-add NET_ADMIN --device /dev/ppp $env \
            -e INTEROP_SERVER="$address" -e INTEROP_IKE="$ike" -e INTEROP_ESP="$esp" \
            -e INTEROP_GROUP="$group" -e INTEROP_PPP="$ppp" \
            --entrypoint /bin/sh "$image" /etc/l2tp/stock-client.sh "$target" >"$here/last-$name.log" 2>&1
    else
        pattern=$refused
        docker run --rm --network "$network" -v "$root:/src:ro" -v omnitun-interop-target:/target:ro \
            $env -e RUST_LOG="${RUST_LOG:-warn}" \
            alpine:3.22.7 /target/debug/examples/l2tp-interop /src/interop/l2tp/profiles.toml "$name" "$target" \
            >"$here/last-$name.log" 2>&1
    fi
    status=$?
    # Let the server log the end of the session (pppd, DELETE).
    sleep 2
    # The server's side of this scenario, appended to the log.
    docker logs "$prefix-$server" 2>&1 | tail -n +$((seen + 1)) >"$here/last-$name.server"
    refusal=$(grep -iE "$pattern" "$here/last-$name.log" | tail -1 | sed 's/^[0-9-]* [0-9:]* //' | cut -c1-100)
    result=ok
    case "$name" in
    reject-*) [ $status -ne 0 ] && [ -n "$pattern" ] && [ -n "$refusal" ] || result=FAILED ;;
    *) [ $status -eq 0 ] || result=FAILED ;;
    esac
    printf '%s\n' "$server_log" | while IFS= read -r line; do
        [ -z "$line" ] || grep -qE "$line" "$here/last-$name.server" || echo "the server did not log: $line"
    done >"$here/last-$name.missing"
    if [ -s "$here/last-$name.missing" ]; then
        cat "$here/last-$name.missing" >>"$here/last-$name.log"
        result=FAILED
    fi
    { echo "--- server"; cat "$here/last-$name.server"; } >>"$here/last-$name.log"
    rm -f "$here/last-$name.server" "$here/last-$name.missing"
    if [ $result = ok ]; then
        echo "ok      $name$( [ $status -ne 0 ] && printf ' (refused: %s)' "$refusal")"
        [ "${KEEP_LOGS:-0}" = 1 ] || rm -f "$here/last-$name.log"
    else
        echo "FAILED  $name (see interop/l2tp/last-$name.log)"
        failed=1
    fi
}

failed=0
for name in $names; do run "$name"; done
for s in $needed; do
    echo "=== $s"
    docker logs "$prefix-$s" 2>&1
done >"$here/last-server.log"
exit $failed

#!/bin/sh
# Runs the OpenVPN engine against OpenVPN 2.6 servers in Docker: every
# scenario of profiles.toml (or those named as arguments) connects, pings
# the server through the tunnel and disconnects; reject-* scenarios must
# fail with the expected error. Keep the servers with KEEP=1, the logs of
# the scenarios that passed with KEEP_LOGS=1.
#
# CLIENT=openvpn runs the same scenarios with the stock openvpn client
# (stock-client.py) instead of the interop example: it checks the bench
# itself.
#
# Both sides run in containers on the omnitun-interop-openvpn network
# (servers 172.31.0.2): Docker Desktop's port forwarding from macOS is not
# reliable for UDP.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
image=omnitun-interop-openvpn
server=omnitun-openvpn
network=omnitun-interop-openvpn
client=${CLIENT:-omnitun}

case $client in
omnitun)
    echo "building the Linux client..."
    # The build directory is a volume: builds in the macOS shared folder
    # see their own intermediate files late.
    docker run --rm -v "$root:/src" -v omnitun-interop-cargo:/usr/local/cargo/registry -w /src \
        -v omnitun-interop-target:/target -e CARGO_TARGET_DIR=/target rust:1-alpine \
        sh -c 'apk add -q musl-dev >/dev/null && cargo build -q -p vpn-openvpn --example openvpn-interop' || exit 1
    ;;
openvpn) ;;
*)
    echo "CLIENT must be omnitun or openvpn" >&2
    exit 2
    ;;
esac

docker build -q -t "$image" "$here" >/dev/null || exit 1
"$here/make-pki.sh" || exit 1
docker network inspect "$network" >/dev/null 2>&1 ||
    docker network create --subnet 172.31.0.0/24 "$network" >/dev/null || exit 1
trap '[ "${KEEP:-0}" = 1 ] || docker rm -f "$server" >/dev/null 2>&1' EXIT
docker rm -f "$server" >/dev/null 2>&1
docker run -d --name "$server" --network "$network" --ip 172.31.0.2 --cap-add NET_ADMIN \
    --device /dev/net/tun -v "$here/pki:/pki:ro" "$image" >/dev/null || exit 1
sleep 2

# What each scenario needs besides its profile: the server instance
# (servers/NN-*.conf, port 2000+NN, server address 10.8.NN.1), the
# stock client's options, the address to ping, what the server must have
# pushed (INTEROP_EXPECT), a line the server must log, how long to keep
# the tunnel up, and for reject-* the error each client must report.
scenario() {
    n= opts= rct="--remote-cert-tls server" target= expect= server_log= duration=0
    password=alice-password refused= stock_refused=
    cert="--cert /pki/client-rsa.pem --key /pki/client-rsa.key"
    pass="--auth-user-pass"
    case $1 in
    udp-cert-rsa) n=1 opts=$cert ;;
    udp-cert-p256) n=1 opts="--cert /pki/client-p256.pem --key /pki/client-p256.key" ;;
    udp-x509-name) n=1 opts="$cert --verify-x509-name server.omnitun.test name" ;;
    tcp-cert) n=2 opts=$cert ;;
    password) n=3 opts=$pass ;;
    cert-password) n=4 opts="$cert $pass" ;;
    static-challenge) n=5 opts="$pass --static-challenge 'Enter the code' 1" ;;
    dynamic-challenge) n=6 opts=$pass ;;
    tls-auth) n=7 opts="$cert --tls-auth /pki/tls-auth.key 1 --auth SHA256" ;;
    tls-crypt) n=8 opts="$cert --tls-crypt /pki/tls-crypt.key" ;;
    cipher-aes-256-gcm) n=9 opts=$cert server_log="cipher AES-256-GCM," ;;
    cipher-aes-128-gcm) n=10 opts=$cert server_log="cipher AES-128-GCM," ;;
    cipher-chacha20-poly1305) n=11 opts=$cert server_log="cipher CHACHA20-POLY1305," ;;
    compress-stub-v2) n=12 opts=$cert ;;
    comp-lzo-no) n=13 opts=$cert ;;
    topology-net30) n=14 opts=$cert ;;
    push-options)
        n=15 opts=$cert target=10.99.0.1
        expect="full-tunnel route=10.99.0.0/16 dns=10.8.15.53 domain=omnitun.test"
        ;;
    # The server renegotiates after 60 s; the client pings across it.
    reneg) n=16 opts=$cert duration=${RENEG_DURATION:-80} server_log="TLS: soft reset" ;;
    tls12) n=17 opts=$cert server_log="Control Channel: TLSv1.2" ;;
    tls13) n=18 opts=$cert server_log="Control Channel: TLSv1.3" ;;
    # A server certificate without serverAuth, accepted when the profile
    # does not ask for remote-cert-tls server.
    no-eku-unchecked) n=19 opts=$cert rct= ;;
    reject-password)
        n=3 opts=$pass password=not-the-password server_log="verification failed"
        refused="auth|password|login" stock_refused="AUTH_FAILED"
        ;;
    reject-rogue-client)
        # The server's alert does not always reach the client: the stock
        # client times out, the server's log says why.
        n=1 opts="--cert /pki/client-rogue.pem --key /pki/client-rogue.key --hand-window 10"
        server_log="unable to get local issuer certificate"
        refused="certificate|alert|handshake|tls|timeout" stock_refused="alert|TLS key negotiation failed"
        ;;
    reject-server-eku)
        n=19 opts=$cert
        refused="serverAuth|key usage|remote-cert-tls|server certificate" stock_refused="VERIFY EKU ERROR"
        ;;
    reject-tls-crypt-key)
        n=8 opts="$cert --tls-crypt /pki/tls-crypt-other.key --hand-window 10" server_log="tls-crypt unwrapping failed"
        refused="timeout|tls-crypt|did not answer|no answer" stock_refused="TLS key negotiation failed"
        ;;
    reject-x509-name)
        n=1 opts="$cert --verify-x509-name other.omnitun.test name"
        refused="verify-x509-name|x509 name|common name|subject" stock_refused="VERIFY X509NAME ERROR"
        ;;
    *) return 1 ;;
    esac
    port=$((2000 + n))
    proto=udp
    [ "$n" = 2 ] && proto=tcp
    opts="--remote 172.31.0.2 $port $proto --ca /pki/ca.pem $rct $opts"
    target=${target:-10.8.$n.1}
    log=/var/log/openvpn/$(printf %02d "$n")-*.log
}

run() { # scenario
    name=$1
    if ! scenario "$name"; then
        echo "FAILED  $name (not described in run.sh)"
        failed=1
        return
    fi
    seen=$(docker exec "$server" sh -c "cat $log | wc -l")
    env="-e INTEROP_USERNAME=alice -e INTEROP_PASSWORD=$password -e INTEROP_OTP=123456"
    env="$env -e INTEROP_DURATION=$duration -e INTEROP_EXPECT=$(printf %s "$expect" | tr ' ' ,)"
    if [ $client = openvpn ]; then
        pattern=$stock_refused
        eval "set -- $opts"
        docker run --rm --network "$network" --cap-add NET_ADMIN --device /dev/net/tun \
            -v "$here/pki:/pki:ro" $env -e INTEROP_EXPECT_ERROR="$pattern" --entrypoint python3 "$image" \
            /etc/openvpn/stock-client.py "$target" "$@" >"$here/last-$name.log" 2>&1
    else
        pattern=$refused
        docker run --rm --network "$network" -v "$root:/src:ro" -v omnitun-interop-target:/target:ro \
            -e INTEROP_PKI=/src/interop/openvpn/pki $env -e RUST_LOG="${RUST_LOG:-warn}" \
            alpine:3.22.7 /target/debug/examples/openvpn-interop /src/interop/openvpn/profiles.toml "$name" "$target" \
            >"$here/last-$name.log" 2>&1
    fi
    status=$?
    # The server's side of this scenario, appended to the log.
    docker exec "$server" sh -c "cat $log" | tail -n +$((seen + 1)) >"$here/last-$name.server"
    refusal=$(grep -iE "$pattern" "$here/last-$name.log" | tail -1 | sed 's/^[0-9-]* [0-9:]* //' | cut -c1-100)
    result=ok
    case "$name" in
    reject-*) [ $status -ne 0 ] && [ -n "$pattern" ] && [ -n "$refusal" ] || result=FAILED ;;
    *) [ $status -eq 0 ] || result=FAILED ;;
    esac
    if [ -n "$server_log" ] && ! grep -qF "$server_log" "$here/last-$name.server"; then
        echo "the server did not log: $server_log" >>"$here/last-$name.log"
        result=FAILED
    fi
    { echo "--- server"; cat "$here/last-$name.server"; } >>"$here/last-$name.log"
    rm -f "$here/last-$name.server"
    if [ $result = ok ]; then
        echo "ok      $name$( [ $status -ne 0 ] && printf ' (refused: %s)' "$refusal")"
        [ "${KEEP_LOGS:-0}" = 1 ] || rm -f "$here/last-$name.log"
    else
        echo "FAILED  $name (see interop/openvpn/last-$name.log)"
        failed=1
    fi
}

all=$(sed -n 's/^name = "\(.*\)"/\1/p' "$here/profiles.toml")
names=${*:-$all}
failed=0
for name in $names; do run "$name"; done
docker exec "$server" sh -c 'tail -n +1 /var/log/openvpn/*.log' >"$here/last-server.log" 2>&1
exit $failed

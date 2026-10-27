#!/bin/sh
# Runs the WireGuard engine against the Linux kernel's WireGuard in
# Docker: every scenario (or those named as arguments) connects, pings the
# server through the tunnel and disconnects; reject-* scenarios must fail
# with the expected error. Keep the logs of the scenarios that passed with
# KEEP_LOGS=1.
#
# Both sides run in containers on the omnitun-interop-wireguard network
# (the server at 172.33.0.10); the client is the wg-interop example.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
image=omnitun-interop-wireguard
server=omnitun-interop-wireguard
network=omnitun-interop-wireguard

echo "building the Linux client..."
# The build directory is a volume: builds in the macOS shared folder see
# their own intermediate files late.
docker run --rm -v "$root:/src" -v omnitun-interop-cargo:/usr/local/cargo/registry -w /src \
    -v omnitun-interop-target:/target -e CARGO_TARGET_DIR=/target rust:1-alpine \
    sh -c 'apk add -q musl-dev >/dev/null && cargo build -q -p vpn-wireguard --example wg-interop' || exit 1
docker build -q -t "$image" "$here" >/dev/null || exit 1
docker network inspect "$network" >/dev/null 2>&1 ||
    docker network create --subnet 172.33.0.0/24 "$network" >/dev/null || exit 1

key() { docker run --rm --entrypoint wg "$image" genkey; }
public() { echo "$1" | docker run --rm -i --entrypoint wg "$image" pubkey; }
psk() { docker run --rm --entrypoint wg "$image" genpsk; }

# What each scenario needs: its profile, whether the peer uses a PSK, the
# private key the client offers (another one for reject-wrong-key), how
# long to ping, what the settings must hold (INTEROP_EXPECT), and for
# reject-* the error expected.
scenario() {
    use_psk= duration=0 expect= refused= wrong_key=
    case $1 in
    split) expect="route=10.9.0.0/24,dns=10.9.0.53" ;;
    full) expect="full-tunnel" ;;
    psk) use_psk=1 ;;
    # WireGuard rekeys after 120 s of traffic: ping across it.
    rekey) duration=${REKEY_DURATION:-140} ;;
    reject-wrong-key) wrong_key=1 refused="did not answer" ;;
    reject-wrong-psk) use_psk=1 wrong_key=psk refused="did not answer" ;;
    *) return 1 ;;
    esac
}

all="split full psk rekey reject-wrong-key reject-wrong-psk"
names=${*:-$all}
trap 'docker rm -f "$server" >/dev/null 2>&1' EXIT

failed=0
for name in $names; do
    if ! scenario "$name"; then
        echo "FAILED  $name (not described in run.sh)"
        failed=1
        continue
    fi
    server_key=$(key) client_key=$(key) shared=
    [ -n "$use_psk" ] && shared=$(psk)
    client_public=$(public "$client_key")
    docker rm -f "$server" >/dev/null 2>&1
    docker run -d --name "$server" --network "$network" --ip 172.33.0.10 --cap-add NET_ADMIN \
        -e SERVER_PRIVATE_KEY="$server_key" -e CLIENT_PUBLIC_KEY="$client_public" -e PSK="$shared" \
        "$image" >/dev/null || exit 1
    offered_key=$client_key offered_psk=$shared
    case $wrong_key in
    1) offered_key=$(key) ;;
    psk) offered_psk=$(psk) ;;
    esac
    case $name in
    full) allowed='"0.0.0.0/0"' ;;
    *) allowed='"10.9.0.0/24"' ;;
    esac
    cat >"$here/last-profiles.toml" <<PROFILE
[[profile]]
name = "$name"
protocol = "wireguard"
endpoint = "172.33.0.10"
public_key = "$(public "$server_key")"
addresses = ["10.9.0.2/32"]
allowed_ips = [$allowed]
preshared_key = $([ -n "$use_psk" ] && echo true || echo false)
persistent_keepalive = 25
dns_servers = ["10.9.0.53"]
dns_search = ["interop.example"]
PROFILE
    sleep 1
    docker run --rm --network "$network" -v "$root:/src:ro" -v omnitun-interop-target:/target:ro \
        -e INTEROP_PRIVATE_KEY="$offered_key" -e INTEROP_PSK="$offered_psk" -e INTEROP_DURATION="$duration" \
        -e INTEROP_EXPECT="$expect" -e RUST_LOG="${RUST_LOG:-warn}" \
        alpine:3.22.7 /target/debug/examples/wg-interop /src/interop/wireguard/last-profiles.toml "$name" 10.9.0.1 \
        >"$here/last-$name.log" 2>&1
    status=$?
    { echo "--- server"; docker logs "$server" 2>&1; } >>"$here/last-$name.log"
    result=ok
    case $name in
    reject-*)
        [ $status -ne 0 ] && grep -q "$refused" "$here/last-$name.log" || result=FAILED
        grep -q "handshake with the client" "$here/last-$name.log" && result=FAILED
        ;;
    *)
        [ $status -eq 0 ] || result=FAILED
        grep -q "handshake with the client" "$here/last-$name.log" || result=FAILED
        ;;
    esac
    if [ $result = ok ]; then
        echo "ok      $name"
        [ "${KEEP_LOGS:-0}" = 1 ] || rm -f "$here/last-$name.log"
    else
        echo "FAILED  $name (see interop/wireguard/last-$name.log)"
        failed=1
    fi
done
rm -f "$here/last-profiles.toml"
exit $failed

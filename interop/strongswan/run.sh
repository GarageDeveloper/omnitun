#!/bin/sh
# Runs the IPsec engine against strongSwan in Docker: every scenario of
# profiles.toml (or those named as arguments) connects, pings 10.99.1.1
# through the tunnel and disconnects. Keep the gateway with KEEP=1.
#
# The client runs in a Linux container on the gateway's network: Docker
# Desktop's port forwarding from macOS loses UDP-encapsulated ESP.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
image=omnitun-interop-strongswan
gateway=omnitun-strongswan
network=omnitun-interop

echo "building the Linux client..."
# The build directory is a volume: builds in the macOS shared folder see
# their own intermediate files late.
docker run --rm -v "$root:/src" -v omnitun-interop-cargo:/usr/local/cargo/registry -w /src \
    -v omnitun-interop-target:/target -e CARGO_TARGET_DIR=/target rust:1-alpine \
    sh -c 'apk add -q musl-dev >/dev/null && cargo build -q -p vpn-ipsec --example interop' || exit 1

docker build -q -t "$image" "$here" >/dev/null || exit 1
"$here/make-pki.sh" || exit 1
docker network inspect "$network" >/dev/null 2>&1 ||
    docker network create --subnet 172.30.0.0/24 "$network" >/dev/null || exit 1
trap '[ "${KEEP:-0}" = 1 ] || docker rm -f "$gateway" >/dev/null 2>&1' EXIT

start_gateway() {
    docker rm -f "$gateway" >/dev/null 2>&1
    docker run -d --name "$gateway" --network "$network" --ip 172.30.0.2 --cap-add NET_ADMIN \
        -e SIGNATURES="$1" -v "$here/pki:/pki:ro" "$image" >/dev/null || exit 1
    sleep 3
}

run() { # scenario, label
    name=$1
    docker run --rm --network "$network" -v "$root:/src:ro" -v omnitun-interop-target:/target:ro \
        -e INTEROP_PKI=/src/interop/strongswan/pki \
        -e INTEROP_PSK=omnitun-interop-psk -e INTEROP_PASSWORD=alice-password -e RUST_LOG="${RUST_LOG:-warn}" \
        alpine:3.22 /target/debug/examples/interop /src/interop/strongswan/profiles.toml "$name" 10.99.1.1 \
        >"$here/last-$2.log" 2>&1
    status=$?
    case "$name" in
    reject-*) [ $status -ne 0 ] && result=ok || result=FAILED ;;
    *) [ $status -eq 0 ] && result=ok || result=FAILED ;;
    esac
    if [ $result = ok ]; then
        echo "ok      $2$( [ $status -ne 0 ] && printf ' (refused: %s)' "$(tail -1 "$here/last-$2.log" | cut -c8-110)")"
        rm -f "$here/last-$2.log"
    else
        echo "FAILED  $2 (see interop/strongswan/last-$2.log)"
        failed=1
    fi
}

all=$(sed -n 's/^name = "\(.*\)"/\1/p' "$here/profiles.toml")
names=${*:-$all}
failed=0
start_gateway default
for name in $names; do run "$name" "$name"; done
docker logs "$gateway" >"$here/last-gateway.log" 2>&1
# The other signature schemes, for the certificate scenarios.
for scheme in classic pss; do
    certs=$(printf '%s\n' $names | grep '^cert-')
    [ -n "$certs" ] || continue
    start_gateway $scheme
    for name in $certs; do run "$name" "$name-$scheme"; done
    docker logs "$gateway" >"$here/last-gateway-$scheme.log" 2>&1
done
exit $failed

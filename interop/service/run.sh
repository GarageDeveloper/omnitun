#!/bin/sh
# Builds the Linux binaries, starts a systemd machine in Docker and runs
# test.sh in it: install as README.md says, then a WireGuard connection
# through the service under packaging/omnitund.service.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
name=omnitun-interop-service

echo "building the Linux binaries..."
# The build directory is a volume: builds in the macOS shared folder see
# their own intermediate files late.
docker run --rm -v "$root:/src" -v omnitun-interop-cargo:/usr/local/cargo/registry -w /src \
    -v omnitun-interop-service-target:/target -e CARGO_TARGET_DIR=/target rust:1-bookworm \
    sh -c 'apt-get update -q >/dev/null && apt-get install -qy libdbus-1-dev pkg-config >/dev/null &&
           cargo build -q --release --locked -p omnitund -p omnitun-engine -p omnitunctl' || exit 1
docker build -q -t "$name" "$here" >/dev/null || exit 1
docker rm -f "$name" >/dev/null 2>&1
trap 'docker rm -f "$name" >/dev/null 2>&1' EXIT
docker run -d --name "$name" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
    -v "$root:/src:ro" -v omnitun-interop-service-target:/target:ro "$name" >/dev/null || exit 1
# systemd up
until docker exec "$name" systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"; do sleep 1; done
if docker exec "$name" sh /src/interop/service/test.sh; then
    status=0
else
    status=1
    docker exec "$name" journalctl -u omnitund --no-pager -n 60
fi
[ "${KEEP:-}" = 1 ] && { trap - EXIT; echo "kept: docker exec -it $name bash"; }
exit $status

# A WireGuard server (the Linux kernel's, set up with wireguard-tools) to
# test the WireGuard engine against (see README.md). Docker Desktop's
# kernel has WireGuard built in.
FROM alpine:3.22.7
RUN apk add --no-cache wireguard-tools-wg iproute2
COPY entrypoint.sh /etc/wireguard/
ENTRYPOINT ["/bin/sh", "/etc/wireguard/entrypoint.sh"]

# OpenVPN 2.6 servers to test the OpenVPN engine against the reference
# implementation (see README.md). The same image runs the stock openvpn
# client for the check runs (CLIENT=openvpn ./run.sh), driven by
# stock-client.py.
FROM alpine:3.22.7
RUN apk add --no-cache 'openvpn~2.6' openssl iproute2 python3
COPY common.conf auth.sh entrypoint.sh stock-client.py /etc/openvpn/
COPY servers /etc/openvpn/servers
ENTRYPOINT ["/bin/sh", "/etc/openvpn/entrypoint.sh"]

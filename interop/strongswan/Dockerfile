# A strongSwan gateway to test the IPsec engine against a third-party
# implementation (see README.md).
FROM alpine:3.22
RUN apk add --no-cache strongswan iproute2
COPY strongswan.conf /etc/strongswan.conf
COPY swanctl.conf /etc/swanctl/swanctl.conf
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]

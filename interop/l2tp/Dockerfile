# L2TP/IPsec servers (strongSwan in transport mode, xl2tpd, pppd) to test
# the L2TP engine against the usual Linux implementation (see README.md).
# The same image runs the stock client for the check runs (CLIENT=stock
# ./run.sh): strongSwan, xl2tpd and pppd on the client side, driven by
# stock-client.sh.
FROM alpine:3.22.7
RUN apk add --no-cache 'strongswan~5.9' 'xl2tpd~1.3' 'ppp-daemon~2.5' iproute2
COPY strongswan.conf /etc/strongswan.conf
COPY entrypoint.sh stock-client.sh /etc/l2tp/
ENTRYPOINT ["/bin/sh", "/etc/l2tp/entrypoint.sh"]

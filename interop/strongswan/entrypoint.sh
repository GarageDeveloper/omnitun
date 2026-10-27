#!/bin/sh
# The address pinged through the tunnel, then charon and its configuration.
set -e
ip addr add 10.99.1.1/32 dev lo
# Test certificates from make-pki.sh, mounted on /pki.
cp /pki/ca.pem /pki/rogue-ca.pem /etc/swanctl/x509ca/
cp /pki/gw-*.pem /etc/swanctl/x509/
cp /pki/gw-*.key /etc/swanctl/private/
# Gateway signatures: RFC 7427 by default (RSA PKCS#1 v1.5, ECDSA),
# "classic" (RFC 7296 RSA and RFC 4754 ECDSA methods) or "pss" (RSA-PSS).
case "${SIGNATURES:-default}" in
classic) sed -i 's/load_modular = yes/&\n    signature_authentication = no/' /etc/strongswan.conf ;;
pss) sed -i 's/load_modular = yes/&\n    rsa_pss = yes/' /etc/strongswan.conf ;;
esac
/usr/lib/strongswan/charon &
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S /var/run/charon.vici ] && break
    sleep 0.5
done
swanctl --load-all
wait

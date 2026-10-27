#!/bin/sh
# Test certificates for the interop gateway, made once with strongSwan's
# pki tool: a CA, gateway certificates with RSA, ECDSA P-256 and P-384
# keys, one from another CA (not trusted by the profiles), and client
# certificates likewise (their keys also as PKCS#8, which the interop
# client signs with in place of the Keychain).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
[ -f "$here/pki/client-rogue.p8" ] && exit 0
rm -rf "$here/pki"
mkdir -p "$here/pki"
docker run --rm -v "$here/pki:/pki" -w /pki --entrypoint sh omnitun-interop-strongswan -c '
set -e
dn="C=CH, O=omnitun interop"
pki --gen --type rsa --size 3072 --outform pem > ca.key
pki --self --ca --lifetime 3650 --in ca.key --dn "$dn, CN=omnitun interop CA" --outform pem > ca.pem
pki --gen --type rsa --size 3072 --outform pem > rogue-ca.key
pki --self --ca --lifetime 3650 --in rogue-ca.key --dn "$dn, CN=someone else CA" --outform pem > rogue-ca.pem
issue() { # name key-type key-size ca
    pki --gen --type "$2" --size "$3" --outform pem > "gw-$1.key"
    pki --pub --in "gw-$1.key" | pki --issue --lifetime 1825 --cacert "$4.pem" --cakey "$4.key" \
        --dn "$dn, CN=gw-$1.omnitun.test" --san "gw-$1.omnitun.test" --flag serverAuth --outform pem > "gw-$1.pem"
}
issue rsa rsa 2048 ca
issue p256 ecdsa 256 ca
issue p384 ecdsa 384 ca
issue rogue rsa 2048 rogue-ca
client() { # name key-type key-size ca [dn]
    pki --gen --type "$2" --size "$3" --outform pem > "client-$1.key"
    pki --pub --in "client-$1.key" | pki --issue --lifetime 1825 --cacert "$4.pem" --cakey "$4.key" \
        --dn "$dn, CN=client-$1" --san "client-$1@omnitun.test" --flag clientAuth --outform pem > "client-$1.pem"
}
client rsa rsa 2048 ca
client p256 ecdsa 256 ca
client p384 ecdsa 384 ca
client rogue ecdsa 256 rogue-ca
'
for cert in "$here"/pki/gw-*.pem "$here"/pki/client-*.pem; do
    openssl x509 -in "$cert" -outform der | shasum -a 256 | cut -d' ' -f1 > "${cert%.pem}.sha256"
done
for key in "$here"/pki/client-*.key; do
    openssl pkcs8 -topk8 -nocrypt -in "$key" -outform der -out "${key%.key}.p8"
done

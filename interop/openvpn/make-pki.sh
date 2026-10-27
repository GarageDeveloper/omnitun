#!/bin/sh
# Test certificates and keys for the interop servers, made once with
# openssl and openvpn in the server image: a CA, the server certificate
# (EKU serverAuth), one without extended key usage (what remote-cert-tls
# server must refuse; with EKU clientAuth alone, TLS libraries refuse it
# before remote-cert-tls is checked), client certificates with RSA and
# ECDSA P-256 keys (EKU clientAuth), one from another CA, and the tls-auth
# and tls-crypt static keys (plus a tls-crypt key the server does not
# know). The client keys are also written as PKCS#8, next to the
# certificate's SHA-256: the interop client signs with them where the app
# uses the Keychain.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
[ -f "$here/pki/tls-crypt-other.key" ] && exit 0
rm -rf "$here/pki"
mkdir -p "$here/pki"
docker run --rm -v "$here/pki:/pki" -w /pki --entrypoint sh omnitun-interop-openvpn -c '
set -e
subj="/C=CH/O=omnitun interop"
ca() { # name, common name
    openssl req -x509 -newkey rsa:3072 -nodes -keyout "$1.key" -out "$1.pem" -days 3650 \
        -subj "$subj/CN=$2" -addext basicConstraints=critical,CA:true \
        -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
}
issue() { # name, common name, key type (rsa or p256), ca, extended key usage
    case $3 in
    rsa) newkey="-newkey rsa:2048" usage=digitalSignature,keyEncipherment ;;
    p256) newkey="-newkey ec -pkeyopt ec_paramgen_curve:P-256" usage=digitalSignature ;;
    esac
    openssl req -new $newkey -nodes -keyout "$1.key" -subj "$subj/CN=$2" -out "$1.csr" 2>/dev/null
    {
        echo basicConstraints=CA:false
        echo keyUsage=critical,$usage
        [ "$5" = none ] || echo extendedKeyUsage=$5
        case $2 in *.*) echo subjectAltName=DNS:$2 ;; esac
    } >"$1.ext"
    openssl x509 -req -in "$1.csr" -CA "$4.pem" -CAkey "$4.key" -CAcreateserial -days 1825 \
        -extfile "$1.ext" -out "$1.pem" 2>/dev/null
    rm "$1.csr" "$1.ext"
    openssl x509 -in "$1.pem" -outform der | openssl dgst -sha256 -r | cut -d" " -f1 >"$1.sha256"
}
ca ca "omnitun interop CA"
ca rogue-ca "someone else CA"
issue server server.omnitun.test rsa ca serverAuth
issue server-noeku server-noeku.omnitun.test p256 ca none
issue client-rsa client-rsa rsa ca clientAuth
issue client-p256 client-p256 p256 ca clientAuth
issue client-rogue client-rogue p256 rogue-ca clientAuth
for key in client-*.key; do
    openssl pkcs8 -topk8 -nocrypt -in "$key" -outform der -out "${key%.key}.p8"
done
openvpn --genkey tls-auth tls-auth.key
openvpn --genkey tls-crypt tls-crypt.key
openvpn --genkey tls-crypt tls-crypt-other.key
rm -f *.srl
chmod 644 *
'

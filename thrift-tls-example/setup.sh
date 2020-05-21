#!/usr/bin/env bash

PASSPHRASE="do not use"
KEYBITS=2048

set -euo pipefail

PREVDIR="$(pwd)"
BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

rm -rf "${BASEDIR}/x509" ${BASEDIR}/src/simple_service.rs

mkdir "${BASEDIR}/x509"
cd "${BASEDIR}/x509"
echo "Generating CA"
openssl genrsa -passout "pass:${PASSPHRASE}" -aes256 -out rootCA.key "${KEYBITS}"
openssl req -x509 -new -nodes -key rootCA.key -passin "pass:${PASSPHRASE}" -sha256 -days 1024 -out rootCA.crt \
    -subj "/CN=Do Not Trust This CA/C=UK/ST=England/L=London/O=None/emailAddress=davide.guerri@gmail.com/"
openssl x509 -in rootCA.crt -text -noout

echo "Generating server cert"
openssl genrsa -out server.key "${KEYBITS}"
openssl req \
    -subj "/CN=localhost/C=UK/ST=England/L=London/O=None/emailAddress=davide.guerri@gmail.com/" \
    -new -key server.key -out server.csr
openssl x509 \
    -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -passin "pass:${PASSPHRASE}" \
    -CAcreateserial -out server.crt -days 365 -sha256 \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=nonRepudiation,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost")
openssl x509 -in server.crt -text -noout
rm server.csr

echo "Generating client cert"
openssl genrsa -out client.key "${KEYBITS}"
openssl req \
    -subj "/CN=this is a client/C=UK/ST=England/L=London/O=None/emailAddress=davide.guerri@gmail.com/" \
    -new -key client.key -out client.csr
openssl x509 \
    -req -in client.csr -CA rootCA.crt -CAkey rootCA.key -passin "pass:${PASSPHRASE}" \
    -CAcreateserial -out client.crt -days 365 -sha256 \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=nonRepudiation,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:localhost")
openssl x509 -in client.crt -text -noout
rm client.csr

echo "Compiling thrift spec"
cd "${BASEDIR}"
thrift --out src --gen rs simple_service.thrift

cd "${PREVDIR}"

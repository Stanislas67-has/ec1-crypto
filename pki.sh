#!/usr/bin/env bash
# TP2 - Etapes 2 a 4 : racine, intermediaire, certificats serveur et client.
# Usage : ./pki.sh [dossier_de_travail]   (defaut : ./pki)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
WORK="${1:-$SRC/pki}"
rm -rf "$WORK" && mkdir -p "$WORK" && cp "$SRC/racine.cnf" "$SRC/inter.cnf" "$WORK/" && cd "$WORK"

for ca in racine inter; do
  mkdir -p "$ca/newcerts" "$ca/crl"
  : > "$ca/index.txt"; echo 1000 > "$ca/serial"; echo 1000 > "$ca/crlnumber"
done

echo "== AC racine (P-384, 10 ans) =="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
chmod 600 racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

echo "== AC intermediaire (P-256, 5 ans) =="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
chmod 600 inter/inter.key
openssl req -new -key inter/inter.key -subj "/C=BF/O=Universite TP/CN=Intermediaire TP" -out inter/inter.csr
openssl ca -batch -notext -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

# emettre <nom> <CN> <SAN> <section> <jours>
emettre() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"
  chmod 600 "$1.key"
  openssl req -new -key "$1.key" -subj "/CN=$2" -addext "subjectAltName=$3" -out "$1.csr"
  openssl ca -batch -notext -config inter.cnf -extensions "$4" -days "$5" -in "$1.csr" -out "$1.crt"
}

echo "== Certificats feuilles =="
emettre serveur www.tp.local "DNS:www.tp.local,DNS:tp.local" ext_serveur 90
emettre alice   alice@tp.local "email:alice@tp.local" ext_client 90
echo "OK : PKI creee dans $WORK"

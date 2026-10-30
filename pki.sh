#!/usr/bin/env bash
# TP2 - Etapes 1 a 4 : arborescence, racine, intermediaire, certificats serveur et client.
# Les fichiers racine.cnf et inter.cnf sont ceux de l'annexe B, non modifies.
# Usage : ./pki.sh [dossier_de_travail]   (defaut : ./pki)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
WORK="${1:-$SRC/pki}"
rm -rf "$WORK" && mkdir -p "$WORK" && cp "$SRC/racine.cnf" "$SRC/inter.cnf" "$WORK/" && cd "$WORK"

echo "== Etape 1 : arborescence (annexe B) =="
for ca in racine inter; do
  mkdir -p "$ca/certs" "$ca/crl" "$ca/newcerts"
  : > "$ca/index.txt"
  # Sans cela, openssl ca refuse d'emettre un 2e certificat de meme sujet
  # tant que le 1er est valide : indispensable pour le renouvellement (TP3).
  echo "unique_subject = no" > "$ca/index.txt.attr"
done
echo 1000 > racine/serial; echo 1000 > racine/crlnumber
echo 2000 > inter/serial;  echo 2000 > inter/crlnumber

echo "== Etape 2 : AC racine (P-384, 10 ans) =="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
chmod 600 racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

echo "== Etape 3 : AC intermediaire (P-256, 5 ans) =="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
chmod 600 inter/inter.key
openssl req -new -key inter/inter.key -subj "/C=BF/O=Universite TP/CN=Intermediaire TP" -out inter/inter.csr
openssl ca -batch -notext -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

# emettre <nom> <CN> <section> <jours> [SAN]
emettre() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"
  chmod 600 "$1.key"
  local san=(); [ -n "${5:-}" ] && san=(-addext "subjectAltName=$5")
  openssl req -new -key "$1.key" -subj "/CN=$2" "${san[@]}" -out "$1.csr"
  openssl ca -batch -notext -config inter.cnf -extensions "$3" -days "$4" -in "$1.csr" -out "$1.crt"
}

echo "== Etape 4 : certificats feuilles =="
emettre serveur www.tp.local  ext_serveur 90 "DNS:www.tp.local,DNS:tp.local"
emettre alice   alice@tp.local ext_client 90      # le SAN vient de ext_client
echo "OK : PKI creee dans $WORK"

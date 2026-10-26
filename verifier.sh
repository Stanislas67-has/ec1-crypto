#!/usr/bin/env bash
# TP2 - Etapes 5 et 6 : validations puis revocation d'Alice. A lancer apres pki.sh.
set -uo pipefail
cd "${1:-$(cd "$(dirname "$0")" && pwd)/pki}"
V="openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt"

echo "--- 1. serveur / www.tp.local (attendu : OK)";            $V -verify_hostname www.tp.local serveur.crt
echo "--- 2. serveur / autre.example (attendu : echec)";        $V -verify_hostname autre.example serveur.crt
echo "--- 3. alice / purpose sslclient (attendu : OK)";         $V -purpose sslclient alice.crt
echo "--- 4. serveur utilise comme client (attendu : echec)";   $V -purpose sslclient serveur.crt

echo "--- 5. certificat pour www.example.com (hors contrainte de nom)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out example.key
openssl req -new -key example.key -subj "/CN=www.example.com" -addext "subjectAltName=DNS:www.example.com" -out example.csr
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days 90 -in example.csr -out example.crt 2>&1 | tail -1
echo "(l'AC a signe) ; validation (attendu : permitted subtree violation) :"
$V example.crt

echo "--- 6. revocation d'Alice (cle compromise)"
openssl ca -config inter.cnf -revoke alice.crt -crl_reason keyCompromise
openssl ca -config inter.cnf   -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf  -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
echo "--- alice apres revocation (attendu : revoked)"
$V -crl_check_all -CRLfile crls.pem alice.crt
echo "--- serveur avec controle CRL (attendu : OK)"
$V -crl_check_all -CRLfile crls.pem serveur.crt
openssl crl -in inter/crl/inter.crl -noout -text | head -20

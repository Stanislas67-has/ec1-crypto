#!/usr/bin/env bash
# TP3 - Etapes 3 et 4 : observer la poignee de main et verifier la configuration.
# A lancer apres preparer.sh et le rechargement de nginx. Ne teste que le serveur de laboratoire.
set -uo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
cd "${PKI_DIR:-$SRC/../tp2/pki}"
S="openssl s_client -connect www.tp.local:443 -servername www.tp.local -CAfile racine/racine.crt"

echo "### 1. Client valide (Bob), TLS negocie"
$S -verify_hostname www.tp.local -cert bob.crt -key bob.key -cert_chain inter/inter.crt -brief </dev/null 2>&1 \
  | grep -E "Protocol version|Ciphersuite|Peer certificate|Verification|Server Temp Key"
echo; echo "### 2. curl avec le certificat de Bob (chaine complete)"
curl -sS --cacert racine/racine.crt --cert bob_chaine.crt --key bob.key https://www.tp.local/
echo; echo "### 3. Sans certificat client : refuse"
curl -sS --cacert racine/racine.crt https://www.tp.local/ | grep -E "<title>"
echo; echo "### 4. Certificat revoque (Alice) : refuse"
cat alice.crt inter/inter.crt > alice_chaine.crt
curl -sS --cacert racine/racine.crt --cert alice_chaine.crt --key alice.key https://www.tp.local/ | grep -E "<title>"
echo; echo "### 5. TLS 1.1 doit etre refuse"
openssl s_client -connect www.tp.local:443 -tls1_1 -brief </dev/null 2>&1 | head -2
echo; echo "### 6. TLS 1.2 force (suite et groupe)"
$S -tls1_2 -cert bob_chaine.crt -key bob.key -brief </dev/null 2>&1 | grep -E "Protocol version|Ciphersuite"
echo; echo "### 7. En-tete HSTS"
curl -sSI --cacert racine/racine.crt --cert bob_chaine.crt --key bob.key https://www.tp.local/ | grep -i -E "^HTTP|strict"
if command -v nmap >/dev/null; then
  echo; echo "### 8. Suites acceptees (nmap)"
  nmap --script ssl-enum-ciphers -p 443 www.tp.local | sed -n '/ssl-enum/,/least strength/p'
fi

#!/usr/bin/env bash
# TP3 - Etape 1 : preparer les fichiers, emettre le certificat client de Bob,
# installer la configuration nginx. A lancer apres tp2/pki.sh et tp2/verifier.sh.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
PKI="${PKI_DIR:-$SRC/../tp2/pki}"
TLS_DIR="${TLS_DIR:-/etc/nginx/tls}"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

cd "$PKI"
if [ ! -f bob.crt ]; then
  echo "== Certificat client de Bob =="
  # ext_client (annexe B) impose subjectAltName = email:alice@tp.local : on ne peut
  # donc pas l'utiliser pour Bob. On garde inter.cnf intact et on fournit une
  # section equivalente, avec le bon SAN, par -extfile.
  cat > bob_ext.cnf << 'EXT'
[ ext_bob ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = email:bob@tp.local
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EXT
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out bob.key
  chmod 600 bob.key
  openssl req -new -key bob.key -subj "/CN=bob@tp.local" -out bob.csr
  openssl ca -batch -notext -config inter.cnf -extfile bob_ext.cnf -extensions ext_bob \
    -days 90 -in bob.csr -out bob.crt
fi
# chaines : le serveur envoie serveur+inter ; le client envoie bob+inter
cat serveur.crt inter/inter.crt > serveur_chaine.crt
cat bob.crt     inter/inter.crt > bob_chaine.crt

echo "== Installation dans $TLS_DIR =="
$SUDO mkdir -p "$TLS_DIR"
$SUDO install -m 600 serveur.key "$TLS_DIR/serveur.key"
$SUDO install -m 644 serveur_chaine.crt racine/racine.crt crls.pem "$TLS_DIR/"
$SUDO install -m 644 "$SRC/www.tp.local.conf" /etc/nginx/conf.d/www.tp.local.conf
grep -q "www.tp.local" /etc/hosts || echo "127.0.0.1 www.tp.local" | $SUDO tee -a /etc/hosts >/dev/null
$SUDO nginx -t
echo "OK. Recharger nginx : sudo systemctl reload nginx"

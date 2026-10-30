#!/usr/bin/env bash
# Regenere les CRL (a planifier : la CRL de l'intermediaire expire au bout de 7 jours !)
# Sans CRL valide, nginx (ssl_crl) refuse TOUS les clients.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
PKI_DIR="${PKI_DIR:-$SRC/../tp2/pki}"
TLS_DIR="${TLS_DIR:-/etc/nginx/tls}"
NGINX_RELOAD="${NGINX_RELOAD:-systemctl reload nginx}"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
cd "$PKI_DIR"
openssl ca -config inter.cnf  -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl   # en vrai : racine hors ligne
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
$SUDO install -m 644 crls.pem "$TLS_DIR/crls.pem"
$SUDO $NGINX_RELOAD
echo "CRL mises a jour."

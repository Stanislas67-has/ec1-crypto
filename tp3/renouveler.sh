#!/usr/bin/env bash
# TP3 - Etape 6 : renouvellement automatique du certificat du serveur.
# Ne renouvelle que si le certificat expire dans moins de SEUIL_JOURS jours (defaut 30).
#
# Variables (toutes facultatives) :
#   PKI_DIR       dossier de la PKI du TP2 (contient inter.cnf, inter/, racine/)
#   TLS_DIR       dossier de nginx             (defaut /etc/nginx/tls)
#   SEUIL_JOURS   seuil de renouvellement      (defaut 30)
#   FORCE=1       renouveler meme si le certificat est encore valable longtemps
#   NGINX_TEST / NGINX_RELOAD   commandes (defaut : nginx -t / systemctl reload nginx)
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
PKI_DIR="${PKI_DIR:-$SRC/../tp2/pki}"
TLS_DIR="${TLS_DIR:-/etc/nginx/tls}"
SEUIL_JOURS="${SEUIL_JOURS:-30}"
FORCE="${FORCE:-0}"
NGINX_TEST="${NGINX_TEST:-nginx -t}"
NGINX_RELOAD="${NGINX_RELOAD:-systemctl reload nginx}"
NOM="www.tp.local"
SAN="DNS:www.tp.local,DNS:tp.local"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
log() { echo "$(date '+%F %T') [renouveler] $*"; }

# 0. Faut-il renouveler ?
if [ "$FORCE" != "1" ] && openssl x509 -in "$TLS_DIR/serveur_chaine.crt" -noout \
     -checkend $((SEUIL_JOURS * 86400)) >/dev/null 2>&1; then
  log "certificat valable encore plus de $SEUIL_JOURS jours : rien a faire."
  exit 0
fi
log "renouvellement necessaire (seuil : $SEUIL_JOURS jours)."

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$PKI_DIR"

# 1. Nouvelle cle et nouvelle demande (nouvelle cle a chaque renouvellement)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP/serveur.key"
openssl req -new -key "$TMP/serveur.key" -subj "/CN=$NOM" \
  -addext "subjectAltName=$SAN" -out "$TMP/serveur.csr"

# 2. Signature par l'intermediaire
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days 90 \
  -in "$TMP/serveur.csr" -out "$TMP/serveur.crt" 2>/dev/null
cat "$TMP/serveur.crt" inter/inter.crt > "$TMP/serveur_chaine.crt"

# 3. Verification AVANT tout deploiement
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslserver -verify_hostname "$NOM" "$TMP/serveur.crt" >/dev/null \
  || { log "ECHEC : la chaine du nouveau certificat est invalide. Rien n'a ete deploye."; exit 1; }
[ "$(openssl x509 -in "$TMP/serveur.crt" -noout -pubkey)" = \
  "$(openssl pkey -in "$TMP/serveur.key" -pubout)" ] \
  || { log "ECHEC : la cle ne correspond pas au certificat. Rien n'a ete deploye."; exit 1; }
log "nouveau certificat verifie."

# 4. Sauvegarde de l'ancien, installation, test et rechargement
SAUVE="$TLS_DIR/sauvegarde/$(date +%Y%m%d-%H%M%S)-$$"
$SUDO mkdir -p "$SAUVE"
$SUDO cp -p "$TLS_DIR/serveur.key" "$TLS_DIR/serveur_chaine.crt" "$SAUVE/"
log "ancien certificat conserve dans $SAUVE"

revenir() {
  log "retour en arriere depuis $SAUVE"
  $SUDO install -m 600 "$SAUVE/serveur.key" "$TLS_DIR/serveur.key"
  $SUDO install -m 644 "$SAUVE/serveur_chaine.crt" "$TLS_DIR/serveur_chaine.crt"
  $SUDO $NGINX_RELOAD || true
}

$SUDO install -m 600 "$TMP/serveur.key" "$TLS_DIR/serveur.key"
$SUDO install -m 644 "$TMP/serveur_chaine.crt" "$TLS_DIR/serveur_chaine.crt"
if ! $SUDO $NGINX_TEST; then
  log "ECHEC : configuration nginx invalide."; revenir; exit 1
fi
if ! $SUDO $NGINX_RELOAD; then
  log "ECHEC : rechargement impossible."; revenir; exit 1
fi
log "OK : certificat renouvele et nginx recharge sans interruption."

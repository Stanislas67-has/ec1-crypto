# TP 3 – Déployer un canal sécurisé et gérer les certificats

> Les sorties ci-dessous viennent de mon environnement de test (nginx 1.24, OpenSSL 3.0.13).
> Refaire les commandes sur votre machine et joindre vos propres captures (Wireshark inclus).

## Adaptation à l'annexe B du TP 2
La PKI utilise les fichiers de configuration officiels, non modifiés. Deux conséquences pour ce TP :
- **Certificat de Bob.** La section `ext_client` impose `subjectAltName = email:alice@tp.local`. Utilisée pour Bob, elle lui donnerait l'identité d'Alice. `preparer.sh` émet donc Bob avec une section équivalente (`ext_bob`, SAN `bob@tp.local`) fournie par `-extfile`, sans toucher à `inter.cnf`.
- **Renouvellement.** Il émet un nouveau certificat de même sujet (`CN=www.tp.local`) alors que l'ancien est encore valide. Cela n'est possible que grâce à `unique_subject = no` dans `inter/index.txt.attr`, créé par `pki.sh` (TP 2).

## Étape 2 – Justification de la configuration nginx
| Directive | Rôle |
|---|---|
| `listen 443 ssl` / `server_name` | Écoute HTTPS ; sélectionne ce serveur pour `www.tp.local` (SNI). |
| `ssl_certificate` (serveur_chaine.crt) | Certificat du serveur **suivi de l'intermédiaire** : le client n'a pas l'intermédiaire. |
| `ssl_certificate_key` | Clé privée, fichier en mode 600. |
| `ssl_protocols TLSv1.2 TLSv1.3` | Interdit SSLv3, TLS 1.0 et 1.1 (obsolètes, attaques connues). |
| `ssl_ciphers ECDHE-ECDSA-…GCM/CHACHA20` | **Ajout par rapport au sujet.** Seulement ECDHE (confidentialité persistante) et AEAD. Avec un certificat ECDSA, aucune suite RSA statique n'est de toute façon utilisable. |
| `ssl_prefer_server_ciphers off` | Toutes les suites autorisées sont sûres ; le client choisit celle qui convient à son matériel (ChaCha20 sur mobile, AES sinon). |
| `ssl_session_tickets off` | Évite qu'une clé de ticket de longue durée annule la confidentialité persistante (question 2). |
| `ssl_client_certificate` (racine.crt) | Ancre de confiance pour valider les certificats **clients**. |
| `ssl_verify_client on` | Le client **doit** présenter un certificat valide (mTLS). |
| `ssl_verify_depth 2` | Chaîne client → intermédiaire → racine : profondeur 2. Avec la valeur par défaut (1), la chaîne serait rejetée. |
| `ssl_crl` (crls.pem) | Rejette les certificats révoqués. Il faut la CRL de **chaque** niveau (intermédiaire et racine). |
| `add_header Strict-Transport-Security … always` | HSTS ; `always` l'ajoute aussi sur les réponses d'erreur. |
| `return 200 "Bonjour $ssl_client_s_dn"` | Prouve que l'identité du client vérifiée par le certificat est connue de nginx. |

## Étape 3 – Poignée de main (voir `sortie_tests.txt`)
| Relevé | Valeur |
|---|---|
| Version de TLS | TLS 1.3 |
| Suite de chiffrement | `TLS_AES_256_GCM_SHA384` |
| Groupe d'échange de clés | X25519 (253 bits) |
| Vérification du serveur | `Verification: OK`, nom vérifié `www.tp.local` |
| TLS 1.2 forcé | `ECDHE-ECDSA-AES256-GCM-SHA384` |
| Réponse de nginx | `Bonjour CN=bob@tp.local` |

**Trois constats pratiques :**
1. **Sans certificat client**, la poignée de main TLS 1.3 aboutit, puis nginx répond `400 No required SSL certificate was sent`. Le refus se fait au niveau HTTP, pas par une alerte TLS.
2. **Avec le certificat révoqué d'Alice**, nginx répond `400 The SSL certificate error`. La cause est la CRL : `openssl verify -crl_check_all` donne `certificate revoked` (TP 2).
3. **Piège avec curl.** La commande `curl --cert bob.crt` du sujet échoue (400) car curl n'envoie que le certificat de Bob, sans l'intermédiaire, et nginx ne peut pas construire la chaîne jusqu'à la racine. Il faut `--cert bob_chaine.crt` (Bob + intermédiaire). Avec `openssl s_client`, l'option `-cert_chain` fait ce travail.

### Capture Wireshark (à faire chez vous)
1. Capturer sur l'interface `lo` (loopback), filtre `tcp.port == 443`.
2. Relancer `curl` (ou `openssl s_client`). Filtre d'affichage : `tls.handshake.type == 1 || tls.handshake.type == 2`.
3. **ClientHello** : versions et suites proposées, extension `supported_versions` (TLS 1.3), `key_share` (X25519), SNI `www.tp.local`.
4. **ServerHello** : suite choisie et `key_share` du serveur.
5. **Pourquoi le certificat du serveur n'est pas visible en TLS 1.3 :** dès le ServerHello, client et serveur ont calculé un secret commun (ECDHE) ; tous les messages suivants (EncryptedExtensions, **Certificate**, CertificateVerify, Finished) sont chiffrés avec les clés de poignée de main. Un observateur voit seulement des « Application Data ». Le certificat du client est protégé de la même manière. En TLS 1.2, le message Certificate (`tls.handshake.type == 11`) est en clair ; on le voit avec `openssl s_client -tls1_2`.

## Étape 4 – Vérification de la configuration
- **TLS 1.1** : `openssl s_client -tls1_1` échoue (« no protocols available »). Sur ma machine, c'est le client OpenSSL 3 qui refuse aussi ce protocole ; la preuve côté serveur est le résultat de nmap, qui ne liste **que** TLS 1.2 et TLS 1.3.
- **nmap** : en TLS 1.2, uniquement trois suites ECDHE-ECDSA avec GCM ou ChaCha20, toutes notées A ; en TLS 1.3, les trois suites standard. Aucune suite sans confidentialité persistante ni sans chiffrement authentifié.

## Étape 5 – Supervision
`surveiller.py DOSSIER` affiche pour chaque certificat les jours restants et un niveau OK / ALERTE (< 30 j) / CRITIQUE (< 7 j). Code de sortie 0, 1 ou 2 (le pire niveau rencontré ; un certificat expiré compte comme CRITIQUE). Il ignore les fichiers qui ne sont pas des certificats (comme `crls.pem`). Résultats : `sortie_surveiller.txt`.

| Test | Code de sortie |
|---|---|
| certificats de 90 jours, 5 ans, 10 ans | 0 |
| un certificat de 20 jours | 1 |
| un certificat émis pour 5 jours | 2 (affiché « 4 jours » : le calcul arrondit à l'entier inférieur, c'est volontairement prudent) |

Tests automatiques : `pytest test_surveiller.py` (5 tests).

## Étape 6 – Renouvellement
`renouveler.sh` : (0) ne fait rien si le certificat vaut encore plus de 30 jours ; (1) nouvelle clé et nouvelle CSR ; (2) signature par l'intermédiaire ; (3) `openssl verify` de la chaîne **et** contrôle que la clé correspond au certificat, avant tout déploiement ; (4) sauvegarde de l'ancien certificat dans `sauvegarde/DATE-PID/`, installation, `nginx -t`, rechargement (`reload` : les connexions en cours ne sont pas coupées) ; en cas d'échec de `nginx -t` ou du rechargement, **retour en arrière automatique**.

Tests réalisés : certificat valable → « rien à faire » ; seuil à 100 jours → renouvelé (numéro de série 1000 → 1006) et nginx sert le nouveau certificat ; échec simulé de `nginx -t` → retour en arrière, le site continue de fonctionner.

Planification, deux options :
```bash
# cron (tous les jours à 3 h)
0 3 * * * PKI_DIR=/opt/tp-pki /opt/tp3/renouveler.sh >> /var/log/renouveler.log 2>&1
# ou minuteur systemd
sudo cp renouveler.service renouveler.timer /etc/systemd/system/
sudo systemctl enable --now renouveler.timer
```
**Attention, la CRL de l'intermédiaire expire au bout de 7 jours** (`default_crl_days = 7` dans `inter.cnf`). Passé ce délai, nginx rejette **tous** les clients. `maj_crl.sh` la régénère ; à planifier chaque jour comme le renouvellement.

## Questions de réflexion
1. **Racine non envoyée.** Le client la possède déjà dans son magasin de confiance : c'est ce qui la rend « de confiance ». La renvoyer alourdit la poignée de main pour rien, et un client ne peut de toute façon pas se fier à une racine fournie par le serveur lui-même. L'intermédiaire, lui, doit être envoyé car le client ne le connaît pas.
2. **Tickets de session.** Les tickets sont chiffrés avec une clé du serveur. Si cette clé n'est pas renouvelée, quiconque la vole (ou la récupère plus tard) peut déchiffrer des sessions enregistrées auparavant, ce qui **annule la confidentialité persistante**. Sans tickets, chaque session repose uniquement sur des clés éphémères.
3. **HSTS.** Il ordonne au navigateur de n'utiliser que HTTPS pour ce site pendant `max-age` secondes (ici un an). Il protège contre le **SSL stripping** et les rétrogradations vers HTTP par un attaquant sur le réseau. Limite : il n'agit qu'après une première visite en HTTPS (sauf liste de préchargement).
4. **Certificats de 100 puis 47 jours.** Un renouvellement manuel devient ingérable : plusieurs renouvellements par an et par certificat, avec un risque d'oubli, donc de panne par expiration. Il faut automatiser (ACME, scripts comme `renouveler.sh`), superviser les expirations (`surveiller.py`) et connaître son inventaire de certificats.
5. **Chaîne incomplète.** Certains clients (navigateurs, Windows) récupèrent l'intermédiaire manquant grâce à l'extension AIA du certificat ou à un cache d'intermédiaires déjà vus. D'autres (curl, OpenSSL, Java, applications mobiles, scripts) ne le font pas et refusent la connexion. Le site « marche dans mon navigateur » mais échoue pour les API. Il faut toujours envoyer la chaîne complète.
6. **Fuite de la clé privée du serveur.**
   1. Déclarer l'incident et isoler : considérer le certificat comme compromis.
   2. Générer une **nouvelle** clé et une nouvelle CSR (ne jamais réutiliser la clé).
   3. Émettre le nouveau certificat et le déployer (`renouveler.sh` avec `FORCE=1`).
   4. **Révoquer** l'ancien (`openssl ca -revoke … -crl_reason keyCompromise`), régénérer et publier les CRL (`maj_crl.sh`).
   5. Redémarrer nginx pour invalider les clés de tickets et les sessions.
   6. Enquêter sur la cause de la fuite (accès, sauvegardes, dépôt de code), consulter les journaux depuis la date possible de fuite.
   7. Prévenir les personnes concernées et rédiger un retour d'expérience.
   Le trafic passé reste protégé grâce à ECDHE (confidentialité persistante), mais jusqu'à la révocation un attaquant peut se faire passer pour le serveur.

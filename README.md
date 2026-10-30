# EC1 – Ingénierie de la cryptographie (TP 2026–2027)

| TP | Contenu | Dossier |
|----|---------|---------|
| 1 | Chiffrement authentifié (AES-GCM), Argon2id, HKDF – mini-coffre | `tp1/` |
| 2 | Infrastructure de gestion de clés avec OpenSSL | `tp2/` |
| 3 | TLS/mTLS avec nginx, supervision, renouvellement | `tp3/` |

Aucune clé privée n'est versionnée (voir `.gitignore`).

## Lancer les tests du TP 1
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install cryptography argon2-cffi pytest
cd tp1 && pytest -v
```

## Réponses aux questions du tp1
1.Le sel n'est pas secret : son rôle est d'être unique par fichier pour
   que deux fichiers (ou deux utilisateurs) ayant le même mot de passe aient des clés
   différentes, et pour rendre inutiles les tables précalculées. L'attaquant doit toujours
   deviner le mot de passe, avec le coût d'Argon2id, pour chaque fichier. Le publier ne
   l'affaiblit donc pas. <br>
   
2. La clé AES-GCM est dérivée d'un sel neuf : chaque fichier a sa propre
   clé, et la clé n'est utilisée qu'une seule fois. Le risque de collision de nonce ne
   concerne que des chiffrements faits avec la même clé ; ici il n'y en a qu'un par clé. <br>
   
3. Un attaquant pourrait renommer/échanger des fichiers
   sans détection. Exemple : `paie_2026.csv` et `brouillon.txt` ont le même mot de passe ; en
   échangeant leurs noms, l'utilisateur ouvre le mauvais contenu en croyant qu'il est authentique. <br>
   
4. Sinon l'attaquant pourrait modifier t, m, p : par exemple m très
   grand (déni de service mémoire) ou t=1, m minimal pour affaiblir la dérivation côté
   utilisateur, ou changer le sel/nonce. L'authentification rend toute modification détectable.
   (On borne aussi les paramètres avant de lancer Argon2, car ils sont lus *avant* la
   vérification de l'étiquette.) <br>
   
5. Distinguer « mauvais mot de passe » / « fichier corrompu » /
   « mauvais nom » fournit un oracle à l'attaquant (ex. confirmer un mot de passe correct,
   apprendre ce qui a été modifié). On affiche donc un message générique.

   ## Réponses aux questions du tp2
1. Elle signe très rarement (l'intermédiaire, ses propres CRL) ; sans connexion, sa clé ne peut pas être volée à distance, or tout repose sur elle. *Intermédiaire compromis* : le révoquer par la CRL de la racine, en créer un nouveau, réémettre les certificats finaux. *Racine compromise* : toute l'infrastructure est à refaire et la nouvelle ancre doit être redistribuée à tous les clients : c'est le pire scénario.<br>

2. Il interdit à l'intermédiaire de créer d'autres AC. Sans lui, l'intermédiaire (ou un attaquant qui le contrôle) pourrait créer des sous-AC non prévues, multipliant les détenteurs d'un pouvoir d'émission et rendant révocation et audit beaucoup plus difficiles.<br>

3. La clé privée ne quitte jamais la machine qui l'utilise : elle ne transite pas et l'AC n'en conserve aucune copie à protéger ou à se faire voler. L'AC ne reçoit que la CSR, qui contient la clé publique.<br>

4. Les clients modernes vérifient le **SAN** ; le CN est ignoré dès qu'un SAN existe (RFC 6125, navigateurs depuis Chrome 58). Le CN reste pour la lisibilité.<br>

5. Taille croissante, délai de publication (le client peut utiliser une CRL périmée), téléchargement coûteux, contrôle souvent « soft-fail ». *OCSP* : état en temps réel d'un seul certificat, mais il faut un répondeur disponible et il révèle les sites visités (atténué par l'OCSP stapling). *Certificats très courts* : le certificat expire de lui-même en quelques jours, ce qui réduit le besoin de révocation, à condition d'automatiser le renouvellement.<br>

6. **Politique de certification minimale.**
   1. Seuls les administrateurs du domaine `tp.local` peuvent demander un certificat serveur.
   2. Les certificats clients sont demandés par les membres de l'université, via leur compte.
   3. L'identité est vérifiée avant émission (compte institutionnel authentifié, contrôle effectif du nom de domaine).
   4. Le demandeur génère sa clé ; seule la CSR est transmise.
   5. Les certificats serveur et client durent 90 jours maximum.
   6. L'AC intermédiaire dure 5 ans, la racine 10 ans, et la racine est hors ligne.
   7. Les noms émis sont limités à `tp.local` par contrainte de nom.
   8. Toute compromission de clé est signalée immédiatement ; le certificat est révoqué.
   9. Les CRL sont publiées au plus tard 24 h après une révocation et renouvelées tous les 7 jours.
   10. Émissions et révocations sont journalisées (`index.txt`) et auditées.
  
## Réponses aux questions du tp3
| Fichier | Rôle |
|---|---|
| `www.tp.local.conf` | Configuration nginx (TLS 1.2/1.3, mTLS, CRL, HSTS) |
| `preparer.sh` | Étape 1 : certificat de Bob, chaînes, installation dans nginx |
| `tests_tls.sh` | Étapes 3 et 4 : poignée de main, TLS 1.1 refusé, nmap |
| `surveiller.py`, `test_surveiller.py` | Étape 5 : supervision des expirations (codes 0/1/2) |
| `renouveler.sh`, `renouveler.service`, `renouveler.timer` | Étape 6 : renouvellement automatique |
| `maj_crl.sh` | Régénération planifiée des CRL |
| `COMPTE_RENDU.md` | Justifications, observations, réponses aux questions |
| `sortie_tests.txt`, `sortie_surveiller.txt` | Résultats réels des tests |

Ordre d'exécution (après `tp2/pki.sh` et `tp2/verifier.sh`) :
```bash
./preparer.sh && sudo systemctl reload nginx
./tests_tls.sh
python3 surveiller.py ../tp2/pki
./renouveler.sh
```

1.Le client la possède déjà dans son magasin de confiance : c'est ce qui la rend « de confiance ». La renvoyer alourdit la poignée de main pour rien, et un client ne peut de toute façon pas se fier à une racine fournie par le serveur lui-même. L'intermédiaire, lui, doit être envoyé car le client ne le connaît pas.<br>

2.Les tickets sont chiffrés avec une clé du serveur. Si cette clé n'est pas renouvelée, quiconque la vole (ou la récupère plus tard) peut déchiffrer des sessions enregistrées auparavant, ce qui annule la confidentialité persistante. Sans tickets, chaque session repose uniquement sur des clés éphémères.<br>

3. HSTS ordonne au navigateur de n'utiliser que HTTPS pour ce site pendant `max-age` secondes (ici un an). Il protège contre le SSL stripping et les rétrogradations vers HTTP par un attaquant sur le réseau. Limite : il n'agit qu'après une première visite en HTTPS (sauf liste de préchargement).<br>

4.Un renouvellement manuel devient ingérable : plusieurs renouvellements par an et par certificat, avec un risque d'oubli, donc de panne par expiration. Il faut automatiser (ACME, scripts comme `renouveler.sh`), superviser les expirations (`surveiller.py`) et connaître son inventaire de certificats.<br>

5.Certains clients (navigateurs, Windows) récupèrent l'intermédiaire manquant grâce à l'extension AIA du certificat ou à un cache d'intermédiaires déjà vus. D'autres (curl, OpenSSL, Java, applications mobiles, scripts) ne le font pas et refusent la connexion. Le site « marche dans mon navigateur » mais échoue pour les API. Il faut toujours envoyer la chaîne complète.<br>

6. **Fuite de la clé privée du serveur.**
   1. Déclarer l'incident et isoler : considérer le certificat comme compromis.
   2. Générer une nouvelle clé et une nouvelle CSR (ne jamais réutiliser la clé).
   3. Émettre le nouveau certificat et le déployer (`renouveler.sh` avec `FORCE=1`).
   4. Révoquer l'ancien (`openssl ca -revoke … -crl_reason keyCompromise`), régénérer et publier les CRL (`maj_crl.sh`).
   5. Redémarrer nginx pour invalider les clés de tickets et les sessions.
   6. Enquêter sur la cause de la fuite (accès, sauvegardes, dépôt de code), consulter les journaux depuis la date possible de fuite.
   7. Prévenir les personnes concernées et rédiger un retour d'expérience.
   Le trafic passé reste protégé grâce à ECDHE (confidentialité persistante), mais jusqu'à la révocation un attaquant peut se faire passer pour le serveur.

# EC1 – Ingénierie de la cryptographie (TP 2026–2027)

| TP | Contenu | Dossier |
|----|---------|---------|
| 1 | Chiffrement authentifié (AES-GCM), Argon2id, HKDF – mini-coffre | `tp1/` |
| 2 | Infrastructure de gestion de clés avec OpenSSL | `tp2/` |
| 3 | TLS/mTLS avec nginx, supervision, renouvellement | `tp3/` |

Aucune clé privée n'est versionnée (voir `.gitignore`).

## Lancer les tests du TP 1
    python3 -m venv .venv && source .venv/bin/activate
    pip install cryptography argon2-cffi pytest
    cd tp1 && pytest -v 
## Réponses aux questions du tp1
1-Le sel n'est pas secret : son rôle est d'être unique par fichier pour que deux fichiers (ou deux utilisateurs) ayant le même mot de passe aient des clés différentes, et pour rendre inutiles les tables précalculées. L'attaquant doit toujours deviner le mot de passe, avec le coût d'Argon2id, pour chaque fichier. Le publier ne l'affaiblit donc pas.

2-Nonce de 96 bits. La clé AES-GCM est dérivée d'un sel neuf : chaque fichier a sa propre clé, et la clé n'est utilisée qu'une seule fois. Le risque de collision de nonce ne concerne que des chiffrements faits avec la même clé ; ici il n'y en a qu'un par clé.

3-Nom hors des données associées. Un attaquant pourrait renommer/échanger des fichiers sans détection. Exemple : paie_2026.csv et brouillon.txt ont le même mot de passe ; en échangeant leurs noms, l'utilisateur ouvre le mauvais contenu en croyant qu'il est authentique.

4-En-tête authentifié. Sinon l'attaquant pourrait modifier t, m, p : par exemple m très grand (déni de service mémoire) ou t=1, m minimal pour affaiblir la dérivation côté utilisateur, ou changer le sel/nonce. L'authentification rend toute modification détectable. (On borne aussi les paramètres avant de lancer Argon2, car ils sont lus avant la vérification de l'étiquette.)

5-Message d'erreur unique. Distinguer « mauvais mot de passe » / « fichier corrompu » / « mauvais nom » fournit un oracle à l'attaquant (ex. confirmer un mot de passe correct, apprendre ce qui a été modifié). On affiche donc un message générique.

## Réponses aux questions du tp2
1-Racine hors ligne. Elle signe très rarement (une fois l'intermédiaire, puis les CRL), donc elle n'a pas besoin d'être connectée : une clé hors ligne ne peut pas être volée à distance. Elle est la confiance de tout l'ensemble. Intermédiaire compromis : le révoquer via la CRL de la racine, en créer un nouveau, réémettre les certificats feuilles, publier la nouvelle CRL. Racine compromise : toute l'infrastructure est à refaire, et la nouvelle ancre de confiance doit être redistribuée à tous les clients ; c'est le pire scénario.

2-pathlen:0. Il interdit à l'intermédiaire de créer d'autres AC. Sans lui, l'intermédiaire (ou un attaquant qui le contrôle) pourrait créer des sous-AC non prévues, ce qui multiplie les détenteurs de pouvoir d'émission et rend la révocation et l'audit beaucoup plus difficiles.

3-Clé privée générée par le demandeur. La clé privée ne quitte jamais la machine qui l'utilise : elle ne transite pas, l'AC n'en garde pas de copie et ne peut pas se faire voler celles des autres. L'AC ne reçoit que la CSR, qui contient la clé publique.

4-CN ou SAN. Les clients modernes vérifient le SAN. Le CN est ignoré s'il y a un SAN (RFC 6125 ; navigateurs depuis Chrome 58). On met le CN pour la lisibilité.

5-Limites des CRL. Taille qui grossit, délai de publication (le client peut utiliser une CRL périmée), téléchargement coûteux, vérification souvent « soft-fail ». OCSP : état en temps réel pour un seul certificat, mais requiert un serveur disponible, révèle au répondeur les sites visités (atténué par l'OCSP stapling). Certificats très courts : le certificat expire de lui-même en quelques jours, ce qui réduit le besoin de révocation, à condition d'automatiser le renouvellement.

6-Politique de certification minimale.
    *Seuls les administrateurs du domaine tp.local peuvent demander un certificat serveur.
    *Les demandes de client sont faites par les utilisateurs de l'université, via leur compte.
    *L'identité est vérifiée avant émission (compte institutionnel authentifié, ou contrôle effectif du nom de domaine demandé).
    *Le demandeur génère sa clé ; seule la CSR est transmise.
    *Les certificats serveur et client durent 90 jours maximum.
    *L'AC intermédiaire dure 5 ans, la racine 10 ans, et la racine est hors ligne.
    *Les noms émis sont limités à tp.local par contrainte de nom.
    *Toute compromission de clé est signalée immédiatement ; le certificat est révoqué.
    *Les CRL sont publiées au plus tard 24 h après une révocation et renouvelées tous les 7 jours.
    *Les émissions et révocations sont journalisées (registre index.txt) et auditées.



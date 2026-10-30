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


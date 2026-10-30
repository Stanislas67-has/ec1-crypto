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

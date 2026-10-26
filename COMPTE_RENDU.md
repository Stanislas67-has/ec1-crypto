# TP 1 – Chiffrement authentifié et dérivation de clés

## Étape 1 – Réglage d'Argon2id
Mesures (voir `bench.py`) : t=3, m=128 Mio, p=4 donne environ 0,7 s sur ma machine ;
t=4, m=128 Mio environ 0,6 s. Valeurs par défaut du module : **t=3, m=64 Mio, p=4**
(à ajuster selon la machine pour viser ~0,5 s). *(Remplacer par vos propres mesures.)*

## Étape 4 – Évolution
Les paramètres (t, m, p) et le sel sont écrits dans l'en-tête de chaque fichier, et
l'identifiant `CFR1` versionne le format. Au déchiffrement on relit les paramètres du
fichier : un ancien fichier reste lisible même si les valeurs par défaut ont augmenté.
`rechiffrer()` déchiffre avec l'ancien mot de passe puis rechiffre avec le nouveau mot de
passe, des paramètres actuels, un sel et un nonce neufs.

## Questions de réflexion
1. **Sel en clair.** Le sel n'est pas secret : son rôle est d'être unique par fichier pour
   que deux fichiers (ou deux utilisateurs) ayant le même mot de passe aient des clés
   différentes, et pour rendre inutiles les tables précalculées. L'attaquant doit toujours
   deviner le mot de passe, avec le coût d'Argon2id, pour chaque fichier. Le publier ne
   l'affaiblit donc pas.
2. **Nonce de 96 bits.** La clé AES-GCM est dérivée d'un sel neuf : chaque fichier a sa propre
   clé, et la clé n'est utilisée qu'**une seule fois**. Le risque de collision de nonce ne
   concerne que des chiffrements faits avec la *même* clé ; ici il n'y en a qu'un par clé.
3. **Nom hors des données associées.** Un attaquant pourrait renommer/échanger des fichiers
   sans détection. Exemple : `paie_2026.csv` et `brouillon.txt` ont le même mot de passe ; en
   échangeant leurs noms, l'utilisateur ouvre le mauvais contenu en croyant qu'il est authentique.
4. **En-tête authentifié.** Sinon l'attaquant pourrait modifier t, m, p : par exemple m très
   grand (déni de service mémoire) ou t=1, m minimal pour affaiblir la dérivation côté
   utilisateur, ou changer le sel/nonce. L'authentification rend toute modification détectable.
   (On borne aussi les paramètres avant de lancer Argon2, car ils sont lus *avant* la
   vérification de l'étiquette.)
5. **Message d'erreur unique.** Distinguer « mauvais mot de passe » / « fichier corrompu » /
   « mauvais nom » fournit un oracle à l'attaquant (ex. confirmer un mot de passe correct,
   apprendre ce qui a été modifié). On affiche donc un message générique.

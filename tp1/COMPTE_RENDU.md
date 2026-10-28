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

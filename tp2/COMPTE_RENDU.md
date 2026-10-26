# TP 2 – Infrastructure de gestion de clés

Fichiers : `racine.cnf`, `inter.cnf`, `pki.sh` (étapes 2 à 4), `verifier.sh` (étapes 5 et 6),
`certificats/` (certificats publics uniquement), `sortie_verifications.txt` (résultats réels).

```bash
./pki.sh        # crée racine, intermédiaire, serveur, alice dans ./pki
./verifier.sh   # validations + révocation d'Alice
```

## Étape 1 – Rôle des extensions
| Extension | Rôle |
|---|---|
| `basicConstraints=critical,CA:TRUE,pathlen:1` (racine) | Ce certificat est une AC ; `pathlen:1` autorise au plus **une** AC intermédiaire en dessous. `critical` : un client qui ne comprend pas l'extension doit rejeter le certificat. |
| `keyUsage=critical,keyCertSign,cRLSign` | La clé ne sert qu'à signer des certificats et des CRL (pas à du TLS). |
| `subjectKeyIdentifier=hash` | Identifiant de la clé du certificat, utilisé pour chaîner. |
| `authorityKeyIdentifier=keyid:always` | Identifie la clé de l'émetteur : permet de retrouver le bon certificat parent. |
| `pathlen:0` (intermédiaire) | L'intermédiaire ne peut signer que des certificats finaux, pas d'autres AC. |
| `nameConstraints=critical,permitted;DNS:tp.local,permitted;email:tp.local` | L'intermédiaire n'est valable que pour `tp.local` (DNS et e-mails). |
| `CA:FALSE` (feuilles) | Ce certificat ne peut pas signer d'autres certificats. |
| `keyUsage=digitalSignature` | Signature de la poignée de main TLS (ECDSA). |
| `extendedKeyUsage=serverAuth` / `clientAuth` | Un certificat serveur ne peut pas servir de certificat client, et inversement. |
| `subjectAltName` | Noms pour lesquels le certificat est valable (DNS pour le serveur, e-mail pour Alice). |

## Étape 2 – Racine
Émetteur = sujet = `C=BF, O=Universite TP, CN=Racine TP` : la racine est **auto-signée**. Il n'y a pas
d'autorité au-dessus d'elle, elle signe son propre certificat et sert d'ancre de confiance, installée
directement chez les clients. Clé : `secp384r1` (P-384), validité 10 ans (jusqu'en 2036),
extensions critiques : `basicConstraints` et `keyUsage`.

## Étape 3 – Intermédiaire
Le certificat de l'intermédiaire contient bien `CA:TRUE, pathlen:0` et la contrainte de nom critique
(`Permitted: DNS:tp.local, email:tp.local`).

## Étape 5 – Validations (résultats dans `sortie_verifications.txt`)
| Test | Résultat | Explication |
|---|---|---|
| serveur, hostname `www.tp.local` | OK | Chaîne valide et nom présent dans le SAN. |
| serveur, hostname `autre.example` | `hostname mismatch` | Le nom demandé n'est pas dans le SAN. |
| alice, `-purpose sslclient` | OK | EKU `clientAuth` présent. |
| serveur utilisé comme client | `unsuitable certificate purpose` | EKU `serverAuth` seulement. |
| `www.example.com` | `permitted subtree violation` | Hors de la contrainte de nom de l'intermédiaire. |

**Pourquoi l'AC a-t-elle pu signer `www.example.com` ?** `openssl ca` applique sa politique
d'émission (`policy_feuille`) mais **ne contrôle pas** les contraintes de nom de son propre certificat :
elles sont faites pour être vérifiées par le **client** au moment de valider la chaîne. La contrainte
est une protection qui s'applique côté validation : même si l'intermédiaire est compromis ou
mal utilisé, aucun certificat hors `tp.local` ne sera accepté.

## Étape 6 – Révocation
Après `-revoke alice.crt -crl_reason keyCompromise` et régénération des CRL, la validation d'Alice
avec `-crl_check_all` donne `certificate revoked`, tandis que le serveur reste valide.
`-crl_check_all` impose de fournir la CRL de **chaque** niveau de la chaîne (d'où `crls.pem` =
CRL intermédiaire + CRL racine).

## Questions de réflexion
1. **Racine hors ligne.** Elle signe très rarement (une fois l'intermédiaire, puis les CRL), donc
   elle n'a pas besoin d'être connectée : une clé hors ligne ne peut pas être volée à distance.
   Elle est la confiance de tout l'ensemble. *Intermédiaire compromis* : le révoquer via la CRL de
   la racine, en créer un nouveau, réémettre les certificats feuilles, publier la nouvelle CRL.
   *Racine compromise* : toute l'infrastructure est à refaire, et la nouvelle ancre de confiance
   doit être redistribuée à tous les clients ; c'est le pire scénario.
2. **`pathlen:0`.** Il interdit à l'intermédiaire de créer d'autres AC. Sans lui, l'intermédiaire (ou
   un attaquant qui le contrôle) pourrait créer des sous-AC non prévues, ce qui multiplie les
   détenteurs de pouvoir d'émission et rend la révocation et l'audit beaucoup plus difficiles.
3. **Clé privée générée par le demandeur.** La clé privée ne quitte jamais la machine qui l'utilise :
   elle ne transite pas, l'AC n'en garde pas de copie et ne peut pas se faire voler celles des
   autres. L'AC ne reçoit que la CSR, qui contient la clé publique.
4. **CN ou SAN.** Les clients modernes vérifient le **SAN**. Le CN est ignoré s'il y a un SAN
   (RFC 6125 ; navigateurs depuis Chrome 58). On met le CN pour la lisibilité.
5. **Limites des CRL.** Taille qui grossit, délai de publication (le client peut utiliser une CRL
   périmée), téléchargement coûteux, vérification souvent « soft-fail ». *OCSP* : état en temps réel
   pour un seul certificat, mais requiert un serveur disponible, révèle au répondeur les sites
   visités (atténué par l'OCSP stapling). *Certificats très courts* : le certificat expire de lui-même
   en quelques jours, ce qui réduit le besoin de révocation, à condition d'automatiser le renouvellement.
6. **Politique de certification minimale.**
   1. Seuls les administrateurs du domaine `tp.local` peuvent demander un certificat serveur.
   2. Les demandes de client sont faites par les utilisateurs de l'université, via leur compte.
   3. L'identité est vérifiée avant émission (compte institutionnel authentifié, ou contrôle
      effectif du nom de domaine demandé).
   4. Le demandeur génère sa clé ; seule la CSR est transmise.
   5. Les certificats serveur et client durent 90 jours maximum.
   6. L'AC intermédiaire dure 5 ans, la racine 10 ans, et la racine est hors ligne.
   7. Les noms émis sont limités à `tp.local` par contrainte de nom.
   8. Toute compromission de clé est signalée immédiatement ; le certificat est révoqué.
   9. Les CRL sont publiées au plus tard 24 h après une révocation et renouvelées tous les 7 jours.
   10. Les émissions et révocations sont journalisées (registre `index.txt`) et auditées.

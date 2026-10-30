# TP 2 – Infrastructure de gestion de clés

Les fichiers `racine.cnf` et `inter.cnf` sont ceux de l'**annexe B** du sujet, recopiés à
l'identique. Scripts : `pki.sh` (étapes 1 à 4), `verifier.sh` (étapes 5 et 6). Les certificats
publics sont dans `certificats/`, les résultats réels dans `sortie_verifications.txt`.

```bash
./pki.sh        # arborescence, racine, intermédiaire, serveur, alice  -> ./pki
./verifier.sh   # validations, certificat hors contrainte de nom, révocation d'Alice
```

## Étape 1 – Rôle de chaque ligne des fichiers de configuration

### `racine.cnf`
| Ligne | Rôle |
|---|---|
| `[ ca ]` `default_ca = ca_racine` | `openssl ca` utilise par défaut la section `ca_racine`. |
| `dir = ./racine` | Dossier de l'AC ; `$dir` sert d'abréviation dans les lignes suivantes. |
| `database = $dir/index.txt` | Base des certificats émis : une ligne par certificat (V valide, R révoqué, E expiré). |
| `new_certs_dir = $dir/newcerts` | Copie de chaque certificat émis, nommée par son numéro de série. |
| `serial = $dir/serial` | Prochain numéro de série (1000 ici), incrémenté à chaque émission. |
| `crlnumber = $dir/crlnumber` | Numéro de la prochaine CRL ; il augmente à chaque CRL pour détecter les remplacements. |
| `certificate`, `private_key` | Certificat et clé privée avec lesquels l'AC signe. |
| `default_md = sha384` | Hachage des signatures, cohérent avec une clé P-384. |
| `default_crl_days = 30` | Une CRL de la racine est valable 30 jours. |
| `policy = politique_souple` | Champs du sujet à contrôler. |
| `copy_extensions = none` | **Aucune** extension de la demande n'est recopiée : seule l'AC décide du contenu du certificat (sinon une CSR pourrait réclamer `CA:TRUE`). |
| `[ politique_souple ]` | `countryName` et `organizationName` facultatifs, `commonName` **obligatoire** (`supplied`). |

### Section `ext_inter` (certificat de l'AC intermédiaire)
| Ligne | Rôle |
|---|---|
| `basicConstraints = critical,CA:TRUE,pathlen:0` | C'est une AC ; `pathlen:0` : elle ne peut signer que des certificats finaux, pas d'autre AC. `critical` : un client qui ne comprend pas l'extension doit rejeter le certificat. |
| `keyUsage = critical,keyCertSign,cRLSign` | La clé ne sert qu'à signer des certificats et des CRL. |
| `nameConstraints = critical,permitted;DNS:.tp.local,permitted;DNS:tp.local,permitted;email:tp.local` | L'intermédiaire n'est valable que pour les noms `*.tp.local` (`DNS:.tp.local` : sous-domaines), `tp.local` lui-même et les adresses `…@tp.local`. |
| `subjectKeyIdentifier = hash` | Identifiant de la clé du certificat (empreinte de la clé publique). |
| `authorityKeyIdentifier = keyid` | Identifiant de la clé de l'émetteur : relie le certificat à son parent dans la chaîne. |

### `inter.cnf`
Mêmes lignes de structure que `racine.cnf` (`dir = ./inter`, base, numéros de série à partir de 2000), avec ces différences :
| Ligne | Rôle |
|---|---|
| `default_md = sha256` | Hachage adapté à une clé P-256. |
| `default_crl_days = 7` | CRL valable 7 jours : à régénérer chaque semaine, sinon les clients qui la contrôlent refusent tout (voir TP 3). |
| `copy_extensions = copy` | Les extensions de la CSR (ici le `subjectAltName` du serveur) sont **recopiées**, sauf celles déjà définies dans la section choisie. L'AC doit donc vérifier la CSR avant de signer. |

### Sections `ext_serveur` et `ext_client` (certificats finaux)
| Ligne | Rôle |
|---|---|
| `basicConstraints = critical,CA:FALSE` | Ce certificat ne peut pas signer d'autres certificats. |
| `keyUsage = critical,digitalSignature` | La clé sert à signer la poignée de main TLS (ECDSA), pas à chiffrer. |
| `extendedKeyUsage = serverAuth` / `clientAuth` | Un certificat de serveur ne peut pas servir de certificat client, et inversement. |
| `subjectAltName = email:alice@tp.local` (`ext_client` seulement) | Identité d'Alice, **fixée dans la section** : l'AC l'impose quelle que soit la CSR. |
| `subjectKeyIdentifier`, `authorityKeyIdentifier` | Identifiants de clés pour construire la chaîne. |

Pour le serveur, le `subjectAltName` (`www.tp.local`, `tp.local`) vient de la CSR grâce à `copy_extensions = copy`.

## Étape 2 – Racine
Émetteur et sujet sont identiques (`C=BF, O=Universite TP, CN=Racine TP`) : la racine est **auto-signée**. Il n'existe pas d'autorité au-dessus d'elle ; elle signe son propre certificat et sert d'ancre de confiance, installée directement chez les clients. Clé `secp384r1`, validité de 10 ans, extensions critiques : `basicConstraints` (`CA:TRUE, pathlen:1`) et `keyUsage`.

## Étape 3 – Intermédiaire
Signé par la racine avec `-extensions ext_inter`. Le certificat porte `CA:TRUE, pathlen:0` et la contrainte de nom critique (vérifiable avec `openssl x509 -in inter/inter.crt -noout -ext nameConstraints`). Son numéro de série est 1000, celui de la racine.

## Étape 4 – Feuilles
Chaque demandeur génère sa propre clé et sa CSR ; l'intermédiaire signe. Numéros de série : serveur 2000, Alice 2001.

## Étape 5 – Validations
| Test | Résultat | Explication |
|---|---|---|
| serveur, nom `www.tp.local` | OK | Chaîne valide, nom présent dans le SAN. |
| serveur, nom `autre.example` | `hostname mismatch` | Le nom demandé n'est pas dans le SAN. |
| Alice, `-purpose sslclient` | OK | Usage `clientAuth` présent. |
| serveur utilisé comme client | `unsuitable certificate purpose` | Il n'a que `serverAuth`. |
| `www.example.com` | `permitted subtree violation` | Hors de la contrainte de nom de l'intermédiaire. |

**Pourquoi l'AC a-t-elle pu signer `www.example.com` ?** `openssl ca` applique sa propre politique (`politique_souple`) mais **ne contrôle pas** les contraintes de nom de son propre certificat. Celles-ci sont vérifiées par le **client** au moment de valider la chaîne. C'est une protection : même si l'intermédiaire est compromis, un certificat hors `tp.local` ne sera jamais accepté.

## Étape 6 – Révocation
Après `-revoke alice.crt -crl_reason keyCompromise` et régénération des CRL, la validation d'Alice avec `-crl_check_all` donne `certificate revoked`, alors que le serveur reste valide. `-crl_check_all` exige la CRL de **chaque** niveau de la chaîne, d'où `crls.pem` (CRL de l'intermédiaire suivie de celle de la racine).

## Points d'attention rencontrés
1. **`nameConstraints` sur une seule ligne.** Dans le PDF de l'annexe, cette ligne est coupée en deux ; dans le fichier `.cnf` elle doit rester sur une seule ligne, sinon `openssl` échoue.
2. **`ext_client` fixe le SAN d'Alice.** Tous les certificats émis avec cette section portent `email:alice@tp.local`. Pour d'autres clients (Bob, au TP 3), il faut une autre section (je la fournis par `-extfile`, sans modifier `inter.cnf`).
3. **`unique_subject`.** Par défaut, `openssl ca` refuse d'émettre un deuxième certificat de même sujet tant que le premier est valide, ce qui bloque un renouvellement. `pki.sh` crée donc `racine/index.txt.attr` et `inter/index.txt.attr` contenant `unique_subject = no`.
4. **Numéros de CRL.** Le fichier `crlnumber` contient des valeurs **hexadécimales** : « 2000 » s'affiche « 8192 » en décimal dans `openssl crl -text`.

## Questions de réflexion
1. **Racine hors ligne.** Elle signe très rarement (l'intermédiaire, ses propres CRL) ; sans connexion, sa clé ne peut pas être volée à distance, or tout repose sur elle. *Intermédiaire compromis* : le révoquer par la CRL de la racine, en créer un nouveau, réémettre les certificats finaux. *Racine compromise* : toute l'infrastructure est à refaire et la nouvelle ancre doit être redistribuée à tous les clients : c'est le pire scénario.
2. **`pathlen:0`.** Il interdit à l'intermédiaire de créer d'autres AC. Sans lui, l'intermédiaire (ou un attaquant qui le contrôle) pourrait créer des sous-AC non prévues, multipliant les détenteurs d'un pouvoir d'émission et rendant révocation et audit beaucoup plus difficiles.
3. **Clé générée par le demandeur.** La clé privée ne quitte jamais la machine qui l'utilise : elle ne transite pas et l'AC n'en conserve aucune copie à protéger ou à se faire voler. L'AC ne reçoit que la CSR, qui contient la clé publique.
4. **CN ou SAN.** Les clients modernes vérifient le **SAN** ; le CN est ignoré dès qu'un SAN existe (RFC 6125, navigateurs depuis Chrome 58). Le CN reste pour la lisibilité.
5. **Limites des CRL.** Taille croissante, délai de publication (le client peut utiliser une CRL périmée), téléchargement coûteux, contrôle souvent « soft-fail ». *OCSP* : état en temps réel d'un seul certificat, mais il faut un répondeur disponible et il révèle les sites visités (atténué par l'OCSP stapling). *Certificats très courts* : le certificat expire de lui-même en quelques jours, ce qui réduit le besoin de révocation, à condition d'automatiser le renouvellement.
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

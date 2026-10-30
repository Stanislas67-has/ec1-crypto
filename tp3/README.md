# TP 3 – Canal sécurisé (TLS/mTLS), supervision, renouvellement

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

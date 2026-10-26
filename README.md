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

"""Mini-coffre de fichiers : AES-256-GCM + Argon2id + HKDF.

Format CFR1 (en-tete de 44 octets, authentifie comme donnee associee) :
  magic "CFR1" (4) | t (4) | m en Kio (4) | p (4) | sel (16) | nonce (12) | chiffre+tag
"""
import os
import struct

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"CFR1"
T, M, P = 3, 64 * 1024, 4          # temps, memoire (Kio), parallelisme
TAILLE_SEL, TAILLE_NONCE = 16, 12
TAILLE_ENTETE = 4 + 12 + TAILLE_SEL + TAILLE_NONCE   # 44
# Bornes de securite : on ne fait pas confiance aux parametres d'un fichier
# non authentifie (evite qu'un fichier forge consomme toute la memoire).
T_MAX, M_MAX, P_MAX = 20, 1024 * 1024, 16


def cle_maitresse(mot_de_passe: str, sel: bytes, t: int = T, m: int = M, p: int = P) -> bytes:
    """Argon2id -> 32 octets."""
    return hash_secret_raw(
        secret=mot_de_passe.encode("utf-8"), salt=sel,
        time_cost=t, memory_cost=m, parallelism=p,
        hash_len=32, type=Type.ID,
    )


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 avec info = b"coffre-v1|" + usage -> 32 octets."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"coffre-v1|" + usage,
    ).derive(maitresse)


def chiffrer(mot_de_passe: str, nom: str, donnees: bytes, params=(T, M, P)) -> bytes:
    t, m, p = params
    sel = os.urandom(TAILLE_SEL)
    nonce = os.urandom(TAILLE_NONCE)
    entete = MAGIC + struct.pack(">III", t, m, p) + sel + nonce
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement")
    ad = entete + nom.encode("utf-8")
    return entete + AESGCM(cle).encrypt(nonce, donnees, ad)


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    """Rend les donnees ou leve InvalidTag / ValueError (message volontairement generique)."""
    if len(blob) < TAILLE_ENTETE + 16 or blob[:4] != MAGIC:
        raise ValueError("fichier invalide")
    t, m, p = struct.unpack(">III", blob[4:16])
    if not (1 <= t <= T_MAX and 8 * p <= m <= M_MAX and 1 <= p <= P_MAX):
        raise ValueError("fichier invalide")
    sel = blob[16:32]
    nonce = blob[32:44]
    entete = blob[:TAILLE_ENTETE]
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement")
    return AESGCM(cle).decrypt(nonce, blob[TAILLE_ENTETE:], entete + nom.encode("utf-8"))


def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes, params=(T, M, P)) -> bytes:
    """Change le mot de passe (et met a niveau les parametres Argon2id)."""
    return chiffrer(nouveau_mdp, nom, dechiffrer(ancien_mdp, nom, blob), params)

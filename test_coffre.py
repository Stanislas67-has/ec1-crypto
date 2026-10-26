import pytest
from cryptography.exceptions import InvalidTag
import coffre

RAPIDE = (1, 8 * 1024, 1)   # parametres legers pour que les tests soient rapides
DONNEES = b"contenu secret du fichier" * 10


def test_aller_retour():
    blob = coffre.chiffrer("mdp", "a.txt", DONNEES, RAPIDE)
    assert coffre.dechiffrer("mdp", "a.txt", blob) == DONNEES


def test_chiffrement_probabiliste():
    b1 = coffre.chiffrer("mdp", "a.txt", DONNEES, RAPIDE)
    b2 = coffre.chiffrer("mdp", "a.txt", DONNEES, RAPIDE)
    assert b1 != b2
    assert b1[16:44] != b2[16:44]  # sel et nonce differents


def test_mauvais_mot_de_passe():
    blob = coffre.chiffrer("mdp", "a.txt", DONNEES, RAPIDE)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("autre", "a.txt", blob)


def test_octet_modifie():
    blob = bytearray(coffre.chiffrer("mdp", "a.txt", DONNEES, RAPIDE))
    blob[60] ^= 1
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("mdp", "a.txt", bytes(blob))


def test_nom_echange():
    blob = coffre.chiffrer("mdp", "a.txt", DONNEES, RAPIDE)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("mdp", "b.txt", blob)


def test_entete_authentifie():
    # Modifier le sel (dans l'en-tete) doit etre detecte.
    blob = bytearray(coffre.chiffrer("mdp", "a.txt", DONNEES, RAPIDE))
    blob[20] ^= 1
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("mdp", "a.txt", bytes(blob))


def test_format_inconnu():
    blob = b"XXXX" + coffre.chiffrer("mdp", "a.txt", DONNEES, RAPIDE)[4:]
    with pytest.raises(ValueError):
        coffre.dechiffrer("mdp", "a.txt", blob)


def test_parametres_abusifs_refuses():
    blob = bytearray(coffre.chiffrer("mdp", "a.txt", DONNEES, RAPIDE))
    blob[8:12] = (0xFFFFFFFF).to_bytes(4, "big")  # m enorme
    with pytest.raises(ValueError):
        coffre.dechiffrer("mdp", "a.txt", bytes(blob))


def test_rechiffrer_et_evolution():
    ancien = coffre.chiffrer("v1", "a.txt", DONNEES, RAPIDE)
    nouveau = coffre.rechiffrer("v1", "v2", "a.txt", ancien, (2, 16 * 1024, 2))
    assert coffre.dechiffrer("v2", "a.txt", nouveau) == DONNEES
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("v1", "a.txt", nouveau)
    # l'ancien fichier reste lisible malgre le changement de parametres
    assert coffre.dechiffrer("v1", "a.txt", ancien) == DONNEES

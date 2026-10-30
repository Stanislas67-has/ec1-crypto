#!/usr/bin/env python3
"""Supervision des expirations de certificats.

Usage : python3 surveiller.py DOSSIER [--alerte 30] [--critique 7]
Code de sortie : 0 = tout OK, 1 = au moins une ALERTE, 2 = au moins un CRITIQUE (ou expire).
Compatible avec les sondes de type Nagios / Zabbix / Icinga.
"""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

EXTENSIONS = {".crt", ".pem", ".cer"}
OK, ALERTE, CRITIQUE = "OK", "ALERTE", "CRITIQUE"


def niveau(jours: int, alerte: int, critique: int) -> str:
    if jours < critique:
        return CRITIQUE
    if jours < alerte:
        return ALERTE
    return OK


def jours_restants(cert: x509.Certificate, maintenant=None) -> int:
    fin = getattr(cert, "not_valid_after_utc", None)
    if fin is None:  # cryptography < 42
        fin = cert.not_valid_after.replace(tzinfo=timezone.utc)
    maintenant = maintenant or datetime.now(timezone.utc)
    return (fin - maintenant).days


def charger(chemin: Path):
    """Rend la liste des certificats d'un fichier PEM (liste vide si ce n'est pas un certificat)."""
    try:
        return x509.load_pem_x509_certificates(chemin.read_bytes())
    except ValueError:
        return []


def nom(cert: x509.Certificate) -> str:
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn[0].value if cn else cert.subject.rfc4514_string()


def analyser(dossier: Path, alerte: int = 30, critique: int = 7):
    """Rend (lignes, code_sortie). Chaque ligne : (fichier, sujet, jours, niveau)."""
    lignes, code = [], 0
    for f in sorted(p for p in dossier.rglob("*") if p.suffix.lower() in EXTENSIONS and p.is_file()):
        for cert in charger(f):
            j = jours_restants(cert)
            n = niveau(j, alerte, critique)
            lignes.append((str(f.relative_to(dossier)), nom(cert), j, n))
            code = max(code, {OK: 0, ALERTE: 1, CRITIQUE: 2}[n])
    return lignes, code


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dossier", type=Path)
    ap.add_argument("--alerte", type=int, default=30, help="seuil ALERTE en jours (defaut 30)")
    ap.add_argument("--critique", type=int, default=7, help="seuil CRITIQUE en jours (defaut 7)")
    args = ap.parse_args(argv)
    if not args.dossier.is_dir():
        print(f"Dossier introuvable : {args.dossier}", file=sys.stderr)
        return 2
    lignes, code = analyser(args.dossier, args.alerte, args.critique)
    if not lignes:
        print("Aucun certificat trouve.", file=sys.stderr)
        return 2
    print(f"{'NIVEAU':<9} {'JOURS':>6}  {'SUJET':<22} FICHIER")
    for fichier, sujet, j, n in lignes:
        etat = "EXPIRE" if j < 0 else j
        print(f"{n:<9} {etat!s:>6}  {sujet:<22} {fichier}")
    return code


if __name__ == "__main__":
    sys.exit(main())

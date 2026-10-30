import datetime as dt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import surveiller


def faire_cert(dossier, nom, jours):
    cle = ec.generate_private_key(ec.SECP256R1())
    sujet = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nom)])
    maintenant = dt.datetime.now(dt.timezone.utc)
    debut = maintenant - dt.timedelta(days=400)
    cert = (x509.CertificateBuilder().subject_name(sujet).issuer_name(sujet)
            .public_key(cle.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(debut).not_valid_after(maintenant + dt.timedelta(days=jours, hours=1))
            .sign(cle, hashes.SHA256()))
    (dossier / f"{nom}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_ok(tmp_path):
    faire_cert(tmp_path, "a", 90)
    assert surveiller.main([str(tmp_path)]) == 0


def test_alerte(tmp_path):
    faire_cert(tmp_path, "a", 90)
    faire_cert(tmp_path, "b", 20)
    assert surveiller.main([str(tmp_path)]) == 1


def test_critique(tmp_path):
    faire_cert(tmp_path, "a", 20)
    faire_cert(tmp_path, "b", 5)
    assert surveiller.main([str(tmp_path)]) == 2


def test_expire(tmp_path):
    faire_cert(tmp_path, "a", -3)
    assert surveiller.main([str(tmp_path)]) == 2


def test_fichier_non_certificat_ignore(tmp_path):
    faire_cert(tmp_path, "a", 90)
    (tmp_path / "crls.pem").write_text("pas un certificat")
    assert surveiller.main([str(tmp_path)]) == 0

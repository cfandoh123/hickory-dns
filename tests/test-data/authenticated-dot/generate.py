"""Generate public, test-only TLS credentials. Requires Python cryptography.

The CA signing keys are discarded. The checked-in server key is deliberately
public test data and must never be used for a deployed service.
"""
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BASE = Path(__file__).resolve().parent


def date(year):
    return datetime(year, 1, 1, tzinfo=timezone.utc)


def authority(name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(date(1990)).not_valid_after(date(2120))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
            .sign(key, hashes.SHA256()))
    return key, cert


def save_cert(name, cert):
    (BASE / name).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


trusted_key, trusted_ca = authority("Hickory authenticated DoT TEST CA")
rogue_key, rogue_ca = authority("Hickory authenticated DoT UNTRUSTED TEST CA")
save_cert("ca.pem", trusted_ca)
save_cert("rogue-ca.pem", rogue_ca)
server_key = ec.generate_private_key(ec.SECP256R1())
(BASE / "server.key").write_bytes(server_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
for case, name, key, issuer, before, after in [
    ("valid", "ns.auth-dot.test", trusted_key, trusted_ca, 2020, 2100),
    ("wrong-name", "unexpected.auth-dot.test", trusted_key, trusted_ca, 2020, 2100),
    ("untrusted", "ns.auth-dot.test", rogue_key, rogue_ca, 2020, 2100),
    ("expired", "ns.auth-dot.test", trusted_key, trusted_ca, 2000, 2001),
]:
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(issuer.subject).public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(date(before)).not_valid_after(date(after))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
            .sign(key, hashes.SHA256()))
    save_cert(case + ".pem", cert)

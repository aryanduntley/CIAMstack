"""A certificate's public facts (opsdir_adapter_x509.certificates), CA-neutral: serial as even-length lowercase hex,
SHA-256 as ciamFingerprint writes it, RFC 4514 subject and issuer, validity as GeneralizedTime, extended key usages
as OIDs (None without the extension); None for text that holds no certificate."""
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from opsdir.domains.pki.pem import pem_fingerprint
from opsdir_adapter_x509.certificates import certificate_facts

KEY = ec.generate_private_key(ec.SECP256R1())


def _pem(serial, usages):
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "web.example.test")])
    start = dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(KEY.public_key())
         .serial_number(serial).not_valid_before(start).not_valid_after(start + dt.timedelta(days=90)))
    b = b.add_extension(x509.ExtendedKeyUsage(list(usages)), critical=False) if usages else b
    return b.sign(KEY, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def test_the_facts_of_a_certificate():
    pem = _pem(0xABC, (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH))
    assert certificate_facts(pem) == {"serial": "0abc", "sha256": pem_fingerprint(pem),
                                      "subject": "CN=web.example.test,O=Example",
                                      "issuer": "CN=web.example.test,O=Example", "not_before": "20260901000000Z",
                                      "not_after": "20261130000000Z",
                                      "usages": ("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2")}
    assert certificate_facts(_pem(7, ()))["usages"] is None


def test_text_without_a_certificate_has_no_facts():
    assert certificate_facts("not a certificate") is None and certificate_facts(None) is None

"""A certificate's public facts (opsdir_adapter_x509.certificates), CA-neutral: serial as even-length lowercase hex,
SHA-256 as ciamFingerprint writes it, RFC 4514 subject and issuer, validity as GeneralizedTime, extended key usages
as OIDs (None without the extension), the revocation endpoints it names (CRL distribution points, freshest CRL, OCSP
and CA issuers, URIs only); None for text that holds no certificate."""
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from opsdir.domains.pki.pem import pem_fingerprint
from opsdir_adapter_x509.certificates import certificate_facts

KEY = ec.generate_private_key(ec.SECP256R1())


def _uri(u):
    return x509.UniformResourceIdentifier(u)


def _points(*uris):
    return [x509.DistributionPoint([_uri(u)], None, None, None) for u in uris]


ENDPOINTS = (x509.CRLDistributionPoints(_points("http://pki.example.test/ca.crl", "ldap://dc1/CN=ca,CN=CDP")),
             x509.FreshestCRL(_points("http://pki.example.test/ca+.crl")),
             x509.AuthorityInformationAccess([
                 x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, _uri("http://pki.example.test/ca.cer")),
                 x509.AccessDescription(AuthorityInformationAccessOID.OCSP, _uri("http://ocsp.example.test/")),
                 x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.DNSName("not-a-uri.test"))]))


def _pem(serial, usages, extensions=()):
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "web.example.test")])
    start = dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(KEY.public_key())
         .serial_number(serial).not_valid_before(start).not_valid_after(start + dt.timedelta(days=90)))
    b = b.add_extension(x509.ExtendedKeyUsage(list(usages)), critical=False) if usages else b
    for e in extensions:
        b = b.add_extension(e, critical=False)
    return b.sign(KEY, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def test_the_facts_of_a_certificate():
    pem = _pem(0xABC, (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH))
    assert certificate_facts(pem) == {"serial": "0abc", "sha256": pem_fingerprint(pem),
                                      "subject": "CN=web.example.test,O=Example",
                                      "issuer": "CN=web.example.test,O=Example", "not_before": "20260901000000Z",
                                      "not_after": "20261130000000Z",
                                      "usages": ("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"), "endpoints": ()}
    assert certificate_facts(_pem(7, ()))["usages"] is None


def test_the_revocation_endpoints_a_certificate_names_in_the_records_order():
    assert certificate_facts(_pem(8, (), ENDPOINTS))["endpoints"] == (
        ("crl", "http://pki.example.test/ca.crl"), ("crl", "ldap://dc1/CN=ca,CN=CDP"),
        ("delta-crl", "http://pki.example.test/ca+.crl"), ("ocsp", "http://ocsp.example.test/"),
        ("ca-issuers", "http://pki.example.test/ca.cer"))


def test_text_without_a_certificate_has_no_facts():
    assert certificate_facts("not a certificate") is None and certificate_facts(None) is None

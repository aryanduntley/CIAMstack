"""A certificate's public facts (opsdir_adapter_x509.certificates), CA-neutral: serial as even-length lowercase hex,
SHA-256 as ciamFingerprint writes it, RFC 4514 subject and issuer, validity as GeneralizedTime, extended key usages
as OIDs (None without the extension), the revocation endpoints it names (CRL distribution points, freshest CRL, OCSP
and CA issuers, URIs only); None for text that holds no certificate. What a relying party checks (task 129b): typed
alternative names (UPN otherNames, email, URI), an EDIPI only where a UPN follows the convention, key identifiers,
basic constraints, policy mappings, and all of it as the record's attributes."""
import base64
import datetime as dt
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, ExtensionOID, NameOID

from opsdir.domains.pki.pem import pem_fingerprint
from opsdir_adapter_x509.certificates import UPN_OID, certificate_facts, der_pem, record_facts, upn_identifiers

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
                                      "usages": ("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"), "endpoints": (),
                                      "names": ("web.example.test",), "policies": (), "upns": (), "emails": (),
                                      "uris": (), "identifiers": (), "ski": None, "aki": None, "ca": None,
                                      "path_length": None, "policy_mappings": ()}
    assert certificate_facts(_pem(7, ()))["usages"] is None


def test_the_revocation_endpoints_a_certificate_names_in_the_records_order():
    assert certificate_facts(_pem(8, (), ENDPOINTS))["endpoints"] == (
        ("crl", "http://pki.example.test/ca.crl"), ("crl", "ldap://dc1/CN=ca,CN=CDP"),
        ("delta-crl", "http://pki.example.test/ca+.crl"), ("ocsp", "http://ocsp.example.test/"),
        ("ca-issuers", "http://pki.example.test/ca.cer"))


def test_text_without_a_certificate_has_no_facts():
    assert certificate_facts("not a certificate") is None and certificate_facts(None) is None


def test_the_names_a_certificate_names_common_name_first():
    alt = x509.SubjectAlternativeName([x509.DNSName("web.example.test"), x509.DNSName("*.web.example.test"),
                                       x509.IPAddress(ipaddress.ip_address("192.0.2.10"))])
    assert certificate_facts(_pem(9, (), (alt,)))["names"] == ("web.example.test", "*.web.example.test",
                                                               "192.0.2.10")


def test_a_der_certificate_in_base64_as_pem():
    pem = _pem(10, ())
    der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
    assert der_pem(base64.b64encode(der).decode()) == pem
    assert der_pem("bm90IGRlcg==") is None and der_pem("not base64!") is None and der_pem(None) is None


# ------------------------------------------------------------------ what a relying party checks (task 129b)
def _der(tag, content):
    """A DER element (contents under 256 bytes: all these tests need)."""
    size = len(content)
    return bytes((tag,)) + (bytes((size,)) if size < 0x80 else bytes((0x81, size))) + content


def _der_oid(dotted):
    arcs = [int(a) for a in dotted.split(".")]

    def base128(n):
        out = [n & 0x7F]
        while n > 0x7F:
            n >>= 7
            out.insert(0, (n & 0x7F) | 0x80)
        return bytes(out)
    return _der(0x06, b"".join(base128(a) for a in (40 * arcs[0] + arcs[1], *arcs[2:])))


def _upn(text):
    return x509.OtherName(x509.ObjectIdentifier(UPN_OID), _der(0x0C, text.encode()))


def _mappings(*pairs):
    der = _der(0x30, b"".join(_der(0x30, _der_oid(a) + _der_oid(b)) for a, b in pairs))
    return x509.UnrecognizedExtension(ExtensionOID.POLICY_MAPPINGS, der)


CAC_POLICY, FPKI_AUTH = "2.16.840.1.101.2.1.11.39", "2.16.840.1.101.3.2.1.3.13"


def test_typed_alternative_names_and_the_edipi_recognised_in_a_cac_upn():
    alt = x509.SubjectAlternativeName([_upn("1234567890123456@mil"), x509.RFC822Name("jane.doe@mail.mil"),
                                       x509.UniformResourceIdentifier("urn:uuid:5f2b0c8e-0000-4000-8000-000000000001"),
                                       x509.OtherName(x509.ObjectIdentifier("1.2.3.4"), _der(0x0C, b"other"))])
    f = certificate_facts(_pem(11, (ExtendedKeyUsageOID.CLIENT_AUTH,), (alt,)))
    assert f["upns"] == ("1234567890123456@mil",) and f["identifiers"] == ("edipi:1234567890",)
    assert f["emails"] == ("jane.doe@mail.mil",) and f["uris"] == ("urn:uuid:5f2b0c8e-0000-4000-8000-000000000001",)


def test_an_edipi_is_derived_only_from_a_upn_that_follows_the_convention():
    assert upn_identifiers(("1234567890@mil", "1234567890@MIL")) == ("edipi:1234567890",)
    assert upn_identifiers(("jane.doe@eca.example.test",)) == ()         # an ECA subscriber has no EDIPI
    assert upn_identifiers(("1234567890@example.test", "123456789012@mil", "12345abcde@mil", "@mil")) == ()
    alt = x509.SubjectAlternativeName([x509.OtherName(x509.ObjectIdentifier(UPN_OID), b"\x04\x02ab")])  # not a string
    assert certificate_facts(_pem(12, (), (alt,)))["upns"] == ()


def test_key_identifiers_basic_constraints_and_policy_mappings():
    issuer = ec.generate_private_key(ec.SECP256R1())
    exts = (x509.BasicConstraints(ca=True, path_length=1), x509.SubjectKeyIdentifier.from_public_key(KEY.public_key()),
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()),
            x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(FPKI_AUTH), None)]),
            _mappings((FPKI_AUTH, CAC_POLICY), ("2.16.840.1.101.3.2.1.3.7", "2.16.840.1.101.2.1.11.19")))
    f = certificate_facts(_pem(13, (), exts))
    assert f["ski"] == x509.SubjectKeyIdentifier.from_public_key(KEY.public_key()).digest.hex()
    assert f["aki"] == x509.SubjectKeyIdentifier.from_public_key(issuer.public_key()).digest.hex()
    assert (f["ca"], f["path_length"], f["policies"]) == (True, 1, (FPKI_AUTH,))
    assert f["policy_mappings"] == ((FPKI_AUTH, CAC_POLICY), ("2.16.840.1.101.3.2.1.3.7", "2.16.840.1.101.2.1.11.19"))
    unlimited = certificate_facts(_pem(14, (), (x509.BasicConstraints(ca=True, path_length=None),)))
    assert (unlimited["ca"], unlimited["path_length"]) == (True, None)
    broken = x509.UnrecognizedExtension(ExtensionOID.POLICY_MAPPINGS, b"\x30\x05\x06\x01")
    assert certificate_facts(_pem(15, (), (broken,)))["policy_mappings"] == ()


def test_the_facts_as_the_records_attributes():
    alt = x509.SubjectAlternativeName([_upn("1234567890@mil")])
    pem = _pem(16, (ExtendedKeyUsageOID.CLIENT_AUTH,), (alt, x509.BasicConstraints(ca=False, path_length=None),
                                                         _mappings((FPKI_AUTH, CAC_POLICY))))
    r = record_facts(certificate_facts(pem))
    assert r["ciamSanUpn"] == ("1234567890@mil",) and r["ciamSubjectIdentifier"] == ("edipi:1234567890",)
    assert r["ciamIsCa"] == ("FALSE",) and r["ciamPathLength"] == () and r["ciamSubjectKeyId"] == ()
    assert r["ciamExtendedKeyUsage"] == ("1.3.6.1.5.5.7.3.2",) and r["ciamFingerprint"] == (pem_fingerprint(pem),)
    assert r["ciamPolicyMapping"] == (f"{FPKI_AUTH}={CAC_POLICY}",) and r["ciamSerialNumber"] == ("10",)
    assert record_facts(certificate_facts(_pem(17, ())))["ciamIsCa"] == ()

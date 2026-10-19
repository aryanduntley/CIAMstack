"""The certificates importer (x509/certificates, task 129b): each record certificate read from its recorded PEM (or a
given file with its fingerprint) gets what it says of itself, entry by entry, nothing else changed; a CA certificate
certifying a root the record holds, issued by another CA, is recorded as a cross-certificate (from the files or from
ou=certificates, which is named for removal), its role kept on re-import; certificates that are neither, files holding
a private key and files without certificates are left out with notices."""
import base64
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from opsdir.core.contract import Imported
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.cross import cross_certificates
from opsdir.domains.pki.naming import CERTIFICATES
from opsdir.domains.pki.pem import pem_fingerprint
from opsdir_adapter_x509.certificates import UPN_OID
from opsdir_adapter_x509.record import pem_blocks, read_certificates
import mini_estate
from support import after_import

NOW = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)
KEYS = {n: ec.generate_private_key(ec.SECP256R1()) for n in ("root", "partner", "bridge", "user")}
NAMES = {"root": "Example Root CA", "partner": "Partner Root CA", "bridge": "Example Bridge CA", "user": "Jane Doe"}
FPKI_AUTH, CAC_POLICY = "2.16.840.1.101.3.2.1.3.13", "2.16.840.1.101.2.1.11.39"
# the policy mappings extension's DER: one mapping, FPKI_AUTH -> CAC_POLICY (the library writes no such extension)
MAPPINGS = bytes.fromhex("30193017060a6086480165030201030d0609608648016502010b27")


def _name(key):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAMES[key])])


def _cert(subject, issuer, ca=True, extensions=(), serial=1):
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(KEYS[subject].public_key()).serial_number(serial).not_valid_before(NOW - dt.timedelta(days=30))
         .not_valid_after(NOW + dt.timedelta(days=700))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(KEYS[subject].public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(KEYS[issuer].public_key()), critical=False))
    for e in extensions:
        b = b.add_extension(e, critical=False)
    return b.sign(KEYS[issuer], hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


ROOT, PARTNER, BRIDGE = _cert("root", "root"), _cert("partner", "partner"), _cert("bridge", "bridge")
CROSS = _cert("partner", "bridge", serial=7, extensions=(x509.UnrecognizedExtension(ExtensionOID.POLICY_MAPPINGS,
                                                                                    MAPPINGS),))
HELD_CROSS = _cert("partner", "root", serial=8)
USER = _cert("user", "partner", ca=False, serial=9, extensions=(
    x509.SubjectAlternativeName([x509.OtherName(x509.ObjectIdentifier(UPN_OID), b"\x0c\x141234567890123456@mil")]),
    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
    x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(CAC_POLICY), None)])))


def _entry(cn, pem, purpose="ca", with_pem=True):
    sub = x509.load_pem_x509_certificate(pem.encode())
    return (f"dn: cn={cn},{CERTIFICATES}\nchangetype: add\nobjectClass: top\nobjectClass: ciamCertificate\ncn: {cn}\n"
            f"ciamFingerprint: {pem_fingerprint(pem)}\nciamNotAfter: 20280901000000Z\nciamCertPurpose: {purpose}\n"
            f"ciamSubject: {sub.subject.rfc4514_string()}\nciamIssuer: {sub.issuer.rfc4514_string()}\n"
            "ciamSanEmail: stale@example.test\n"
            + (f"ciamCertificatePem:: {base64.b64encode(pem.encode()).decode()}\n" if with_pem else ""))


def _record():
    text = "\n".join(("dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
                      "objectClass: organizationalUnit\nou: certificates\n",
                      _entry("example-root", ROOT), _entry("partner-root", PARTNER),
                      _entry("partner-by-root", HELD_CROSS),
                      _entry("jane", USER, purpose="client-auth", with_pem=False)))
    return mini_estate.directory(tuple(parse(text)))


FILES = {"jane.pem": USER, "cross/partner-by-bridge.crt": CROSS, "bridge.pem": BRIDGE,
         "jane.key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n" + USER, "notes.txt": "nothing"}


def test_pem_blocks_split_a_bundle():
    assert pem_blocks(ROOT + "junk\n" + PARTNER) == (ROOT, PARTNER) and pem_blocks(None) == ()


def test_record_certificates_get_what_they_say_of_themselves():
    d = _record()
    after = after_import(d, read_certificates(FILES, d, ()))
    jane = get(after, f"cn=jane,{CERTIFICATES}")
    assert values(jane, "ciamSanUpn") == ("1234567890123456@mil",)
    assert values(jane, "ciamSubjectIdentifier") == ("edipi:1234567890",)
    assert values(jane, "ciamSanEmail") == ()                                 # the certificate is the source
    assert one(jane, "ciamIsCa") == "FALSE" and values(jane, "ciamCertPolicyOid") == (CAC_POLICY,)
    assert values(jane, "ciamExtendedKeyUsage") == ("1.3.6.1.5.5.7.3.2",) and one(jane, "ciamSerialNumber") == "09"
    assert one(jane, "ciamCertificatePem") is None and one(jane, "ciamCertPurpose") == "client-auth"
    root = get(after, f"cn=example-root,{CERTIFICATES}")
    assert one(root, "ciamIsCa") == "TRUE" and one(root, "ciamSubjectKeyId") == one(root, "ciamAuthorityKeyId")
    assert one(root, "ciamPathLength") is None and values(root, "ciamSubjectIdentifier") == ()


def test_cross_certificates_are_recognised_from_the_files_and_the_record():
    d = _record()
    imported = read_certificates(FILES, d, ())
    after = after_import(d, imported)
    crosses = {one(x, "cn"): x for x in cross_certificates(after)}
    assert set(crosses) == {"Partner Root CA by Example Bridge CA", "Partner Root CA by Example Root CA"}
    x = crosses["Partner Root CA by Example Bridge CA"]
    assert (one(x, "ciamIssuer"), one(x, "ciamSubject")) == ("CN=Example Bridge CA", "CN=Partner Root CA")
    assert values(x, "ciamPolicyMapping") == (f"{FPKI_AUTH}={CAC_POLICY}",)
    assert one(x, "ciamFingerprint") == pem_fingerprint(CROSS) and one(x, "ciamSerialNumber") == "07"
    assert one(x, "ciamCertificatePem") == CROSS and one(x, "ciamNotAfter")
    notes = imported.notices
    assert notes[0] == "certificates: 4 record certificate(s) read from their PEM (1 from the files given), 2 " \
                       "cross-certificate(s)"
    assert any(n.startswith("partner-by-root: a cross-certificate") and "remove it from ou=certificates" in n
               for n in notes)
    assert any(n.startswith("bridge.pem: CN=Example Bridge CA") and "left out" in n for n in notes)
    assert "jane.key: holds a private key: not read (give certificates only)" in notes
    assert "notes.txt: holds no PEM certificate: not read" in notes


def test_a_reimport_keeps_the_cross_certificates_role_and_changes_nothing():
    d = _record()
    after = after_import(d, read_certificates(FILES, d, ()))
    x = next(x for x in cross_certificates(after) if one(x, "ciamIssuer") == "CN=Example Bridge CA")
    after = after_import(after, Imported((), ((x.dn, (x._replace(attrs={**x.attrs,
                                                                         "ciamCrossRole": ("bridge-to-member",)}),)),),
                                         ()))
    again = after_import(after, read_certificates({"cross.pem": CROSS}, after, ()))
    assert one(get(again, x.dn), "ciamCrossRole") == "bridge-to-member"
    assert again.entries == after.entries


def test_without_files_the_records_own_pems_are_read():
    d = _record()
    imported = read_certificates({}, d, ())
    after = after_import(d, imported)
    assert one(get(after, f"cn=partner-root,{CERTIFICATES}"), "ciamIsCa") == "TRUE"
    assert one(get(after, f"cn=jane,{CERTIFICATES}"), "ciamSanUpn") is None      # no PEM anywhere
    assert [one(x, "cn") for x in cross_certificates(after)] == ["Partner Root CA by Example Root CA"]

"""DISA PKE bundles (dod-pki/bundle): an archive shaped like DISA's (a combined and per-root PKCS#7 bundles, a
CMS-signed sha256 manifest, the signer's chain) exported with openssl and imported: verified against the record's CA
certificates, signed-unanchored before the root is approved, failed on a tampered file or a bad chain; members named
and grouped; openssl's facts for a certificate the cryptography library refuses."""
import datetime as dt
import hashlib
import io
import json
import shutil
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import NameOID

from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.naming import trust_bundle_dn
from opsdir.domains.pki.trust import FAILED, UNANCHORED, VERIFIED
from opsdir_adapter_dod_pki.adapter import ADAPTER
from opsdir_adapter_dod_pki.bundle import chain_shape_ok, member_names, read_bundles
from opsdir_adapter_dod_pki.export import main, manifest_lines, openssl_facts
import mini_estate
from support import after_import

needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl isn't on the PATH")
BASE = "Certificates_PKCS7_v5_14_DoD"
POLICY_OID = "2.16.840.1.101.2.1.11.39"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Gov"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn, issuer=None, issuer_key=None, ca=True, policies=()):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer or cn))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if policies:
        b = b.add_extension(x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(p), None)
                                                      for p in policies]), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256()), key


@pytest.fixture(scope="module")
def pki():
    root, root_key = _cert("Example Root CA 6")
    email, email_key = _cert("EXAMPLE EMAIL CA-73", "Example Root CA 6", root_key, policies=(POLICY_OID,))
    ident, _ = _cert("EXAMPLE ID CA-81", "Example Root CA 6", root_key, policies=(POLICY_OID,))
    signer, signer_key = _cert("SIGNER.1234567890", "EXAMPLE EMAIL CA-73", email_key, ca=False)
    return {"root": root, "email": email, "ident": ident, "signer": signer, "signer_key": signer_key}


def _p7b(certs):
    return pkcs7.serialize_certificates(list(certs), Encoding.DER)


def _archive(pki, tamper=False, chain=None):
    """A DISA-shaped archive: per-root and combined DER bundles, the chain, and the manifest signed by the signer."""
    certs = (pki["root"], pki["email"], pki["ident"])
    files = {f"{BASE}/{BASE}_Example_Root_CA_6.der.p7b": _p7b(certs), f"{BASE}/{BASE}.der.p7b": _p7b(certs),
             f"{BASE}/README.txt": b"verify me\r\n"}
    lines = "".join(f"{hashlib.sha256(v).hexdigest()}  {k.split('/')[-1]}\r\n" for k, v in sorted(files.items()))
    signed = (pkcs7.PKCS7SignatureBuilder().set_data(lines.encode())
              .add_signer(pki["signer"], pki["signer_key"], hashes.SHA256())
              .add_certificate(pki["email"]).sign(Encoding.DER, [pkcs7.PKCS7Options.Binary]))
    chain = chain if chain is not None else (pki["root"], pki["email"])
    files[f"{BASE}/{BASE}.sha256"] = signed
    files[f"{BASE}/DoD_PKE_CA_chain.pem"] = b"".join(c.public_bytes(Encoding.PEM) for c in chain)
    if tamper:
        files[f"{BASE}/{BASE}.der.p7b"] = _p7b((pki["root"], pki["email"]))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    return buf.getvalue()


def _export(tmp_path, raw):
    (tmp_path / "dod.zip").write_bytes(raw)
    assert main([str(tmp_path / "dod.zip"), "--out", str(tmp_path / "out")]) == 0
    text = (tmp_path / "out" / "dod-pki" / "dod.json").read_text()
    return {"dod-pki/dod.json": text}, json.loads(text)


def _record(pki, with_root=False):
    held = (f"dn: cn=Example Root CA 6,ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
            f"objectClass: ciamCertificate\ncn: Example Root CA 6\nciamCertPurpose: ca\n"
            f"ciamFingerprint: {pki['root'].fingerprint(hashes.SHA256()).hex(':').upper()}\n"
            f"ciamNotAfter: 20351230000000Z\n") if with_root else ""
    return mini_estate.directory(tuple(parse("dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
                                             f"objectClass: organizationalUnit\nou: certificates\n\n{held}")))


def test_the_adapter_declares_the_bundle_importer():
    assert ADAPTER.kind == "pki" and [i.name for i in ADAPTER.importers] == ["bundle"]


@needs_openssl
def test_an_export_is_signed_unanchored_until_its_root_is_held_then_verified(tmp_path, pki):
    files, doc = _export(tmp_path, _archive(pki))
    assert (doc["bundle"], doc["version"], doc["manifest"]["signature"]) == ("dod", "5.14", "valid")
    assert "SIGNER" not in json.dumps(doc)                       # the signer's name is never kept
    imported = read_bundles(files, _record(pki), ())
    bundle = imported.groups[0][1][0]
    assert one(bundle, "ciamBundleVerification") == UNANCHORED and "compare that SHA-1" in imported.notices[0]
    d = after_import(_record(pki, with_root=True), read_bundles(files, _record(pki, with_root=True), ()))
    b = get(d, trust_bundle_dn("dod"))
    assert one(b, "ciamBundleVerification") == VERIFIED and one(b, "ciamTrustBundleRelease") == "5.14"
    ident = get(d, f"cn=EXAMPLE ID CA-81,{trust_bundle_dn('dod')}")
    assert values(ident, "ciamCertPolicyOid") == (POLICY_OID,) and one(ident, "ciamCaType") == "subordinate"
    assert one(ident, "ciamBundleGroup") == "Example Root CA 6"
    assert one(get(d, f"cn=Example Root CA 6,{trust_bundle_dn('dod')}"), "ciamCaType") == "root"


@needs_openssl
def test_a_tampered_file_fails_the_bundle(tmp_path, pki):
    files, _ = _export(tmp_path, _archive(pki, tamper=True))
    bundle = read_bundles(files, _record(pki, with_root=True), ()).groups[0][1][0]
    assert one(bundle, "ciamBundleVerification") == FAILED
    assert any("SHA-256 differs" in p for p in values(bundle, "ciamInventoryProblem"))


@needs_openssl
def test_a_chain_without_its_root_fails_the_signature(tmp_path, pki):
    files, doc = _export(tmp_path, _archive(pki, chain=(pki["email"],)))
    assert doc["manifest"]["signature"] == "invalid"
    assert one(read_bundles(files, _record(pki), ()).groups[0][1][0], "ciamBundleVerification") == FAILED


def test_the_chain_is_a_root_alone_or_with_one_ca_it_issued():
    root = {"subject": "CN=R", "issuer": "CN=R"}
    assert chain_shape_ok([root]) and chain_shape_ok([root, {"subject": "CN=E", "issuer": "CN=R"}])
    assert not chain_shape_ok([{"subject": "CN=E", "issuer": "CN=R"}])
    assert not chain_shape_ok([root, {"subject": "CN=E", "issuer": "CN=R"}, {"subject": "CN=F", "issuer": "CN=R"}])


def test_manifest_lines_tolerate_crlf_and_names_are_unique():
    assert manifest_lines("AB" * 32 + "  a.p7b\r\n" + "cd" * 32 + " *b.p7b\r\n") == {"a.p7b": "ab" * 32,
                                                                                    "b.p7b": "cd" * 32}
    facts = [{"ciamSubject": "CN=DoD Root CA 3,O=US", "ciamFingerprint": "AA:" * 31 + "AA"},
             {"ciamSubject": "CN=Twin,O=US", "ciamFingerprint": "12:34:56:78:" + "00:" * 27 + "00"},
             {"ciamSubject": "CN=Twin,O=US", "ciamFingerprint": "9A:BC:DE:F0:" + "00:" * 27 + "00"}]
    assert member_names(facts) == ("DoD Root CA 3", "Twin 12345678", "Twin 9ABCDEF0")


def test_openssl_facts_stand_in_for_a_certificate_the_library_refuses():
    out = ("subject=CN=DoD Root CA 4,OU=PKI,OU=DoD,O=U.S. Government,C=US\n"
           "issuer=CN=DoD Root CA 4,OU=PKI,OU=DoD,O=U.S. Government,C=US\n"
           "notBefore=Jul 30 19:48:23 2012 GMT\nnotAfter=Jul 25 19:48:23 2032 GMT\nserial=1\n"
           "sha256 Fingerprint=55:9A:51\n")
    assert openssl_facts(out) == {"subject": "CN=DoD Root CA 4,OU=PKI,OU=DoD,O=U.S. Government,C=US",
                                  "issuer": "CN=DoD Root CA 4,OU=PKI,OU=DoD,O=U.S. Government,C=US",
                                  "not_before": "20120730194823Z", "not_after": "20320725194823Z",
                                  "serial": "01", "sha256": "55:9A:51"}
    doc = {"bundle": "dod", "version": "5.14", "exported_at": "2026-10-17T12:00:00+00:00",
           "manifest": {"signature": "valid", "files": [{"name": "x.der.p7b", "listed": "a", "actual": "a"}]},
           "combined": "x.der.p7b", "chain": [{"subject": "CN=R", "issuer": "CN=R", "sha256": "01"}],
           "certificates": [{"pem": "not a certificate", "group": "DoD Root CA 4", "facts": openssl_facts(out)}]}
    d = after_import(_record(None), read_bundles({"dod-pki/dod.json": json.dumps(doc)}, _record(None), ()))
    root4 = get(d, f"cn=DoD Root CA 4,{trust_bundle_dn('dod')}")
    assert one(root4, "ciamCaType") == "root" and one(root4, "ciamNotAfter") == "20320725194823Z"

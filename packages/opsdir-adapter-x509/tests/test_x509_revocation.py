"""The x509 adapter (x509/revocation): registration, what the observation asks each endpoint (CRL URLs as recorded,
OCSP requests by GET with the CA's CertID), CRLs and OCSP responses checked against the CA certificates the record
holds (valid, wrongly signed, another issuer, no CA certificate, key usage, delegated responders, refusals,
unreadable answers), the importer turning an export into ou=revocation-observations (unreachable, HTTP errors,
endpoints missing from the export) and a collection that stays complete when an endpoint can't be reached."""
import base64
import datetime as dt
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from opsdir.connectors.collecting import collect
from opsdir.connectors.registry import ADAPTERS
from opsdir.core.contract import Imported, PlanContext, Request
from opsdir.core.directory import get, gtime, ou_entry
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.observation import observation
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.issued import AUTHORITIES, authorities, authority_entry, endpoint_entry
from opsdir.domains.pki.naming import observation_dn
from opsdir.domains.pki.revocation import check_revocation_endpoints
from opsdir_adapter_x509.adapter import ADAPTER
from opsdir_adapter_x509.collect import revocation_steps
from opsdir_adapter_x509.plan import ocsp_request, plan
from opsdir_adapter_x509.revocation import read_revocation
from opsdir_adapter_x509.verify import crl_facts, key_hash, ocsp_facts
import mini_estate
from support import after_import

CA = "Example Issuing CA"
NOW = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)
CA_DN = "cn=issuing-ca,ou=certificates,dc=ciam-ops"
URLS = {"crl": "http://pki.example.test/CertEnroll/Example Issuing CA.crl",
        "delta-crl": "http://pki.example.test/CertEnroll/Example Issuing CA+.crl",
        "ocsp": "http://ocsp.example.test/ocsp", "ldap": "ldap:///CN=Example Issuing CA,CN=CDP"}


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, key, issuer=None, issuer_key=None, ca=True, eku=None, crl_sign=True, serial=0x1A2B):
    builder = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer or subject))
               .public_key(key.public_key()).serial_number(serial).not_valid_before(NOW - dt.timedelta(days=365))
               .not_valid_after(NOW + dt.timedelta(days=365)))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=crl_sign, content_commitment=False,
                          key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False,
                          decipher_only=False), critical=True)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256())


KEY = ec.generate_private_key(ec.SECP256R1())
CA_CERT = _cert(CA, KEY)
LEAF = _cert("web.example.test", ec.generate_private_key(ec.SECP256R1()), CA, KEY, ca=False)


def _crl(key=KEY, issuer=CA, number=41, base=None, nxt=dt.timedelta(days=7), this=NOW - dt.timedelta(hours=1)):
    builder = (x509.CertificateRevocationListBuilder().issuer_name(_name(issuer)).last_update(this)
               .add_extension(x509.CRLNumber(number), critical=False))
    builder = builder.next_update(this + nxt) if nxt else builder
    if base is not None:
        builder = builder.add_extension(x509.DeltaCRLIndicator(base), critical=True)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _ocsp(responder=CA_CERT, responder_key=KEY, status=ocsp.OCSPCertStatus.GOOD, certs=None):
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=LEAF, issuer=CA_CERT, algorithm=hashes.SHA1(), cert_status=status, this_update=NOW - dt.timedelta(hours=1),
        next_update=NOW + dt.timedelta(days=1), revocation_time=NOW - dt.timedelta(days=3)
        if status == ocsp.OCSPCertStatus.REVOKED else None,
        revocation_reason=None).responder_id(ocsp.OCSPResponderEncoding.HASH, responder)
    if certs:
        builder = builder.certificates(certs)
    return builder.sign(responder_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _record(pem=True, serial=True):
    pem_line = ("ciamCertificatePem:: " + base64.b64encode(_pem(CA_CERT).encode()).decode() + "\n") if pem else ""
    leaf = ("dn: cn=web,ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: ciamCertificate\n"
            "cn: web\nciamFingerprint: 11:22\nciamNotAfter: 20270101000000Z\nciamCertPurpose: tls-server\n"
            f"ciamSubject: CN=web.example.test\nciamIssuer: CN={CA}\n"
            + (f"ciamSerialNumber: {LEAF.serial_number:x}\n" if serial else ""))
    text = ("dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n\n"
            f"dn: {CA_DN}\nchangetype: add\nobjectClass: top\nobjectClass: ciamCertificate\ncn: issuing-ca\n"
            f"ciamFingerprint: AA:BB\nciamNotAfter: 20300101000000Z\nciamCertPurpose: ca\nciamSubject: CN={CA}\n"
            f"ciamIssuer: CN={CA}\n{pem_line}\n{leaf}")
    d = mini_estate.directory(tuple(parse(text)))
    ca = authority_entry(d, CA, f"PKI1\\{CA}")
    ca = ca._replace(attrs={**ca.attrs, "ciamCaCertificate": (CA_DN,)})
    eps = (endpoint_entry(d, CA, "crl", 1, URLS["ldap"]), endpoint_entry(d, CA, "crl", 2, URLS["crl"]),
           endpoint_entry(d, CA, "delta-crl", 1, URLS["delta-crl"]), endpoint_entry(d, CA, "ocsp", 1, URLS["ocsp"]),
           endpoint_entry(d, CA, "ca-issuers", 1, "http://pki.example.test/ca.crt"))
    return after_import(d, Imported((ou_entry(AUTHORITIES),), (inventory_group(ca, eps),), ()))


def _cas(cert=CA_CERT, d=None):
    d = d or _record()
    return ((get(d, CA_DN), cert),)


def test_registered_as_a_declaration_only_pki_adapter_with_an_estate_collector():
    found = next(a for a in ADAPTERS if a.name == "x509")
    assert found is ADAPTER and ADAPTER.kind == "pki" and ADAPTER.applies is None and ADAPTER.render_env is None
    assert [i.name for i in ADAPTER.importers] == ["revocation", "certificates"]
    assert [(c.importer, c.scope) for c in ADAPTER.collectors] == [("revocation", "estate")]


def test_the_observation_fetches_http_crls_and_asks_ocsp_by_get():
    d = _record()
    steps = dict(revocation_steps(d, None, {}, {}))
    assert set(steps) == {f"{CA}/crl-2.json", f"{CA}/delta-crl-1.json", f"{CA}/ocsp-1.json"}    # not ldap, not AIA
    assert all(isinstance(r, Request) and r.observe and r.credential is None for r in steps.values())
    assert steps[f"{CA}/crl-2.json"].url == "http://pki.example.test/CertEnroll/Example%20Issuing%20CA.crl"
    url = steps[f"{CA}/ocsp-1.json"].url
    assert url.startswith("http://ocsp.example.test/ocsp/")
    der = base64.b64decode(urllib.parse.unquote(url.rsplit("/", 1)[1]))
    asked = ocsp.load_der_ocsp_request(der)
    same = ocsp.OCSPRequestBuilder().add_certificate(LEAF, CA_CERT, hashes.SHA1()).build()      # the library's own
    assert (asked.issuer_name_hash, asked.issuer_key_hash, asked.serial_number) == \
        (same.issuer_name_hash, same.issuer_key_hash, LEAF.serial_number)
    assert asked.issuer_key_hash == key_hash(CA_CERT) and list(asked.extensions) == []        # no nonce
    assert der == ocsp_request(CA_CERT, f"{LEAF.serial_number:x}")
    why = {p.path: p.why_not for p in plan(_record(pem=False))}
    assert why[f"{CA}/ocsp-1.json"] == "the record holds no certificate of the CA (PEM) to build the request with"
    assert why[f"{CA}/crl-1.json"] == "not an http(s) URL (ldap)"
    assert plan(_record(serial=False))[-1].why_not.startswith("no certificate it issued is recorded")


def test_crls_are_checked_against_the_cas_certificate():
    good = crl_facts(_crl(), _cas())
    assert (good["ciamEndpointAnswer"], good["ciamSignatureCheck"], good["ciamSignedBy"]) == ("answered", "valid",
                                                                                               CA_DN)
    assert (good["ciamCrlNumber"], good["ciamBaseCrlNumber"]) == ("41", None)
    assert good["ciamThisUpdate"] == gtime(NOW - dt.timedelta(hours=1))
    assert good["ciamNextUpdate"] == gtime(NOW + dt.timedelta(days=7) - dt.timedelta(hours=1))
    delta = crl_facts(_crl(number=43, base=41), _cas())
    assert (delta["ciamCrlNumber"], delta["ciamBaseCrlNumber"]) == ("43", "41")
    pem = x509.load_der_x509_crl(_crl()).public_bytes(serialization.Encoding.PEM)
    assert crl_facts(pem, _cas())["ciamSignatureCheck"] == "valid"
    assert crl_facts(_crl(key=ec.generate_private_key(ec.SECP256R1())), _cas())["ciamSignatureCheck"] == "invalid"
    other = crl_facts(_crl(issuer="Someone Else CA"), _cas())
    assert (other["ciamSignatureCheck"], other["ciamInventoryProblem"]) == ("other-issuer",
                                                                             ("issued by CN=Someone Else CA",))
    assert crl_facts(_crl(), ())["ciamSignatureCheck"] == "no-ca-certificate"
    no_sign = _cert(CA, KEY, crl_sign=False)
    assert crl_facts(_crl(), _cas(no_sign))["ciamInventoryProblem"] == \
        ("the CA certificate's key usage doesn't include CRL signing",)
    assert crl_facts(b"<html>moved</html>", _cas())["ciamEndpointAnswer"] == "unreadable"


def test_ocsp_responses_are_checked_against_the_ca_or_its_delegated_responder():
    direct = ocsp_facts(_ocsp(), _cas(), "ffff")
    assert (direct["ciamOcspStatus"], direct["ciamSignatureCheck"], direct["ciamSignedBy"]) == ("good", "valid", CA_DN)
    assert direct["ciamSerialNumber"] == f"{LEAF.serial_number:x}"                 # the response's own CertID
    responder_key = ec.generate_private_key(ec.SECP256R1())
    delegate = _cert("Example OCSP Responder", responder_key, CA, KEY, ca=False, eku=[ExtendedKeyUsageOID.OCSP_SIGNING])
    via = ocsp_facts(_ocsp(delegate, responder_key, certs=[delegate]), _cas())
    assert (via["ciamSignatureCheck"], via["ciamSignedBy"]) == ("valid", CA_DN)
    assert via["ciamInventoryProblem"] == ("through responder certificate CN=Example OCSP Responder",)
    no_eku = _cert("Example OCSP Responder", responder_key, CA, KEY, ca=False)
    assert ocsp_facts(_ocsp(no_eku, responder_key, certs=[no_eku]), _cas())["ciamSignatureCheck"] == \
        "unauthorized-responder"
    other = ec.generate_private_key(ec.SECP256R1())
    impostor = _cert(CA, other)                                     # the CA's name, another key
    forged = ocsp.OCSPResponseBuilder().add_response(
        cert=LEAF, issuer=CA_CERT, algorithm=hashes.SHA1(), cert_status=ocsp.OCSPCertStatus.GOOD, this_update=NOW,
        next_update=None, revocation_time=None, revocation_reason=None) \
        .responder_id(ocsp.OCSPResponderEncoding.NAME, impostor).sign(other, hashes.SHA256())
    assert ocsp_facts(forged.public_bytes(serialization.Encoding.DER), _cas())["ciamSignatureCheck"] == "invalid"
    revoked = ocsp_facts(_ocsp(status=ocsp.OCSPCertStatus.REVOKED), _cas())
    assert revoked["ciamOcspStatus"] == "revoked"
    refused = ocsp_facts(ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED)
                         .public_bytes(serialization.Encoding.DER), _cas(), "1a2b")
    assert refused == {"ciamEndpointAnswer": "answered", "ciamOcspStatus": "unauthorized", "ciamSerialNumber": "1a2b"}
    assert ocsp_facts(b"not der", _cas())["ciamEndpointAnswer"] == "unreadable"


def test_rsa_signed_answers_verify_too():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _cert(CA, key)
    assert crl_facts(_crl(key=key), _cas(cert))["ciamSignatureCheck"] == "valid"
    response = ocsp.OCSPResponseBuilder().add_response(
        cert=LEAF, issuer=cert, algorithm=hashes.SHA1(), cert_status=ocsp.OCSPCertStatus.GOOD, this_update=NOW,
        next_update=None, revocation_time=None, revocation_reason=None) \
        .responder_id(ocsp.OCSPResponderEncoding.NAME, cert).sign(key, hashes.SHA256())
    facts = ocsp_facts(response.public_bytes(serialization.Encoding.DER), _cas(cert))
    assert (facts["ciamSignatureCheck"], facts["ciamNextUpdate"]) == ("valid", None)


def _export(**answers):
    return {f"{CA}/{name}.json": text for name, text in answers.items()}


def test_the_importer_records_each_answer_and_the_planner_judges_them():
    d = _record()
    files = _export(**{"crl-2": observation(NOW, 200, "application/pkix-crl", _crl(), None),
                       "delta-crl-1": observation(NOW, 404, "text/html", b"gone", None),
                       "ocsp-1": observation(NOW, None, None, None, "URLError: timed out"),
                       "stray": observation(NOW, 200, None, b"x", None)})
    imported = read_revocation(files, d, ())
    assert imported.notices == ("revocation: 3 of 4 endpoint(s) of 1 CA(s) observed",
                                f"{CA}/stray.json: no recorded CA endpoint of that name: left out")
    d = after_import(d, imported)
    seen = get(d, observation_dn(CA))
    assert (seen.attrs["ciamInventoryAt"], seen.attrs["ciamInventoryState"]) == ((gtime(NOW),), ("complete",))
    def of(name):
        return get(d, f"cn={name},{observation_dn(CA)}").attrs
    assert of("crl-2")["ciamSignatureCheck"] == ("valid",) and of("crl-2")["ciamCrlNumber"] == ("41",)
    assert (of("delta-crl-1")["ciamEndpointAnswer"], of("delta-crl-1")["ciamInventoryProblem"]) == \
        (("http-error",), ("HTTP 404",))
    assert of("ocsp-1")["ciamEndpointAnswer"] == ("unreachable",)
    assert of("ocsp-1")["ciamSerialNumber"] == (f"{LEAF.serial_number:x}",)
    assert (of("crl-1")["ciamEndpointAnswer"], of("crl-1")["ciamInventoryProblem"]) == \
        (("not-observed",), ("not an http(s) URL (ldap)",))
    assert of("crl-2")["ciamEndpointUrl"] == (URLS["crl"],)                   # as the CA records it
    ctx = PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, NOW.date(), {}, {}, ())
    actions = check_revocation_endpoints(ctx).actions
    assert sorted(a[1].split("`")[1] for a in actions) == ["delta-crl-1", "ocsp-1"]


def test_an_endpoint_missing_from_the_export_leaves_the_observation_incomplete():
    d = _record()
    files = _export(**{"crl-2": observation(NOW, 200, None, _crl(), None)})
    d = after_import(d, read_revocation(files, d, ()))
    seen = get(d, observation_dn(CA))
    assert seen.attrs["ciamInventoryState"] == ("incomplete",)
    assert seen.attrs["ciamInventoryProblem"] == ("not in the export: delta-crl-1, ocsp-1",)
    assert get(d, f"cn=ocsp-1,{observation_dn(CA)}").attrs["ciamInventoryProblem"] == ("not in the export",)
    assert read_revocation({}, _record(), ()).notices[1] == f"{CA}: nothing observed and no --at: its observation " \
                                                            "isn't recorded"
    at = dt.datetime(2026, 9, 29, tzinfo=dt.timezone.utc)
    d = after_import(_record(), read_revocation({}, _record(), (), at))
    assert get(d, observation_dn(CA)).attrs["ciamInventoryAt"] == (gtime(at),)


def test_an_unreachable_endpoint_never_fails_the_collection():
    d = _record()
    collector = ADAPTER.collectors[0]
    answers = {"crl": observation(NOW, 200, None, _crl(), None),
               "ocsp": observation(NOW, None, None, None, "URLError: [Errno 111] Connection refused")}
    def run(call):
        assert call.observe
        return answers["ocsp" if "ocsp" in call.url else "crl"], None
    done = collect("x509/revocation", collector, d, None, run)
    assert done.problems == () and set(done.files) == {f"{CA}/crl-2.json", f"{CA}/delta-crl-1.json",
                                                       f"{CA}/ocsp-1.json"}
    d = after_import(d, read_revocation(done.files, d, ()))
    assert [a.attrs["cn"] for a in authorities(d)] == [(CA,)]
    assert get(d, f"cn=ocsp-1,{observation_dn(CA)}").attrs["ciamEndpointAnswer"] == ("unreachable",)

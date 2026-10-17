"""EJBCA inventory (ejbca/inventory): the importer reads a source's REST answers into each CA it runs (named after its
subject's CN, the EJBCA name as ciamProviderRef), the revocation endpoints its latest active end-entity certificate
names (else the record's kept), its certificate profiles as its own templates (validity, usages, the end entity
profiles named) and the certificates it issued (facts from base64Cert, EJBCA's columns without it; template, requester
and revocation reason as EJBCA records them); complete only when every page holds what the search counted and EJBCA
counts no more than the reader saw; a root's empty search denied. The collector lists, then posts each CA's search page
by page (the only POST it declares) and reads each profile the certificates name, every answer trimmed."""
import base64
import datetime as dt
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from opsdir.connectors.collecting import collect, evidence
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.inventory import PRESENT
from opsdir.domains.pki.issued import REVOKED, reconciled
from opsdir.domains.pki.naming import authority_dn, issued_inventory_dn, template_dn
from opsdir_adapter_ejbca.adapter import ADAPTER
from opsdir_adapter_ejbca.collect import COLLECTORS, QUERIES, base_of, inventory_steps, search_body, source_problems
from opsdir_adapter_ejbca.inventory import (DENIED, PAGE_SIZE, certificate_pem, page_path, profile_path, read_inventory)
from opsdir_adapter_ejbca.profiles import RIGHTS_UNREAD, offered_to, validity_days
from opsdir_adapter_x509.certificates import certificate_facts
import mini_estate
from network_fixtures import ALPHA, entry, model
from support import after_import

AT = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.timezone.utc)
AS_OF = dt.date(2026, 10, 1)
SOURCE = "ejbca-hq"
CA, CA_ID, CA_DN = "Example Aero Issuing CA", -1009388046, "CN=Example Aero Issuing CA,O=Example Aero"
ROOT, ROOT_ID, ROOT_DN = "Example Aero Root CA", 35790970, "CN=Example Aero Root CA,O=Example Aero"
KEY = ec.generate_private_key(ec.SECP256R1())
CRL, OCSP, AIA = "http://pki.example-aero.test/crl/issuing.crl", "http://ocsp.example-aero.test/", \
    "http://pki.example-aero.test/ca/issuing.cer"
SERVER, CLIENT = "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Aero"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn, serial, start, days=397, urls=(CRL, OCSP, AIA)):
    begin = dt.datetime.fromisoformat(start).replace(tzinfo=dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(CA)).public_key(KEY.public_key())
         .serial_number(serial).not_valid_before(begin).not_valid_after(begin + dt.timedelta(days=days))
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    if urls:
        crl, ocsp, aia = urls
        b = (b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                [x509.UniformResourceIdentifier(crl)], None, None, None)]), critical=False)
             .add_extension(x509.AuthorityInformationAccess([
                 x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp)),
                 x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                        x509.UniformResourceIdentifier(aia))]), critical=False))
    return b.sign(KEY, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def _b64(pem):
    """base64Cert as EJBCA 9.6 sends it: base64 of the PEM body."""
    body = "".join(pem.splitlines()[1:-1])
    return base64.b64encode("\n".join(body[i:i + 64] for i in range(0, len(body), 64)).encode()).decode()


def _ms(day):
    return int(dt.datetime.fromisoformat(day).replace(tzinfo=dt.timezone.utc).timestamp() * 1000)


IDM, SSO, OLD, NEW = 0x2FAD51689E94B136, 0x70612626C947D083, 0x09FD3D8DFAA11569, 0x7E57
PEMS = {IDM: _cert("idm.lab.example-aero.test", IDM, "2026-09-01"),
        SSO: _cert("sso.lab.example-aero.test", SSO, "2026-09-10"),
        OLD: _cert("old-sso.lab.example-aero.test", OLD, "2026-03-01"),
        NEW: _cert("new.lab.example-aero.test", NEW, "2026-09-20", urls=None)}


def _hex(serial):
    return f"{serial:X}"


def result(serial, status=20, revoked=None, reason=-1, profile="ciam-tls", eep="ciam-servers", user=None, data=True):
    """One certificate of a v2 search answer as EJBCA 9.6 gives it."""
    pem = PEMS[serial]
    cert = x509.load_pem_x509_certificate(pem.encode())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    out = {"serialNumber": _hex(serial), "subjectDN": f"CN={cn},O=Example Aero", "issuerDN": CA_DN,
           "notBefore": int(cert.not_valid_before_utc.timestamp() * 1000),
           "expireDate": int(cert.not_valid_after_utc.timestamp() * 1000),
           "status": status, "type": 1, "revocationDate": _ms(revoked) if revoked else -1,
           "revocationReason": reason, "username": user or cn.split(".")[0],
           **({"certificateProfile": profile, "endEntityProfile": eep} if profile else {})}
    return {**out, **({"base64Cert": _b64(pem)} if data else {})}


ALL = (result(IDM), result(SSO), result(OLD, 40, "2026-09-15", 1), result(NEW, profile="ciam-short", eep="EMPTY"))
PROFILES = {"ciam-tls": {"certificate_profile_id": 1001, "available_cas": [CA], "extended_key_usages": [SERVER, CLIENT],
                         "validity": "397d"},
            "ciam-short": {"certificate_profile_id": 1002, "available_cas": ["ANY_CA"], "validity": "1y 2mo"}}


def page(certs, total=None, n=1):
    total = len(certs) if total is None else total
    return json.dumps({"certificates": list(certs), "pagination_summary": {
        "page_size": PAGE_SIZE, "current_page": n, **({"total_certs": total} if certs else {})}})


def export(certs=ALL, root=(), profiles=PROFILES, count=None, cas=None, extra=None, drop=()):
    files = {f"ejbca/{SOURCE}/cas.json": json.dumps({"certificate_authorities": cas or [
                 {"id": CA_ID, "name": CA, "subject_dn": CA_DN, "issuer_dn": ROOT_DN, "external": False},
                 {"id": ROOT_ID, "name": ROOT, "subject_dn": ROOT_DN, "issuer_dn": ROOT_DN, "external": False}]}),
             page_path(SOURCE, CA_ID, 1): page(certs), page_path(SOURCE, ROOT_ID, 1): page(root),
             **{profile_path(SOURCE, n): json.dumps(p) for n, p in profiles.items()},
             **({f"ejbca/{SOURCE}/count.json": json.dumps({"count": count})} if count is not None else {}),
             **(extra or {})}
    return {p: t for p, t in files.items() if p not in drop}


def _record(*certificates):
    head = ("dn: ou=owners,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: owners\n",
            "dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n")
    return mini_estate.directory(tuple(parse("\n".join((*head, *certificates)))))


def _recorded(cn, serial):
    f = certificate_facts(PEMS[serial])
    return (f"dn: cn={cn},ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
            f"objectClass: ciamCertificate\ncn: {cn}\nciamFingerprint: {f['sha256']}\nciamNotAfter: {f['not_after']}\n"
            f"ciamNotBefore: {f['not_before']}\nciamCertPurpose: tls-server\nciamSubject: {f['subject']}\n"
            f"ciamIssuer: CN={CA}\n")


def _imported(files, d=None):
    d = d if d is not None else _record()
    return after_import(d, read_inventory(files, d, (), AT))


def _inv(files, ca=CA):
    return get(_imported(files), issued_inventory_dn(ca))


def test_registered_as_a_pki_adapter_with_a_declared_query():
    assert (ADAPTER.name, ADAPTER.kind, [i.name for i in ADAPTER.importers]) == ("ejbca", "pki", ["inventory"])
    assert [(c.importer, c.scope, c.queries) for c in COLLECTORS] == [("inventory", "environment", QUERIES)]


def test_a_ca_becomes_its_authority_endpoints_inventory_and_certificates():
    d = _imported(export())
    ca = get(d, authority_dn(CA))
    assert one(ca, "ciamProviderRef") == CA
    assert values(ca, "ciamTemplateName") == (f"{CA}/ciam-tls", f"{CA}/ciam-short")
    ends = {one(e, "cn"): one(e, "ciamEndpointUrl") for e in d.entries.values() if e.dn.endswith("," + ca.dn)}
    assert ends == {"crl-1": CRL, "ocsp-1": OCSP, "ca-issuers-1": AIA}        # SSO's: the latest active naming them
    inv = get(d, issued_inventory_dn(CA))
    assert (one(inv, "ciamInventoryState"), one(inv, "ciamProviderRef")) == ("complete", CA)
    idm = get(d, f"cn={_hex(IDM)},{inv.dn}")
    f = certificate_facts(PEMS[IDM])
    assert (one(idm, "ciamSerialNumber"), one(idm, "ciamFingerprint"), one(idm, "ciamSubject"),
            one(idm, "ciamNotAfter")) == (f["serial"], f["sha256"], f["subject"], f["not_after"])
    assert (one(idm, "ciamTemplateName"), one(idm, "ciamRequester"), one(idm, "ciamRevocationReason")) == \
        (f"{CA}/ciam-tls", "idm", None)
    old = get(d, f"cn={_hex(OLD)},{inv.dn}")
    assert (one(old, "ciamRevocationReason"), one(old, "ciamRevokedAt")) == ("keyCompromise", "20260915000000Z")
    root = get(d, issued_inventory_dn(ROOT))
    assert one(root, "ciamInventoryState") == "denied" and values(root, "ciamInventoryProblem") == (DENIED,)


def test_profiles_are_the_cas_own_templates():
    imported = read_inventory(export(), _record(), (), AT)
    d = after_import(_record(), imported)
    tls, short = get(d, template_dn(f"{CA}/ciam-tls")), get(d, template_dn(f"{CA}/ciam-short"))
    assert one(tls, "ciamTemplateAuthority") == authority_dn(CA)
    assert (one(tls, "ciamMaxValidityDays"), values(tls, "ciamExtendedKeyUsage")) == ("397", (SERVER, CLIENT))
    assert one(tls, "description") == "EJBCA certificate profile ciam-tls (end entity profiles ciam-servers)"
    assert one(tls, "ciamSubjectFromRequest") is None and one(tls, "ciamEnrollmentScope") is None
    assert (one(short, "ciamMaxValidityDays"), values(short, "ciamExtendedKeyUsage")) == ("425", ())
    assert RIGHTS_UNREAD in imported.notices
    gone = {**PROFILES, "ciam-tls": {**PROFILES["ciam-tls"], "available_cas": ["Other CA"]}}
    imported = read_inventory(export(profiles=gone), d, (), AT)
    d = after_import(d, imported)
    assert get(d, template_dn(f"{CA}/ciam-tls")) is None
    assert f"{CA}/ciam-tls: certificate profile ciam-tls no longer offers {CA}: left out" in imported.notices
    unread = after_import(d, read_inventory(export(drop=(profile_path(SOURCE, "ciam-short"),)), d, (), AT))
    assert get(unread, template_dn(f"{CA}/ciam-short")) is not None


def test_record_certificates_reconcile_through_the_core():
    d = _imported(export(), _record(_recorded("idm-tls", IDM), _recorded("old-sso-tls", OLD)))
    states = {r.cert.attrs["cn"][0]: r.state for r in reconciled(d, AS_OF)}
    assert states == {"idm-tls": PRESENT, "old-sso-tls": REVOKED}


def test_without_certificate_data_ejbcas_columns_are_read():
    imported = read_inventory(export(certs=(result(IDM, data=False),)), _record(), (), AT)
    d = after_import(_record(), imported)
    idm = get(d, f"cn={_hex(IDM)},{issued_inventory_dn(CA)}")
    assert (one(idm, "ciamSerialNumber"), one(idm, "ciamFingerprint"), one(idm, "ciamSubject"),
            one(idm, "ciamNotBefore")) == (f"{IDM:016x}", None, "CN=idm.lab.example-aero.test,O=Example Aero",
                                           "20260901000000Z")
    assert f"{CA}: 1 certificate(s) without their certificate data (the profile doesn't store it): EJBCA's " \
           "columns only, no SHA-256" in imported.notices


def test_what_the_pages_dont_hold_leaves_the_inventory_incomplete():
    two = export(extra={page_path(SOURCE, CA_ID, 1): page(ALL, total=PAGE_SIZE + 1)})
    assert values(_inv(two), "ciamInventoryProblem") == ("search page 2 wasn't saved",)
    partial = {**two, page_path(SOURCE, CA_ID, 2): page((), total=PAGE_SIZE + 1, n=2)}
    assert values(_inv(partial), "ciamInventoryProblem") == (
        f"its pages hold 4 distinct certificate(s) of the {PAGE_SIZE + 1} the search counted: collect again",)
    moved = {**two, page_path(SOURCE, CA_ID, 2): page((result(IDM),), total=PAGE_SIZE + 2, n=2)}
    assert values(_inv(moved), "ciamInventoryProblem") == (
        f"the search counted {PAGE_SIZE + 1} certificate(s), then {PAGE_SIZE + 2}, while its pages were read: "
        "collect again",)
    error = export(extra={page_path(SOURCE, CA_ID, 1): '{"error_code": 400, "error_message": "unknown CA"}'})
    assert values(_inv(error), "ciamInventoryProblem") == ("search page 1 EJBCA answered 400: unknown CA",)


def test_a_full_first_page_and_its_second_are_one_complete_inventory():
    many = tuple({**result(IDM, data=False), "serialNumber": f"{0x1000 + n:X}"} for n in range(PAGE_SIZE))
    files = export(extra={page_path(SOURCE, CA_ID, 1): page(many, total=PAGE_SIZE + 1),
                          page_path(SOURCE, CA_ID, 2): page((result(SSO),), total=PAGE_SIZE + 1, n=2)})
    inv = _inv(files)
    assert one(inv, "ciamInventoryState") == "complete"


def test_ejbca_counting_more_than_the_reader_saw_leaves_every_ca_incomplete():
    root = (result(IDM, profile=None, user="SYSTEMCA"),)
    files = export(root=root, count=9)
    problem = ("EJBCA counts 9 certificate(s), the reader saw 5 across the CAs it may read: certificates of CAs or "
               "end entity profiles its role may not view are left out")
    assert values(_inv(files), "ciamInventoryProblem") == (problem,)
    assert values(_inv(files, ROOT), "ciamInventoryProblem") == (problem,)
    assert one(_inv(export(root=root, count=5)), "ciamInventoryState") == "complete"
    imported = read_inventory(export(root=root), _record(), (), AT)
    assert any(n.startswith(f"{SOURCE}: the reader may not count") for n in imported.notices)


def test_a_sub_ca_with_nothing_issued_is_complete_and_keeps_the_records_endpoints():
    d = _imported(export())
    d = _imported(export(certs=()), d)
    inv = get(d, issued_inventory_dn(CA))
    assert one(inv, "ciamInventoryState") == "complete"
    assert get(d, f"cn=crl-1,{authority_dn(CA)}") is not None


def test_external_cas_and_names_taken_by_another_source_are_left_out():
    cas = [{"id": 7, "name": "Partner CA", "subject_dn": "CN=Partner CA", "issuer_dn": "CN=Partner CA",
            "external": True},
           {"id": CA_ID, "name": CA, "subject_dn": CA_DN, "issuer_dn": ROOT_DN}]
    files = export(cas=cas)
    other = {p.replace(f"ejbca/{SOURCE}/", "ejbca/zz-lab/"): t for p, t in files.items()}
    imported = read_inventory({**files, **other}, _record(), (), AT)
    assert f"{SOURCE}: Partner CA is an external CA (EJBCA doesn't issue from it): not inventoried" in imported.notices
    assert f"zz-lab: CA {CA} is named {CA} like another CA read: left out" in imported.notices


def test_an_import_is_dated_and_names_an_empty_export():
    assert read_inventory(export(), _record(), (), None).notices == (
        "an inventory is dated: give --at (when EJBCA was read)",)
    assert read_inventory({}, _record(), (), AT).notices == (
        "no EJBCA sources (ejbca/<source>/cas.json, as `opsdir collect` saves them)",)


def test_profile_facts_and_certificate_data():
    assert validity_days("397d") == (397, None) and validity_days("2y") == (730, None)
    assert validity_days("1y 6mo 12h") == (546, None) and validity_days("90d 1s") == (91, None)
    assert validity_days("2030-01-01 00:00:00+00:00")[0] is None and validity_days(None) == (None, "no validity")
    assert offered_to({"available_cas": ["ANY_CA"]}, "x") and not offered_to({"available_cas": ["y"]}, "x")
    der = x509.load_pem_x509_certificate(PEMS[IDM].encode()).public_bytes(serialization.Encoding.DER)
    assert certificate_facts(certificate_pem(base64.b64encode(der).decode()))["serial"] == f"{IDM:016x}"
    assert certificate_pem(_b64(PEMS[IDM])) is not None and certificate_pem(None) is None
    assert certificate_pem(base64.b64encode(b"nonsense").decode()) is None


# ------------------------------------------------------------------ the collector
BINDING = {"ciamBindingRole": "collect-ejbca", "ciamImporter": "ejbca/inventory",
           "ciamSourceRef": "https://ejbca.example-aero.test:8443/ejbca", "ciamCredentialRole": "ejbca-reader",
           "ciamCredentialScheme": "client-certificate", "ciamCaRole": "ejbca-ca"}


def _alpha(**over):
    _, alpha, _ = model(alpha=(entry(ALPHA, SOURCE, "ciamCollectionSource", **{**BINDING, **over}),
                               entry(ALPHA, "ejbca-reader", "ciamSecretRef", ciamBindingRole="ejbca-reader",
                                     ciamRefUri="fake://vault/ejbca-reader"),
                               entry(ALPHA, "ejbca-ca", "ciamCertificateRef", ciamBindingRole="ejbca-ca",
                                     ciamRefUri="fake://vault/ejbca-ca")))
    return alpha


API = "https://ejbca.example-aero.test:8443/ejbca/ejbca-rest-api"


def _answers(files):
    """A runner answering the collector's calls from an export (each call's keep applied by the core)."""
    by_url = {f"{API}/v1/ca": files[f"ejbca/{SOURCE}/cas.json"],
              **{f"{API}/v2/certificate/profile/{n}": json.dumps(p) for n, p in PROFILES.items()}}
    seen = []

    def run(call):
        seen.append(call)
        if call.body is not None:
            asked = json.loads(call.body)
            ca = asked["criteria"][0]["value"]
            return files[page_path(SOURCE, {CA: CA_ID, ROOT: ROOT_ID}[ca], asked["pagination"]["current_page"])], None
        return by_url.get(call.url), None
    return run, seen


def test_the_collector_lists_then_searches_each_ca_and_reads_each_profile():
    m = _alpha()
    first = dict(inventory_steps(m.d, m, {}, {}))
    assert {p: c.url for p, c in first.items()} == {f"ejbca/{SOURCE}/cas.json": f"{API}/v1/ca",
                                                     f"ejbca/{SOURCE}/count.json": f"{API}/v2/certificate/count"}
    call = first[f"ejbca/{SOURCE}/cas.json"]
    assert (call.credential, call.ca, call.body) == (("client-certificate", "fake://vault/ejbca-reader", None),
                                                     "fake://vault/ejbca-ca", None)
    files = export()
    run, seen = _answers(files)
    c = collect("ejbca/inventory", COLLECTORS[0], m.d, m, run)
    assert c.problems == ()
    posts = [json.loads(x.body) for x in seen if x.body is not None]
    assert posts == [json.loads(search_body(CA, 1)), json.loads(search_body(ROOT, 1))]
    assert posts[0]["criteria"] == [{"property": "CA", "value": CA, "operation": "EQUAL"}]
    assert posts[0]["sort"] == {"property": "ISSUED_DATE", "operation": "ASC"}
    assert sorted(x.url.rsplit("/", 1)[1] for x in seen if "/profile/" in x.url) == ["ciam-short", "ciam-tls"]
    assert any(" <- POST " in e and '"current_page": 1' in e for e in evidence(c)["ciamCollectedCall"])
    d = after_import(_record(), read_inventory(c.files, _record(), (), AT))
    assert one(get(d, issued_inventory_dn(CA)), "ciamInventoryState") == "complete"


def test_a_second_page_is_asked_for_once_the_first_names_more():
    m = _alpha()
    done = {f"ejbca/{SOURCE}/cas.json": export()[f"ejbca/{SOURCE}/cas.json"],
            page_path(SOURCE, CA_ID, 1): page(ALL, total=2 * PAGE_SIZE + 1)}
    steps = dict(inventory_steps(m.d, m, done, {}))
    assert [json.loads(steps[page_path(SOURCE, CA_ID, n)].body)["pagination"]["current_page"] for n in (2, 3)] == [2, 3]
    assert page_path(SOURCE, CA_ID, 4) not in steps


def test_answers_are_trimmed_to_what_the_importer_reads():
    m = _alpha()
    done = {f"ejbca/{SOURCE}/cas.json": export()[f"ejbca/{SOURCE}/cas.json"]}
    keep = dict(inventory_steps(m.d, m, done, {}))[page_path(SOURCE, CA_ID, 1)].keep
    raw = json.dumps({"certificates": [{**result(IDM), "certificateRequest": "MIIC-csr", "subjectKeyId": "ab"}],
                      "pagination_summary": {"total_certs": 1}, "other": 1})
    kept = json.loads(keep(raw))
    assert set(kept) == {"certificates", "pagination_summary"}
    assert "certificateRequest" not in kept["certificates"][0] and "base64Cert" in kept["certificates"][0]
    assert keep("not json") == "not json"


def test_sources_that_cant_be_read_say_why_and_nothing_is_read():
    assert base_of("https://ejbca.test:8443/ejbca/") == "https://ejbca.test:8443/ejbca/ejbca-rest-api"
    assert base_of("https://ejbca.test") == "https://ejbca.test/ejbca/ejbca-rest-api" and base_of("http://x/") is None
    m = _alpha(ciamCredentialScheme="basic")
    assert source_problems(m.d, m, {}) == (f"collection source `{SOURCE}`: credential scheme `basic`: EJBCA's REST API "
                                           "takes a client certificate (client-certificate: mutual TLS)",)
    assert inventory_steps(m.d, m, {}, {}) == ()
    m = _alpha(ciamSourceRef="http://ejbca.example-aero.test/ejbca")
    assert source_problems(m.d, m, {}) == (f"collection source `{SOURCE}`: http://ejbca.example-aero.test/ejbca isn't "
                                           "an https URL (https://<host>:<port>/ejbca)",)

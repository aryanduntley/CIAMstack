"""Venafi / CyberArk Certificate Manager – Self-Hosted (venafi/certificates): the importer reads a policy folder's
listing pages and each certificate's details (shaped as the Web SDK documents them; no instance can run locally) into a
certificate manager's inventory: names, serial, SHA-1 thumbprint, validity, how it is managed, who is notified, where it
is installed, what is wrong, revocation; incomplete when the listing falls short of its total or details are unread,
denied when the listing was refused (what to grant named). The record's certificates reconcile with it (managed,
renewed, in error). The collector makes only GETs, pages by the total, trims every answer and reads nothing where no
source names a folder."""
import datetime as dt
import json

from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.managed import IN_ERROR, NOT_MANAGED, RENEWED, check_managed_certificates, reconcile_managed
from opsdir.domains.pki.naming import managed_inventory_dn
from opsdir_adapter_venafi.adapter import ADAPTER
from opsdir_adapter_venafi.certificates import (CERTIFICATES_IMPORTER, GRANT, certificate_facts, detail_path, guid_key,
                                                page_path, read_certificates, sources)
from opsdir_adapter_venafi.collect import (COLLECTORS, DETAIL_CALLS, LIMIT, certificate_steps, folder_of, kept_detail,
                                           kept_page, source_problems)
import mini_estate
from network_fixtures import ALPHA, entry, model
from support import after_import

AT = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)
AS_OF = dt.date(2026, 10, 1)
SRC = "venafi-prod"
FOLDER = "\\VED\\Policy\\Example"
ADDRESS = "https://tpp.example.test/vedsdk"
OWNERS = "ou=owners,dc=ciam-ops"
G_SSO, G_LDAP, G_LOGIN = ("{2a25573b-745c-4018-806a-e5c73f424675}", "{0b1c2d3e-0000-4000-8000-000000000002}",
                          "{0b1c2d3e-0000-4000-8000-000000000003}")


def _x509(cn, serial, thumb, start, end, issuer="CN=Public CA R11", sans=None):
    return {"CN": cn, "Issuer": issuer, "Subject": f"CN={cn}", "Serial": serial, "Thumbprint": thumb,
            "ValidFrom": f"{start}T00:00:00.0000000Z", "ValidTo": f"{end}T00:00:00.0000000Z",
            "SANS": {"DNS": sans if sans is not None else [cn]}}


def _listed(guid, name, x509):
    return {"DN": f"{FOLDER}\\{name}", "Guid": guid, "Name": name, "ParentDn": FOLDER,
            "SchemaClass": "X509 Server Certificate", "CreatedOn": "2026-01-02T00:00:00.0000000Z", "X509": x509}


def _page(certs, total=None, **more):
    return json.dumps({"Folder": FOLDER, "Address": ADDRESS, "TotalCount": len(certs) if total is None else total,
                       "Certificates": certs, **more})


def _detail(guid, management="Provisioning", created="Web SDK", **more):
    return json.dumps({"Guid": guid, "ManagementType": management, "CreatedBy": [created],
                       "Contact": ["local:{11111111-2222-3333-4444-555555555555}"],
                       "Consumers": ["\\VED\\Policy\\Example\\Devices\\sso-lb\\App-443"],
                       "CertificateAuthorityDN": "\\VED\\Policy\\CA Templates\\Public CA", **more})


def export(**over):
    sso = _listed(G_SSO, "sso.example-aero.test",
                  _x509("sso.example-aero.test", "04A1", "6323B71D1C5E38F211EEB34EDC8F9D981F8C835A", "2026-09-01",
                        "2027-09-01"))
    ldap = _listed(G_LDAP, "ldap.id.example-aero.test",
                   _x509("ldap.id.example-aero.test", "1F2E", "11" * 20, "2025-12-20", "2026-12-20",
                         issuer="CN=Example Aero Issuing CA 2"))
    login = _listed(G_LOGIN, "login.example-aero.test",
                    _x509("login.example-aero.test", "77", "22" * 20, "2026-08-01", "2027-02-01",
                          issuer="CN=Stray CA"))
    files = {page_path(SRC, 0): _page([sso, ldap, login]),
             detail_path(SRC, G_SSO): _detail(G_SSO),
             detail_path(SRC, G_LDAP): _detail(G_LDAP, "Enrollment", ProcessingDetails={
                 "InError": True, "InProcess": False, "Stage": 500,
                 "Status": "Example Aero Issuing CA 2 refused the request"}),
             detail_path(SRC, G_LOGIN): _detail(G_LOGIN, "Monitoring", "Network Discovery", Consumers=[])}
    return {**files, **over}


def _record():
    head = (f"dn: {OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
            f"dn: cn=platform,{OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\ncn: platform\n"
            "ciamOwnerKind: team\n",
            "dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n")
    certs = tuple(f"dn: cn={cn},ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
                  f"objectClass: ciamCertificate\ncn: {cn}\nciamFingerprint: {fp}\nciamCertPurpose: tls-server\n"
                  f"ciamSubject: CN={name}\nciamSubjectAltName: {name}\nciamIssuer: {issuer}\nciamSerialNumber: "
                  f"{serial}\nciamNotBefore: {nb}000000Z\nciamNotAfter: {na}000000Z\nciamOwner: cn=platform,{OWNERS}\n"
                  for cn, fp, name, issuer, serial, nb, na in (
                      ("sso-tls-2026", "24:1F", "sso.example-aero.test", "CN=Public CA R11", "03FF", "20260210",
                       "20270210"),
                      ("ds-ldaps-2026", "8D:76", "ldap.id.example-aero.test", "CN=Example Aero Issuing CA 2", "1f:2e",
                       "20251220", "20261220"),
                      ("pf-signing-2025", "AA:BB", "pf.example-aero.test", "self-signed", "01", "20250630",
                       "20270630")))
    return mini_estate.directory(tuple(parse("\n".join((*head, *certs)))))


def _imported(d, files=None):
    return after_import(d, read_certificates(export() if files is None else files, d, (), AT))


def test_the_listing_and_details_become_the_inventory():
    imp = read_certificates(export(), _record(), (), AT)
    assert imp.notices == (f"{SRC} ({FOLDER}): 3 certificate(s), complete",)
    d = _imported(_record())
    inv = get(d, managed_inventory_dn(SRC))
    assert (one(inv, "ciamInventoryState"), one(inv, "ciamInventoryPrefix"), one(inv, "ciamProviderRef")) == (
        "complete", FOLDER, ADDRESS)
    sso = get(d, f"cn={guid_key(G_SSO)},{managed_inventory_dn(SRC)}")
    assert one(sso, "ciamThumbprint") == "63:23:B7:1D:1C:5E:38:F2:11:EE:B3:4E:DC:8F:9D:98:1F:8C:83:5A"
    assert (one(sso, "ciamNotBefore"), one(sso, "ciamManagement"), one(sso, "ciamManagedOrigin")) == (
        "20260901000000Z", "provisioned", "added")
    assert values(sso, "ciamInstalledAt") == ("\\VED\\Policy\\Example\\Devices\\sso-lb\\App-443",)
    assert one(sso, "ciamManagerPath") == f"{FOLDER}\\sso.example-aero.test"
    login = get(d, f"cn={guid_key(G_LOGIN)},{managed_inventory_dn(SRC)}")
    assert (one(login, "ciamManagedOrigin"), one(login, "ciamManagement")) == ("discovered", "monitored")
    assert "ciamInstalledAt" not in login.attrs


def test_the_record_reconciles_with_it():
    d = _imported(_record())
    states = {r.cert.attrs["cn"][0]: r.state for r in reconcile_managed(d, AS_OF)}
    assert states == {"sso-tls-2026": RENEWED, "ds-ldaps-2026": IN_ERROR, "pf-signing-2025": NOT_MANAGED}
    ldap = get(d, f"cn={guid_key(G_LDAP)},{managed_inventory_dn(SRC)}")
    assert values(ldap, "ciamManagerProblem") == ("in error at stage 500: Example Aero Issuing CA 2 refused the "
                                                  "request",)
    ctx = PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF, {}, {}, ())
    texts = [t for _, t, _, _ in check_managed_certificates(ctx).actions]
    assert len(texts) == 2 and texts[0].startswith("Certificate `ds-ldaps-2026`: venafi-prod reports a problem")
    assert texts[1].startswith("Certificate `sso-tls-2026` was renewed by venafi-prod")


def test_a_short_listing_or_unread_details_leave_it_incomplete():
    files = export()
    short = {**files, page_path(SRC, 0): _page(json.loads(files[page_path(SRC, 0)])["Certificates"], total=700)}
    del short[detail_path(SRC, G_LOGIN)]
    d = _imported(_record(), short)
    inv = get(d, managed_inventory_dn(SRC))
    assert one(inv, "ciamInventoryState") == "incomplete"
    assert values(inv, "ciamInventoryProblem")[0] == "3 of 700 certificate(s) listed"
    assert values(inv, "ciamInventoryProblem")[1].startswith("details of 1 certificate(s) not read")
    login = get(d, f"cn={guid_key(G_LOGIN)},{managed_inventory_dn(SRC)}")
    assert "ciamManagement" not in login.attrs and one(login, "ciamThumbprint")


def test_a_refused_listing_is_denied_with_what_to_grant():
    files = {page_path(SRC, 0): json.dumps({"Folder": FOLDER, "Address": ADDRESS, "Error": "HTTP 403"})}
    d = _imported(_record(), files)
    inv = get(d, managed_inventory_dn(SRC))
    assert one(inv, "ciamInventoryState") == "denied"
    assert values(inv, "ciamInventoryProblem") == (f"the listing of {FOLDER} was refused (HTTP 403): {GRANT}",)
    assert "View and Read on the folder" in GRANT and "Private Key Read" in GRANT and "`certificate`" in GRANT


def test_details_say_revocation_and_disabled_management():
    facts, notices = certificate_facts(
        _listed(G_SSO, "x", _x509("x", "01", "33" * 20, "2026-01-01", "2027-01-01")),
        {"ManagementType": "Bespoke", "Disabled": 1,
         "CertificateDetails": {"RevocationStatus": "Confirmed", "RevocationDate": "2026-09-15T10:00:00Z",
                                "Issuer": "CN=Detail CA", "SubjectAltNameDNS": ["y"]}})
    assert (facts["ciamObjectState"], facts["ciamRevokedAt"], facts["ciamRevocationReason"]) == (
        "disabled", "20260915100000Z", "unspecified")
    assert facts["ciamIssuer"] == "CN=Detail CA" and facts["ciamCertificateName"] == ("x", "y")
    assert facts["ciamManagement"] is None and notices == (f"{FOLDER}\\x: ManagementType 'Bespoke' unknown: left out",)
    pending, _ = certificate_facts(_listed(G_SSO, "x", {}), {"CertificateDetails": {"RevocationStatus": "Pending"}})
    assert pending["ciamManagerProblem"] == ("revocation requested, not yet done (Pending)",)
    assert pending["ciamRevokedAt"] is None
    bare, _ = certificate_facts(_listed(G_SSO, "x", {}), None)
    assert bare["ciamObjectState"] is None and bare["ciamManagedOrigin"] is None


def test_the_export_needs_a_date_and_names_what_it_holds():
    assert read_certificates(export(), _record(), (), None).notices == (
        "an inventory is dated: give --at (when the folder was read)",)
    assert sources(export()) == (SRC,)
    assert read_certificates({}, _record(), (), AT).notices[-1].startswith("no listings")
    assert CERTIFICATES_IMPORTER in ADAPTER.importers and ADAPTER.kind == "pki"
    assert isinstance(read_certificates(export(), _record(), (), AT), Imported)


# ------------------------------------------------------------------ the collector
SOURCE = {"ciamBindingRole": "collect-venafi", "ciamImporter": "venafi/certificates",
          "ciamSourceRef": "https://tpp.example.test/VED/Policy/Example", "ciamCredentialRole": "venafi-reader",
          "ciamCredentialScheme": "bearer"}


def _alpha(**over):
    _, alpha, _ = model(alpha=(entry(ALPHA, SRC, "ciamCollectionSource", **{**SOURCE, **over}),
                               entry(ALPHA, "venafi-reader", "ciamSecretRef", ciamBindingRole="venafi-reader",
                                     ciamRefUri="fake://vault/venafi-reader")))
    return alpha


def test_the_collector_pages_by_the_total_then_reads_details_with_gets_only():
    m = _alpha()
    first = dict(certificate_steps(m.d, m, {}, {}))
    assert list(first) == [page_path(SRC, 0)]
    call = first[page_path(SRC, 0)]
    assert call.url == (f"{ADDRESS}/certificates/?ParentDnRecursive=%5CVED%5CPolicy%5CExample&Limit={LIMIT}&Offset=0"
                        "&OptionalFields=Issuer%2CSubject")
    assert call.credential == ("bearer", "fake://vault/venafi-reader", None) and call.absent == ()
    done = {page_path(SRC, 0): _page(json.loads(export()[page_path(SRC, 0)])["Certificates"], total=1200)}
    second = dict(certificate_steps(m.d, m, done, {}))
    assert [p for p in second if "certificates-" in p] == [page_path(SRC, o) for o in (0, LIMIT, 2 * LIMIT)]
    detail = second[detail_path(SRC, G_SSO)]
    assert detail.url == f"{ADDRESS}/certificates/%7B2a25573b-745c-4018-806a-e5c73f424675%7D"
    assert detail.absent == (403, 404)
    many = {page_path(SRC, 0): _page([{"Guid": f"{{{n:08x}-0000-4000-8000-000000000000}}"} for n in range(2000)])}
    assert sum(1 for p in dict(certificate_steps(m.d, m, many, {})) if "/details/" in p) == DETAIL_CALLS


def test_answers_are_trimmed_to_what_the_importer_reads():
    page = json.loads(kept_page(FOLDER, ADDRESS)(json.dumps({"TotalCount": 1, "Certificates": [{
        "Guid": G_SSO, "DN": "x", "CustomFields": [{"Name": "cost centre", "Value": "secret-ish"}],
        "X509": {"CN": "a", "PublicKey": "...", "Serial": "01"}}], "_links": []})))
    assert page == {"Folder": FOLDER, "Address": ADDRESS, "TotalCount": 1,
                    "Certificates": [{"Guid": G_SSO, "DN": "x", "X509": {"CN": "a", "Serial": "01"}}]}
    detail = json.loads(kept_detail(json.dumps({"Guid": G_SSO, "CustomFields": [], "Approver": ["local:{x}"],
                                                "ProcessingDetails": {"InError": True, "TicketDN": "t"},
                                                "CertificateDetails": {"Serial": "01", "PublicKeyHash": "h"}})))
    assert detail == {"Guid": G_SSO, "ProcessingDetails": {"InError": True}, "CertificateDetails": {"Serial": "01"}}
    assert kept_page(FOLDER, ADDRESS)("not json") == "not json" and kept_detail("nope") == "nope"


def test_the_sources_problems():
    assert source_problems(None, _alpha(ciamCredentialScheme="basic"), {}) == (
        "collection source `venafi-prod`: credential scheme `basic`: Certificate Manager's Web SDK takes an OAuth "
        "access token: bearer (issued by POST /vedauth/authorize/..., outside opsdir)",)
    bare = _alpha(ciamSourceRef="https://tpp.example.test/vedsdk")
    assert certificate_steps(bare.d, bare, {}, {}) == ()
    assert source_problems(bare.d, bare, {}) == (
        "collection source `venafi-prod`: https://tpp.example.test/vedsdk names no folder "
        "(https://<host>/VED/Policy/<folder>)",)
    assert folder_of("https://tpp:8443/VED/Policy/Example%20Aero/Web") == (
        "https://tpp:8443/vedsdk", "\\VED\\Policy\\Example Aero\\Web")
    assert folder_of("http://tpp/VED/Policy") is None
    assert COLLECTORS[0].importer == "certificates"

"""Venafi / CyberArk Certificate Manager – Self-Hosted (venafi/certificates): the importer reads a policy folder's
listing pages and each certificate's details (shaped as the Web SDK documents them; no instance can run locally) into a
certificate manager's inventory: names, serial, SHA-1 thumbprint, validity, how it is managed, who is notified, where it
is installed (applications, and host:port from network validation), what is wrong, revocation, and each certificate's
earlier versions (renewed as it: exact renewal); incomplete when the listing falls short of its total or details,
history or validation results are unread, denied when the listing was refused (what to grant named). The record's
certificates reconcile with it (managed, renewed, in error). The collector makes only GETs, pages by the total, reads
details, then history and validation results within its budget, trims every answer and reads nothing where no source
names a folder."""
import datetime as dt
import json

from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.managed import (IN_ERROR, MANAGED_STATE, NOT_MANAGED, RENEWED, check_managed_certificates,
                                        in_service, reconcile_managed, unrecorded)
from opsdir.domains.pki.naming import managed_inventory_dn
from opsdir_adapter_venafi.adapter import ADAPTER
from opsdir_adapter_venafi.certificates import (CERTIFICATES_IMPORTER, GRANT, certificate_facts, detail_path,
                                                earlier_versions, guid_key, history_path, installed_at, page_path,
                                                read_certificates, sources, validation_path)
from opsdir_adapter_venafi.collect import (COLLECTORS, DETAIL_CALLS, LIMIT, certificate_steps, folder_of, kept_detail,
                                           kept_history, kept_page, kept_validation, source_problems)
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


def _history(*versions):
    return json.dumps({"PreviousVersions": [{"VaultId": vault, "CertificateDetails": {
        "Thumbprint": thumb, "Serial": serial, "Subject": subject, "Issuer": "CN=Public CA R11", "CN": cn,
        "SubjectAltNameDNS": [cn], "ValidFrom": f"{start}T00:00:00.0000000Z", "ValidTo": f"{end}T00:00:00.0000000Z"}}
        for vault, thumb, serial, cn, subject, start, end in versions], "Success": True})


def _validation(*found):
    return json.dumps({"SslTls": [{"Host": host, "IpAddress": ip, "Port": port} for host, ip, port in found],
                       "Validated": True})


NOT_VALIDATED = json.dumps({"SslTls": [], "Validated": False})
SSO_THUMB = "6323B71D1C5E38F211EEB34EDC8F9D981F8C835A"


def export(**over):
    sso = _listed(G_SSO, "sso.example-aero.test",
                  _x509("sso.example-aero.test", "04A1", SSO_THUMB, "2026-09-01", "2027-09-01"))
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
             detail_path(SRC, G_LOGIN): _detail(G_LOGIN, "Monitoring", "Network Discovery", Consumers=[]),
             # the history lists the current version first, then the record's sso-tls-2026 (serial 03FF)
             history_path(SRC, G_SSO): _history(
                 (1301, SSO_THUMB, "04A1", "sso.example-aero.test", "CN=sso.example-aero.test", "2026-09-01",
                  "2027-09-01"),
                 (1201, "44" * 20, "03FF", "sso.example-aero.test", "CN=sso.example-aero.test", "2026-02-10",
                  "2027-02-10")),
             history_path(SRC, G_LDAP): _history(), history_path(SRC, G_LOGIN): _history(),
             validation_path(SRC, G_SSO): _validation(("sso.example-aero.test", "10.0.0.5", 443)),
             validation_path(SRC, G_LDAP): NOT_VALIDATED,
             validation_path(SRC, G_LOGIN): _validation((None, "10.0.0.9", 8443))}
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
    assert imp.notices == (f"{SRC} ({FOLDER}): 3 certificate(s) and 1 earlier version(s), complete",)
    d = _imported(_record())
    inv = get(d, managed_inventory_dn(SRC))
    assert (one(inv, "ciamInventoryState"), one(inv, "ciamInventoryPrefix"), one(inv, "ciamProviderRef")) == (
        "complete", FOLDER, ADDRESS)
    sso = get(d, f"cn={guid_key(G_SSO)},{managed_inventory_dn(SRC)}")
    assert one(sso, "ciamThumbprint") == "63:23:B7:1D:1C:5E:38:F2:11:EE:B3:4E:DC:8F:9D:98:1F:8C:83:5A"
    assert (one(sso, "ciamNotBefore"), one(sso, "ciamManagement"), one(sso, "ciamManagedOrigin")) == (
        "20260901000000Z", "provisioned", "added")
    assert values(sso, "ciamInstalledAt") == ("\\VED\\Policy\\Example\\Devices\\sso-lb\\App-443",
                                              "sso.example-aero.test:443")
    assert one(sso, "ciamManagerPath") == f"{FOLDER}\\sso.example-aero.test"
    login = get(d, f"cn={guid_key(G_LOGIN)},{managed_inventory_dn(SRC)}")
    assert (one(login, "ciamManagedOrigin"), one(login, "ciamManagement")) == ("discovered", "monitored")
    assert values(login, "ciamInstalledAt") == ("10.0.0.9:8443",)
    ldap = get(d, f"cn={guid_key(G_LDAP)},{managed_inventory_dn(SRC)}")
    assert "ciamInstalledAt" in ldap.attrs and not any(":" in v for v in values(ldap, "ciamInstalledAt"))
    old = get(d, f"cn={guid_key(G_SSO)}-v1201,{managed_inventory_dn(SRC)}")
    assert (one(old, "ciamSerialNumber"), one(old, "ciamRenewedAs"), one(old, "ciamNotAfter")) == (
        "03FF", guid_key(G_SSO), "20270210000000Z")
    assert one(old, "ciamThumbprint") == ":".join(["44"] * 20) and not in_service(old, AS_OF)
    assert get(d, f"cn={guid_key(G_SSO)}-v1301,{managed_inventory_dn(SRC)}") is None    # the current version


def test_the_record_reconciles_with_it():
    d = _imported(_record())
    done = reconcile_managed(d, AS_OF)
    states = {r.cert.attrs["cn"][0]: r.state for r in done}
    assert states == {"sso-tls-2026": RENEWED, "ds-ldaps-2026": IN_ERROR, "pf-signing-2025": NOT_MANAGED}
    sso = next(r for r in done if r.state == RENEWED)        # exact: the earlier version found names its renewal
    assert (sso.found.attrs["cn"][0], sso.newer.attrs["cn"][0]) == (f"{guid_key(G_SSO)}-v1201", guid_key(G_SSO))
    assert [r.attrs["cn"][0] for _, r in unrecorded(d, done, AS_OF)] == [guid_key(G_LOGIN)]
    ldap = get(d, f"cn={guid_key(G_LDAP)},{managed_inventory_dn(SRC)}")
    assert values(ldap, "ciamManagerProblem") == ("in error at stage 500: Example Aero Issuing CA 2 refused the "
                                                  "request",)
    ctx = PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF, {}, {}, ())
    texts = [t for _, t, _, _ in check_managed_certificates(ctx).actions]
    assert len(texts) == 2 and texts[0].startswith("Certificate `ds-ldaps-2026`: venafi-prod reports a problem")
    assert texts[1].startswith("Certificate `sso-tls-2026` was renewed by venafi-prod")


def test_a_linked_renewal_is_exact_never_inferred():
    # the newer version disabled: the record's certificate isn't renewed as anything (no inference by subject)
    files = export(**{detail_path(SRC, G_SSO): _detail(G_SSO, Disabled=1)})
    sso = next(r for r in reconcile_managed(_imported(_record(), files), AS_OF) if r.cert.attrs["cn"][0] ==
               "sso-tls-2026")
    assert (sso.state, sso.newer, sso.found.attrs["cn"][0]) == (MANAGED_STATE, None, f"{guid_key(G_SSO)}-v1201")
    # no history: renewal inferred from the newer certificate for the same subject and issuer
    files = export(**{history_path(SRC, G_SSO): _history()})
    sso = next(r for r in reconcile_managed(_imported(_record(), files), AS_OF) if r.cert.attrs["cn"][0] ==
               "sso-tls-2026")
    assert (sso.state, sso.found, sso.newer.attrs["cn"][0]) == (RENEWED, None, guid_key(G_SSO))
    listed = _listed(G_SSO, "x", _x509("x", "01", SSO_THUMB, "2026-01-01", "2027-01-01"))
    assert earlier_versions(guid_key(G_SSO), listed, None) == ()
    assert [k for k, _ in earlier_versions("g", listed, {"PreviousVersions": [
        {"CertificateDetails": {"Thumbprint": "55" * 20}}, {"VaultId": 7, "CertificateDetails": {"Thumbprint": "aa"}},
        {"VaultId": 8}]})] == ["g-" + "55" * 20, "g-v7"]


def test_validation_results_name_host_and_port():
    assert installed_at(json.loads(_validation(("a.test", "10.0.0.1", 443), (None, "10.0.0.2", 636),
                                               ("b.test", None, None)))) == ("a.test:443", "10.0.0.2:636")
    assert installed_at(json.loads(NOT_VALIDATED)) == () and installed_at(None) == ()


def test_a_short_listing_or_unread_details_leave_it_incomplete():
    files = export()
    short = {**files, page_path(SRC, 0): _page(json.loads(files[page_path(SRC, 0)])["Certificates"], total=700)}
    del short[detail_path(SRC, G_LOGIN)]
    d = _imported(_record(), short)
    inv = get(d, managed_inventory_dn(SRC))
    assert one(inv, "ciamInventoryState") == "incomplete"
    assert values(inv, "ciamInventoryProblem")[0] == "3 of 700 certificate(s) listed"
    assert values(inv, "ciamInventoryProblem")[1].startswith("details of 1 certificate(s) not read")
    untraced = export()
    del untraced[validation_path(SRC, G_LDAP)], untraced[history_path(SRC, G_LOGIN)]
    inv = get(_imported(_record(), untraced), managed_inventory_dn(SRC))
    assert one(inv, "ciamInventoryState") == "incomplete"
    assert values(inv, "ciamInventoryProblem") == (
        "previous versions or validation results of 2 certificate(s) not read (their renewals are inferred, and "
        "where network validation found them is unknown): collect again, or export the folder with "
        "scripts/export-venafi.sh",)
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
    assert second[history_path(SRC, G_SSO)].url == f"{detail.url}/PreviousVersions"
    assert second[validation_path(SRC, G_LOGIN)].url.endswith("%7D/ValidationResults")
    assert all(c.body is None and c.absent == (403, 404) for p, c in second.items() if "certificates-" not in p)
    assert sum(1 for p in second if "certificates-" not in p) == 9
    def reads(n):
        many = {page_path(SRC, 0): _page([{"Guid": f"{{{i:08x}-0000-4000-8000-000000000000}}"} for i in range(n)])}
        steps = dict(certificate_steps(m.d, m, many, {}))
        return tuple(sum(1 for p in steps if f"/{kind}/" in p) for kind in ("details", "history", "validation"))
    assert reads(2000) == (DETAIL_CALLS, 0, 0)
    assert reads(700) == (700, (DETAIL_CALLS - 700) // 2, (DETAIL_CALLS - 700) // 2)
    assert reads(400) == (400, 400, 400)


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
    history = json.loads(kept_history(json.dumps({"Success": True, "PreviousVersions": [
        {"VaultId": 3, "CertificateDetails": {"Serial": "01", "PublicKeyHash": "h", "SubjectAltNameEmail": ["e"]}},
        {"VaultId": 4}]})))
    assert history == {"PreviousVersions": [{"VaultId": 3, "CertificateDetails": {"Serial": "01"}}]}
    found = json.loads(kept_validation(json.dumps({"File": [{"Installation": "x"}], "SslTls": [
        {"Host": "a", "IpAddress": "10.0.0.1", "Port": 443, "Result": {"ID": 1}, "Sources": ["SAN"]}]})))
    assert found == {"SslTls": [{"Host": "a", "IpAddress": "10.0.0.1", "Port": 443}], "Validated": True}
    assert json.loads(kept_validation("")) == json.loads(NOT_VALIDATED)
    assert kept_history("nope") == "nope" and kept_validation("nope") == "nope"


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

"""CyberArk Certificate Manager – SaaS (venafi/saas): the importer reads a tenant's certificate search pages (shaped as
the vendor's examples and vcert show them; no tenant can be reached here) into a certificate manager's inventory:
SHA-1 fingerprint, serial, subject, issuer, validity, names, status, origin, installations (instances not superseded)
and earlier versions renewed as their managed certificate's current one (exact renewal); incomplete when pages are
missing or unreadable, the count isn't reached or the page past it isn't empty, denied when the search was refused.
The collector's only call is the declared read-only search POST, paged from 0 to one past the count's end, with the
API key in the tppl-api-key header or a bearer token, trimmed."""
import datetime as dt
import json

from opsdir.connectors.collecting import refused
from opsdir.core.contract import Request
from opsdir.core.directory import get, one, values
from opsdir.domains.pki.managed import RENEWED, reconcile_managed, unrecorded
from opsdir.domains.pki.naming import managed_inventory_dn
from opsdir_adapter_venafi.adapter import ADAPTER
from opsdir_adapter_venafi.saas import (GRANT, SAAS_IMPORTER, installed_at, page_path, read_saas, saas_facts,
                                        sources)
from opsdir_adapter_venafi.saas_collect import (PAGE_SIZE, QUERIES, SAAS_COLLECTORS, address_of, kept_page,
                                                saas_source_problems, saas_steps, search_body)
from opsdir.core.interchange.ldif import parse
import mini_estate
from network_fixtures import ALPHA, entry, model
from support import after_import

AT = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)
AS_OF = dt.date(2026, 10, 1)
SRC = "Example-Aero-SaaS"
ADDRESS = "https://api.venafi.cloud"
NEW, OLD_ID, STRAY = ("0f6e1a2b-1111-4aaa-8bbb-000000000001", "0f6e1a2b-1111-4aaa-8bbb-000000000002",
                      "0f6e1a2b-1111-4aaa-8bbb-000000000003")


def _cert(cid, cn, serial, thumb, start, end, version="CURRENT", managed="m-sso", status="ACTIVE", **more):
    return {"id": cid, "managedCertificateId": managed, "versionType": version, "certificateStatus": status,
            "fingerprint": thumb, "serialNumber": serial, "subjectCN": [cn], "subjectDN": f"CN={cn}",
            "issuerDN": "CN=Public CA R11", "validityStart": f"{start}T00:00:00.000+0000",
            "validityEnd": f"{end}T00:00:00.000+0000", "subjectAlternativeNamesByType": {"dNSName": [cn]},
            "certificateSource": "USER_PROVIDED", **more}


def _record():
    """The record: its SSO certificate (serial 03FF), which the tenant renewed."""
    return mini_estate.directory(tuple(parse(
        "dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
        "ou: certificates\n\n"
        "dn: cn=sso-tls-2026,ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
        "objectClass: ciamCertificate\ncn: sso-tls-2026\nciamFingerprint: 24:1F\nciamCertPurpose: tls-server\n"
        "ciamSubject: CN=sso.example-aero.test\nciamSubjectAltName: sso.example-aero.test\n"
        "ciamIssuer: CN=Public CA R11\nciamSerialNumber: 03FF\nciamNotBefore: 20260210000000Z\n"
        "ciamNotAfter: 20270210000000Z\n")))


def _page(certs, count=None, **more):
    return json.dumps({"Address": ADDRESS, "PageSize": PAGE_SIZE, "count": len(certs) if count is None else count,
                       "certificates": certs, **more})


def export(**over):
    certs = [_cert(NEW, "sso.example-aero.test", "05C1", "AB" * 20, "2026-09-01", "2027-09-01", instances=[
                 {"hostname": "sso.example-aero.test", "ipAddress": "10.0.0.5", "port": 443,
                  "deploymentStatus": "INSTALLED"},
                 {"hostname": "old-lb.example-aero.test", "port": 443, "deploymentStatus": "SUPERSEDED"}]),
             _cert(OLD_ID, "sso.example-aero.test", "03FF", "CD" * 20, "2026-02-10", "2027-02-10", version="OLD",
                   status="RETIRED"),
             _cert(STRAY, "login.example-aero.test", "0777", "EF" * 20, "2026-08-01", "2027-02-01",
                   managed="m-login", certificateSource="USER_SCAN",
                   instances=[{"ipAddress": "10.0.0.9", "port": 8443, "deploymentStatus": "INSTALLED"}])]
    return {page_path(SRC, 0): _page(certs), page_path(SRC, 1): _page([], count=3), **over}


def _imported(d, files=None):
    return after_import(d, read_saas(export() if files is None else files, d, (), AT))


def test_the_search_becomes_the_inventory():
    imp = read_saas(export(), _record(), (), AT)
    assert imp.notices == (f"{SRC} ({ADDRESS}): 3 certificate(s) (1 earlier version(s)), complete",)
    d = _imported(_record())
    inv = get(d, managed_inventory_dn(SRC))
    assert (one(inv, "ciamInventoryState"), one(inv, "ciamProviderRef")) == ("complete", ADDRESS)
    new = get(d, f"cn={NEW},{managed_inventory_dn(SRC)}")
    assert one(new, "ciamThumbprint") == ":".join(["AB"] * 20) and one(new, "ciamNotBefore") == "20260901000000Z"
    assert values(new, "ciamInstalledAt") == ("sso.example-aero.test:443",)
    assert (one(new, "ciamObjectState"), one(new, "ciamManagedOrigin"), one(new, "ciamRenewedAs")) == (
        "active", "added", None)
    old = get(d, f"cn={OLD_ID},{managed_inventory_dn(SRC)}")
    assert (one(old, "ciamRenewedAs"), one(old, "ciamObjectState")) == (NEW, "disabled")
    stray = get(d, f"cn={STRAY},{managed_inventory_dn(SRC)}")
    assert (one(stray, "ciamManagedOrigin"), values(stray, "ciamInstalledAt")) == ("discovered", ("10.0.0.9:8443",))


def test_the_record_is_renewed_exactly_through_the_earlier_version():
    d = _imported(_record())
    done = reconcile_managed(d, AS_OF)
    sso = next(r for r in done if r.cert.attrs["cn"][0] == "sso-tls-2026")
    assert (sso.state, sso.found.attrs["cn"][0], sso.newer.attrs["cn"][0]) == (RENEWED, OLD_ID, NEW)
    assert [r.attrs["cn"][0] for _, r in unrecorded(d, done, AS_OF)] == [STRAY]


def test_facts_left_unset_where_the_search_says_nothing():
    facts = saas_facts({"id": "X", "versionType": "OLD", "managedCertificateId": "m", "certificateStatus": "Odd"},
                       {"m": "x"})
    assert facts["ciamRenewedAs"] is None and facts["ciamObjectState"] is None       # itself the current one
    assert facts["ciamManagedOrigin"] is None and facts["ciamSubject"] is None
    assert saas_facts({"id": "Y", "versionType": "OLD", "managedCertificateId": "gone"}, {})["ciamRenewedAs"] is None
    assert installed_at({"instances": [{"hostname": "h", "port": None}, "x", {"ipAddress": "1.2.3.4", "port": 0}]}) == (
        "1.2.3.4:0",)


def test_missing_pages_a_short_count_or_more_past_it_leave_it_incomplete():
    certs = json.loads(export()[page_path(SRC, 0)])["certificates"]
    short = {page_path(SRC, 0): _page(certs, count=120)}
    inv = get(_imported(_record(), short), managed_inventory_dn(SRC))
    assert one(inv, "ciamInventoryState") == "incomplete"
    assert values(inv, "ciamInventoryProblem") == ("search page(s) 1, 2, 3 not read", "3 of 120 certificate(s) found")
    beyond = export(**{page_path(SRC, 1): _page([_cert("extra", "x.test", "01", "12" * 20, "2026-01-01",
                                                        "2027-01-01", managed="m-x")], count=3)})
    inv = get(_imported(_record(), beyond), managed_inventory_dn(SRC))
    assert values(inv, "ciamInventoryProblem") == (
        "the page past the count (1) still holds certificates: the count isn't the total",)
    broken = export(**{page_path(SRC, 1): "<html>"})
    assert values(get(_imported(_record(), broken), managed_inventory_dn(SRC)), "ciamInventoryProblem") == (
        "1 search page(s) not a search answer (page 1)",)


def test_a_refused_search_is_denied_with_what_to_grant():
    files = {page_path(SRC, 0): json.dumps({"Address": ADDRESS, "Error": "HTTP 401"})}
    inv = get(_imported(_record(), files), managed_inventory_dn(SRC))
    assert one(inv, "ciamInventoryState") == "denied"
    assert values(inv, "ciamInventoryProblem") == (f"the certificate search was refused (HTTP 401): {GRANT}",)
    assert "Guest" in GRANT and "tppl-api-key" in GRANT


def test_the_export_needs_a_date_and_names_what_it_holds():
    assert read_saas(export(), _record(), (), None).notices == (
        "an inventory is dated: give --at (when the tenant was searched)",)
    assert sources(export()) == (SRC,)
    assert read_saas({}, _record(), (), AT).notices[-1].startswith("no search pages")
    assert SAAS_IMPORTER in ADAPTER.importers and SAAS_COLLECTORS[0] in ADAPTER.collectors


# ------------------------------------------------------------------ the collector
SOURCE = {"ciamBindingRole": "collect-saas", "ciamImporter": "venafi/saas", "ciamSourceRef": ADDRESS,
          "ciamCredentialRole": "saas-reader", "ciamCredentialScheme": "api-key"}


def _alpha(**over):
    _, alpha, _ = model(alpha=(entry(ALPHA, SRC, "ciamCollectionSource", **{**SOURCE, **over}),
                               entry(ALPHA, "saas-reader", "ciamSecretRef", ciamBindingRole="saas-reader",
                                     ciamRefUri="fake://vault/saas-reader")))
    return alpha


def test_the_collector_posts_only_the_declared_search_paged_past_the_count():
    m = _alpha()
    first = dict(saas_steps(m.d, m, {}, {}))
    assert list(first) == [page_path(SRC, 0)]
    call = first[page_path(SRC, 0)]
    assert call.url == f"{ADDRESS}/outagedetection/v1/certificatesearch?excludeSupersededInstances=true"
    assert json.loads(call.body) == {"paging": {"pageNumber": 0, "pageSize": PAGE_SIZE}} == json.loads(search_body(0))
    assert call.credential == ("api-key", "fake://vault/saas-reader", None, "tppl-api-key")
    assert refused(call, QUERIES) is None
    assert refused(Request(f"{ADDRESS}/outagedetection/v1/certificates", body="{}"), QUERIES)
    second = dict(saas_steps(m.d, m, {page_path(SRC, 0): _page([], count=2 * PAGE_SIZE + 1)}, {}))
    assert list(second) == [page_path(SRC, n) for n in range(4)]
    assert json.loads(second[page_path(SRC, 3)].body)["paging"]["pageNumber"] == 3
    bearer = _alpha(ciamCredentialScheme="bearer")
    assert dict(saas_steps(bearer.d, bearer, {}, {}))[page_path(SRC, 0)].credential == (
        "bearer", "fake://vault/saas-reader", None)


def test_answers_are_trimmed_to_what_the_importer_reads():
    page = json.loads(kept_page(ADDRESS)(json.dumps({"count": 1, "certificates": [{
        "id": "a", "companyId": "c", "keyStrength": 2048, "subjectAlternativeNamesByType": {"dNSName": ["x"],
                                                                                             "rfc822Name": ["m"]},
        "instances": [{"hostname": "h", "port": 1, "sslProtocols": [], "applicationIds": []}]}]})))
    assert page == {"Address": ADDRESS, "PageSize": PAGE_SIZE, "count": 1, "certificates": [
        {"id": "a", "subjectAlternativeNamesByType": {"dNSName": ["x"]}, "instances": [{"hostname": "h", "port": 1}]}]}
    assert kept_page(ADDRESS)("nope") == "nope"


def test_the_sources_problems():
    assert saas_source_problems(None, _alpha(ciamCredentialScheme="basic"), {}) == (
        f"collection source `{SRC}`: credential scheme `basic`: Certificate Manager – SaaS takes a user API key "
        "(api-key: the tppl-api-key header) or a service account's access token (bearer)",)
    bad = _alpha(ciamSourceRef="https://api.venafi.cloud/outagedetection")
    assert saas_steps(bad.d, bad, {}, {}) == ()
    assert saas_source_problems(bad.d, bad, {})[0].endswith("isn't the tenant's API address (https://api.venafi.cloud "
                                                            "or its regional host, no path)")
    assert address_of("https://api.eu.venafi.cloud/") == "https://api.eu.venafi.cloud"
    assert address_of("https://api.venafi.eu") == "https://api.venafi.eu"
    assert address_of("http://api.venafi.cloud") is None

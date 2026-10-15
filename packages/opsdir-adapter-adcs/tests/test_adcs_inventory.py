"""The AD CS inventory importer (adcs/inventory): registration, a CA's typed JSON export read into its authority,
endpoints and issued-certificate inventory (metadata only, key columns never read), the forest's templates from LDIF
(base64 values, pKIExpirationPeriod decoded or refused), template values resolved by name, display name or OID, the
publication URL entries' flags and variables, incomplete and denied exports, and reconciliation with the record."""
import base64
import datetime as dt
import json

from opsdir.connectors.registry import ADAPTERS
from opsdir.core.directory import get
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.issued import REVOKED, reconciled
from opsdir.domains.pki.naming import authority_dn, issued_inventory_dn, template_dn
from opsdir_adapter_adcs.adapter import ADAPTER
from opsdir_adapter_adcs.inventory import read_inventory
from opsdir_adapter_adcs.templates import validity_days
from opsdir_adapter_adcs.urls import CRL_KINDS, endpoints, split_entry
import mini_estate
from support import after_import

AT = dt.datetime(2026, 9, 23, 9, 0, tzinfo=dt.timezone.utc)
CA = "Example Issuing CA"
SHA = "ab" * 32
DEFAULT_PERIOD = bytes.fromhex("00 40 39 87 2E E1 FE FF")


def _ldif_template(cn, display, oid, period=DEFAULT_PERIOD, usages=("1.3.6.1.5.5.7.3.1",)):
    return "\n".join((f"dn: CN={cn},CN=Certificate Templates,CN=Public Key Services,CN=Services,"
                      "CN=Configuration,DC=corp,DC=example,DC=test", "objectClass: top",
                      "objectClass: pKICertificateTemplate", f"cn: {cn}",
                      f"displayName:: {base64.b64encode(display.encode()).decode()}",
                      f"msPKI-Cert-Template-OID: {oid}",
                      *((f"pKIExpirationPeriod:: {base64.b64encode(period).decode()}",) if period else ()),
                      *(f"pKIExtendedKeyUsage: {u}" for u in usages), ""))


TEMPLATES = "\n".join((_ldif_template("CIAM-WebServer", "CIAM Web Server", "1.3.6.1.4.1.311.21.8.1.2"),
                       _ldif_template("Odd", "Odd period", "1.3.6.1.4.1.311.21.8.1.3",
                                      period=(-(10_000_000 * 3600)).to_bytes(8, "little", signed=True))))


def _row(request, disposition=20, **more):
    return {"RequestID": request, "SerialNumber": f"00{request:02x}aa", "NotBefore": "2026-01-01T00:00:00Z",
            "NotAfter": "2027-01-01T00:00:00Z", "CertificateTemplate": "1.3.6.1.4.1.311.21.8.1.2",
            "Request.RequesterName": "CORP\\svc-web", "Request.Disposition": disposition,
            "Request.RevokedWhen": None, "Request.RevokedEffectiveWhen": None, "Request.RevokedReason": None,
            "SHA256": None, "Subject": f"CN=host{request}.example.test", **more}


def _export(rows=(), **more):
    return json.dumps({"format": "opsdir-adcs-inventory", "version": 1, "exporter": "Export-AdcsInventory 1.0",
                       "exportedAt": "2026-09-23T09:00:00Z", "config": f"PKI1\\{CA}", "caName": CA,
                       "dnsName": "pki1.corp.example.test", "netbiosName": "PKI1", "complete": True, "error": None,
                       "templates": ["CIAM-WebServer", "1.3.6.1.4.1.311.21.8.1.2"],
                       "crlPublicationUrls": ["65:C:\\Windows\\system32\\CertSrv\\CertEnroll\\%3%8%9.crl",
                                              "6:http://pki.example.test/crl/%3%8%9.crl"],
                       "caCertPublicationUrls": ["2:http://pki.example.test/aia/%1_%3%4.crt",
                                                 "32:http://ocsp.example.test/ocsp"],
                       "rows": list(rows), **more})


def _read(files, d=None):
    return read_inventory(files, d or mini_estate.directory(), (), AT)


def test_registered_declaration_only_of_kind_pki():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "pki" and ADAPTER.applies is None
    assert [i.name for i in ADAPTER.importers] == ["inventory"]


def test_a_ca_export_becomes_its_authority_endpoints_and_inventory():
    revoked = _row(2, 21, **{"Request.RevokedWhen": "2026-09-02T10:00:00Z",
                             "Request.RevokedEffectiveWhen": "2026-09-01T00:00:00Z", "Request.RevokedReason": 4,
                             "SHA256": SHA.upper()})
    imp = _read({"templates.ldif": TEMPLATES, f"ca/{CA}.json": _export((_row(1), revoked))})
    d = after_import(mini_estate.directory(), imp)
    ca = get(d, authority_dn(CA))
    assert ca.attrs["ciamProviderRef"] == (f"PKI1\\{CA}",) and ca.attrs["ciamTemplateName"] == ("CIAM-WebServer",)
    eps = {e.attrs["cn"][0]: (e.attrs["ciamEndpointUrl"][0], e.attrs.get("description")) for e in d.entries.values()
           if e.dn.endswith(authority_dn(CA)) and e.dn != authority_dn(CA)}
    assert eps == {"crl-1": (f"http://pki.example.test/crl/{CA}.crl", None),
                   "delta-crl-1": (f"http://pki.example.test/crl/{CA}+.crl", None),
                   "ca-issuers-1": (f"http://pki.example.test/aia/pki1.corp.example.test_{CA}%4.crt",
                                    ("the CA's template: http://pki.example.test/aia/%1_%3%4.crt",)),
                   "ocsp-1": ("http://ocsp.example.test/ocsp", None)}
    inv = get(d, issued_inventory_dn(CA))
    assert inv.attrs["ciamInventoryState"] == ("complete",) and inv.attrs["ciamInventoryAt"] == ("20260923090000Z",)
    one = get(d, f"cn=1,{issued_inventory_dn(CA)}")
    assert one.attrs["ciamSerialNumber"] == ("0001aa",) and one.attrs["ciamTemplateName"] == ("CIAM-WebServer",)
    assert one.attrs["ciamNotAfter"] == ("20270101000000Z",) and "ciamRevokedAt" not in one.attrs
    two = get(d, f"cn=2,{issued_inventory_dn(CA)}")
    assert two.attrs["ciamRevokedAt"] == ("20260901000000Z",) and two.attrs["ciamRevocationReason"] == ("superseded",)
    assert two.attrs["ciamFingerprint"][0] == ":".join(["AB"] * 32)
    assert any("%4 not filled" in n for n in imp.notices)


def test_templates_from_ldif():
    d = after_import(mini_estate.directory(), _read({"templates.ldif": TEMPLATES}))
    web = get(d, template_dn("CIAM-WebServer"))
    assert web.attrs["description"] == ("CIAM Web Server",) and web.attrs["ciamMaxValidityDays"] == ("365",)
    assert web.attrs["ciamTemplateOid"] == ("1.3.6.1.4.1.311.21.8.1.2",)
    assert web.attrs["ciamExtendedKeyUsage"] == ("1.3.6.1.5.5.7.3.1",)
    assert "ciamMaxValidityDays" not in get(d, template_dn("Odd")).attrs
    assert validity_days(DEFAULT_PERIOD) == (365, None)
    assert validity_days((10).to_bytes(8, "little", signed=True))[0] is None
    assert validity_days(b"\x00" * 7)[0] is None


def test_unreadable_rows_leave_the_inventory_incomplete_and_key_columns_are_never_read():
    rows = (_row(1, NotAfter="2027-01-01T00:00:00"), _row(3, 30), {"SerialNumber": "ff"},
            _row(4, RawArchivedKey="AAAA", Extra="x"))
    imp = _read({f"ca/{CA}.json": _export(rows)})
    d = after_import(mini_estate.directory(), imp)
    inv = get(d, issued_inventory_dn(CA))
    assert inv.attrs["ciamInventoryState"] == ("incomplete",)
    problems = " | ".join(inv.attrs["ciamInventoryProblem"])
    assert "NotAfter '2027-01-01T00:00:00' has no time zone" in problems
    assert "disposition 30" in problems and "1 row(s) without a request id" in problems
    assert get(d, f"cn=3,{issued_inventory_dn(CA)}") is None
    assert any("key column(s) RawArchivedKey: never read" in n for n in imp.notices)
    assert all("AAAA" not in str(e.attrs) for e in d.entries.values())


def test_denied_and_partial_exports():
    d = after_import(mini_estate.directory(), _read({f"ca/{CA}.json": _export((_row(1),),
                                                                             error="0x80070005 access denied")}))
    inv = get(d, issued_inventory_dn(CA))
    assert inv.attrs["ciamInventoryState"] == ("denied",) and get(d, f"cn=1,{inv.dn}") is None
    d = after_import(mini_estate.directory(), _read({f"ca/{CA}.json": _export((_row(1),), complete=False)}))
    assert get(d, issued_inventory_dn(CA)).attrs["ciamInventoryProblem"] == ("the exporter didn't read every row",)
    assert _read({"ca/x.json": json.dumps({"format": "other"})}).groups == ()
    assert len(_read({f"ca/{CA}.json": "\ufeff" + _export()}).groups) == 2       # a BOM, as PowerShell 5.1 writes


def test_publication_url_entries():
    assert split_entry("65:C:\\Windows\\x.crl") == (65, "C:\\Windows\\x.crl") and split_entry("C:\\x") is None
    found, notices = endpoints(("8:ldap:///CN=%7%8,CN=%2,CN=CDP,%6%10", "x"), CRL_KINDS, {"netbios": "PKI1"})
    assert found == () and notices == ("publication URL entry 'x' has no decimal flags: left out",)


def test_reconciled_with_the_record():
    cert = ("dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n\ndn: cn=tls,ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
            f"objectClass: ciamCertificate\ncn: tls\nciamFingerprint: {SHA}\nciamNotAfter: 20270101000000Z\n"
            f"ciamCertPurpose: tls-server\nciamIssuer: CN={CA}, O=Example\n")
    d = mini_estate.directory(tuple(parse(cert)))
    revoked = _row(2, 21, **{"Request.RevokedEffectiveWhen": "2026-09-01T00:00:00Z", "Request.RevokedReason": 1,
                             "SHA256": SHA})
    d = after_import(d, _read({f"ca/{CA}.json": _export((revoked,))}, d))
    assert [(r.state, r.found.attrs["ciamRevocationReason"]) for r in reconciled(d, dt.date(2026, 9, 23))] == [
        (REVOKED, ("keyCompromise",))]

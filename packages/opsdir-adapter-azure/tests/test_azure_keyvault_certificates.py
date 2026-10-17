"""Azure Key Vault certificates (azure/keyvault-certificates): the importer reads a vault's certificate listing, each
certificate's versions, policy and pending operation, each version's public certificate, and the vault's contacts and
issuers (shaped as Key Vault's REST reference, api-version 2025-07-01, documents them) into a certificate manager's
inventory: one managed certificate per version, how the policy manages it, who is notified, what is wrong now;
incomplete when pages, versions, policies or versions' certificates are unread, denied when the listing was refused
(what to grant named). The record's certificates reconcile with it (renewed by a newer version, in error). The
collector makes only `az rest` GETs on the vault's own address, with the cloud's token audience, pages by nextLink,
trims every answer (never a key's or secret's id, a CSR, a phone number or tags) and reads nothing where no source
names a vault of the cloud."""
import base64
import datetime as dt
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from opsdir.core.contract import Command, Imported, PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.managed import IN_ERROR, NOT_MANAGED, RENEWED, check_managed_certificates, reconcile_managed
from opsdir.domains.pki.naming import managed_inventory_dn
from opsdir.domains.pki.pem import pem_fingerprint, pem_thumbprint
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.keyvault_certificates import (GRANT, KEYVAULT_CERTIFICATES, authority, certificate_rows,
                                                        epoch_time, id_parts, lifetime_actions, management, page_path,
                                                        pending_path,
                                                        pending_problems, policy_path, read_keyvault_certificates,
                                                        sources, thumbprint, vault_path, version_path, versions_path)
from opsdir_adapter_azure.keyvault_collect import (API_VERSION, DETAIL_CALLS, KEYVAULT_COLLECTOR, kept_contacts,
                                                   kept_page, kept_pending, kept_policy, kept_version,
                                                   keyvault_problems, keyvault_steps, vault_of)
import mini_estate
from network_fixtures import ALPHA, entry, model
from support import after_import

AT = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)
AS_OF = dt.date(2026, 10, 1)
SRC = "kv-prod"
VAULT = "https://kv-example.vault.azure.net"
OWNERS = "ou=owners,dc=ciam-ops"
KEY = ec.generate_private_key(ec.SECP256R1())
V1, V2, V3, V4 = "a" * 32, "b" * 32, "c" * 32, "d" * 32


def _pem(cn, serial, start, end, issuer=None):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (x509.CertificateBuilder().subject_name(subject)
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]) if issuer else subject)
         .public_key(KEY.public_key()).serial_number(serial)
         .not_valid_before(dt.datetime.fromisoformat(f"{start}T00:00:00+00:00"))
         .not_valid_after(dt.datetime.fromisoformat(f"{end}T00:00:00+00:00"))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False))
    return b.sign(KEY, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


PEMS = {V1: _pem("sp.example-aero.test", 0x11, "2025-11-01", "2026-11-30"),
        V2: _pem("sp.example-aero.test", 0x12, "2026-09-01", "2027-09-30"),
        V3: _pem("ldap.example-aero.test", 0x2F, "2026-01-10", "2027-01-10", "Public CA G2"),
        V4: _pem("login.example-aero.test", 0x44, "2026-08-01", "2027-08-01", "Public CA G2")}
NAMES = {V1: "sp-signing", V2: "sp-signing", V3: "ldap-tls", V4: "login-tls"}


def _der(pem):
    return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)


def _x5t(pem):
    return base64.urlsafe_b64encode(bytes.fromhex(pem_thumbprint(pem).replace(":", ""))).decode().rstrip("=")


def _epoch(day):
    return int(dt.datetime.fromisoformat(f"{day}T00:00:00+00:00").timestamp())


def _item(name, version=None, enabled=True):
    pem = PEMS[version] if version else PEMS[{"sp-signing": V2, "ldap-tls": V3, "login-tls": V4}[name]]
    cert = x509.load_pem_x509_certificate(pem.encode())
    return {"id": f"{VAULT}/certificates/{name}" + (f"/{version}" if version else ""), "x5t": _x5t(pem),
            "attributes": {"enabled": enabled, "nbf": int(cert.not_valid_before_utc.timestamp()),
                           "exp": int(cert.not_valid_after_utc.timestamp())}}


def _page(items, next_link=None):
    return json.dumps({"Vault": VAULT, "value": items, "nextLink": next_link})


def _version(version):
    item = _item(NAMES[version], version)
    return json.dumps({**item, "cer": base64.b64encode(_der(PEMS[version])).decode()})


def _policy(issuer, *actions):
    return json.dumps({"issuer": {"name": issuer}, "x509_props": {"subject": "CN=x", "validity_months": 12},
                       "lifetime_actions": [{"trigger": trigger, "action": {"action_type": kind}}
                                            for kind, trigger in actions], "attributes": {"enabled": True}})


def export(**over):
    files = {page_path(SRC, 0): _page([_item("sp-signing"), _item("ldap-tls"), _item("login-tls")]),
             vault_path(SRC, "contacts"): json.dumps({"contacts": [{"email": "pki@example-aero.test", "name": "PKI"}]}),
             vault_path(SRC, "issuers"): json.dumps({"value": [{"id": f"{VAULT}/certificates/issuers/DigiCertIssuer",
                                                               "provider": "DigiCert"}]}),
             versions_path(SRC, "sp-signing", 0): json.dumps({"value": [_item("sp-signing", V1),
                                                                         _item("sp-signing", V2)]}),
             versions_path(SRC, "ldap-tls", 0): json.dumps({"value": [_item("ldap-tls", V3)]}),
             versions_path(SRC, "login-tls", 0): json.dumps({"value": [_item("login-tls", V4)]}),
             policy_path(SRC, "sp-signing"): _policy("Self", ("AutoRenew", {"lifetime_percentage": 80})),
             policy_path(SRC, "ldap-tls"): _policy("DigiCertIssuer", ("EmailContacts", {"days_before_expiry": 30})),
             policy_path(SRC, "login-tls"): _policy("Unknown"),
             pending_path(SRC, "ldap-tls"): json.dumps({"status": "failed", "status_details": "Order rejected",
                                                        "error": {"code": "CertificateRequestRejected",
                                                                  "message": "domain validation failed"},
                                                        "issuer": {"name": "DigiCertIssuer"}}),
             **{version_path(SRC, NAMES[v], v): _version(v) for v in PEMS}}
    return {**files, **over}


def _record():
    head = (f"dn: {OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
            f"dn: cn=platform,{OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\ncn: platform\n"
            "ciamOwnerKind: team\n",
            "dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n")
    certs = tuple(f"dn: cn={cn},ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
                  f"objectClass: ciamCertificate\ncn: {cn}\nciamFingerprint: {fp}\nciamCertPurpose: tls-server\n"
                  f"ciamSubject: CN={name}\nciamSubjectAltName: {name}\nciamIssuer: {issuer}\n{serial}"
                  f"ciamNotBefore: {nb}000000Z\nciamNotAfter: {na}000000Z\nciamOwner: cn=platform,{OWNERS}\n"
                  for cn, fp, name, issuer, serial, nb, na in (
                      ("sp-signing-2025", pem_fingerprint(PEMS[V1]), "sp.example-aero.test", "self-signed", "",
                       "20251101", "20261130"),
                      ("ldap-tls-2026", "8D:76", "ldap.example-aero.test", "CN=Public CA G2",
                       "ciamSerialNumber: 2f\n", "20260110", "20270110"),
                      ("pf-signing-2025", "AA:BB", "pf.example-aero.test", "self-signed", "", "20250630",
                       "20270630")))
    return mini_estate.directory(tuple(parse("\n".join((*head, *certs)))))


def _imported(d, files=None):
    return after_import(d, read_keyvault_certificates(export() if files is None else files, d, (), AT))


def _managed(d, cn):
    return get(d, f"cn={cn},{managed_inventory_dn(SRC)}")


def test_every_version_becomes_a_managed_certificate():
    imp = read_keyvault_certificates(export(), _record(), (), AT)
    assert imp.notices == (f"{SRC} (kv-example): 4 version(s) of 3 certificate(s), complete",)
    d = _imported(_record())
    inv = get(d, managed_inventory_dn(SRC))
    assert (one(inv, "ciamInventoryState"), one(inv, "ciamInventoryPrefix"), one(inv, "ciamProviderRef")) == (
        "complete", "kv-example", VAULT)
    old = _managed(d, f"sp-signing/{V1}")
    assert (one(old, "ciamFingerprint"), one(old, "ciamThumbprint"), one(old, "ciamSerialNumber")) == (
        pem_fingerprint(PEMS[V1]), pem_thumbprint(PEMS[V1]), "11")
    assert (one(old, "ciamSubject"), one(old, "ciamIssuer"), one(old, "ciamNotBefore"), one(old, "ciamNotAfter")) == (
        "CN=sp.example-aero.test", "CN=sp.example-aero.test", "20251101000000Z", "20261130000000Z")
    assert values(old, "ciamCertificateName") == ("sp.example-aero.test",)
    assert (one(old, "ciamManagement"), one(old, "ciamManagedAuthority"), one(old, "ciamManagedOrigin")) == (
        "enrolled", "Self", "added")
    assert one(old, "ciamManagerPath") == f"kv-example/sp-signing/{V1}" and one(old, "ciamObjectState") == "active"
    assert values(old, "ciamManagerContact") == ("pki@example-aero.test",)
    ldap = _managed(d, f"ldap-tls/{V3}")
    assert (one(ldap, "ciamManagement"), one(ldap, "ciamManagedAuthority")) == ("monitored",
                                                                                "DigiCertIssuer (DigiCert)")
    assert values(ldap, "ciamManagerProblem") == (
        "the pending request to DigiCertIssuer failed: Order rejected; CertificateRequestRejected; domain validation "
        "failed",)
    login = _managed(d, f"login-tls/{V4}")
    assert (one(login, "ciamManagement"), one(login, "ciamManagedAuthority")) == ("unassigned", "Unknown")
    assert "ciamManagerContact" not in login.attrs and "ciamInstalledAt" not in login.attrs


def test_older_versions_name_their_successor_and_the_policy_its_actions():
    # ciamRenewedAs and ciamManagerAction are the core's (attrs 905, 900): what the importer gives managed_entry
    rows, gaps = certificate_rows(export(), SRC, "kv-example", "sp-signing", _x5t(PEMS[V2]), {}, ("a@x",))
    assert [(cn, f["ciamRenewedAs"]) for cn, f in rows] == [(f"sp-signing/{V1}", f"sp-signing/{V2}"),
                                                            (f"sp-signing/{V2}", None)]
    assert rows[0][1]["ciamManagerAction"] == ("AutoRenew at 80% of its lifetime",) and gaps == (False, 0, False)
    ldap, _ = certificate_rows(export(), SRC, "kv-example", "ldap-tls", None, {}, ())
    assert ldap[0][1]["ciamManagerAction"] == ("EmailContacts at 30 days before expiry",)
    assert ldap[0][1]["ciamManagerProblem"] == ()           # the pending operation is the current version's only


def test_the_record_reconciles_with_it():
    d = _imported(_record())
    states = {r.cert.attrs["cn"][0]: r.state for r in reconcile_managed(d, AS_OF)}
    assert states == {"sp-signing-2025": RENEWED, "ldap-tls-2026": IN_ERROR, "pf-signing-2025": NOT_MANAGED}
    ctx = PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF, {}, {}, ())
    texts = [t for _, t, _, _ in check_managed_certificates(ctx).actions]
    assert len(texts) == 2
    assert texts[0].startswith(f"Certificate `ldap-tls-2026`: {SRC} reports a problem with it")
    assert texts[1].startswith(f"Certificate `sp-signing-2025` was renewed by {SRC}") and V2 in texts[1]


def test_unread_pages_versions_policies_or_certificates_leave_it_incomplete():
    files = export(**{page_path(SRC, 0): _page([_item("sp-signing"), _item("ldap-tls"), _item("login-tls")],
                                               f"{VAULT}/certificates?$skiptoken=x")})
    for gone in (version_path(SRC, "sp-signing", V1), policy_path(SRC, "login-tls"),
                 versions_path(SRC, "ldap-tls", 0)):
        del files[gone]
    d = _imported(_record(), files)
    inv = get(d, managed_inventory_dn(SRC))
    assert one(inv, "ciamInventoryState") == "incomplete"
    assert values(inv, "ciamInventoryProblem") == (
        "the certificate listing is incomplete (a page isn't one, or the next page wasn't read)",
        "versions of 1 certificate(s) not all listed",
        "1 certificate version(s) not read (only the thumbprint and validity are known)",
        "policies of 1 certificate(s) not read (how the vault manages them is unknown)")
    old = _managed(d, f"sp-signing/{V1}")
    assert one(old, "ciamThumbprint") == pem_thumbprint(PEMS[V1]) and "ciamSubject" not in old.attrs
    assert one(old, "ciamNotAfter") == "20261130000000Z"
    assert "ciamManagement" not in _managed(d, f"login-tls/{V4}").attrs


def test_a_refused_listing_is_denied_with_what_to_grant():
    files = {page_path(SRC, 0): json.dumps({"Vault": VAULT, "error": {"code": "Forbidden", "message": "denied"}})}
    d = _imported(_record(), files)
    inv = get(d, managed_inventory_dn(SRC))
    assert one(inv, "ciamInventoryState") == "denied"
    assert values(inv, "ciamInventoryProblem") == (f"the listing of the vault's certificates was refused (denied): "
                                                   f"{GRANT}",)
    assert "Key Vault Reader" in GRANT and "not Key Vault Certificate User" in GRANT


def test_disabled_versions_unread_contacts_and_the_policys_words():
    files = export(**{versions_path(SRC, "login-tls", 0): json.dumps({"value": [_item("login-tls", V4, False)]})})
    del files[version_path(SRC, "login-tls", V4)], files[vault_path(SRC, "contacts")]
    imp = read_keyvault_certificates(files, _record(), (), AT)
    assert imp.notices[-1] == (f"{SRC}: the vault's certificate contacts weren't read (none set, or the identity lacks "
                               "managecontacts): who it notifies is unknown")
    d = after_import(_record(), imp)
    assert one(_managed(d, f"login-tls/{V4}"), "ciamObjectState") == "disabled"
    assert "ciamManagerContact" not in _managed(d, f"sp-signing/{V2}").attrs
    policy = json.loads(_policy("Self", ("autoRenew", {"lifetime_percentage": 80}),
                                ("EmailContacts", {"days_before_expiry": 30}), ("EmailContacts", {})))
    assert lifetime_actions(policy) == (("autoRenew", "80% of its lifetime"),
                                        ("EmailContacts", "30 days before expiry"), ("EmailContacts", None))
    assert management(policy) == "enrolled" and management(None) is None
    assert authority(policy, {}) == "Self" and authority(None, {}) is None
    assert pending_problems({"status": "inProgress"}) == () and pending_problems(None) == ()
    assert pending_problems({"status": "canceled"}) == ("the pending request canceled",)


def test_ids_thumbprints_and_times():
    assert id_parts(f"{VAULT}/certificates/sp-signing/{V1}") == ("sp-signing", V1)
    assert id_parts(f"{VAULT}/certificates/sp-signing") == ("sp-signing", None)
    assert id_parts(f"{VAULT}/secrets/sp-signing") is None and id_parts(None) is None
    assert thumbprint(_x5t(PEMS[V1])) == pem_thumbprint(PEMS[V1]) and thumbprint("abc") is None
    assert epoch_time(_epoch("2026-11-30")) == "20261130000000Z" and epoch_time(True) is None


def test_the_export_needs_a_date_and_names_what_it_holds():
    assert read_keyvault_certificates(export(), _record(), (), None).notices == (
        "an inventory is dated: give --at (when the vault was read)",)
    assert sources(export()) == (SRC,)
    assert read_keyvault_certificates({}, _record(), (), AT).notices[-1].startswith("no listings")
    assert KEYVAULT_CERTIFICATES in ADAPTER.importers and KEYVAULT_COLLECTOR in ADAPTER.collectors
    assert isinstance(read_keyvault_certificates(export(), _record(), (), AT), Imported)


# ------------------------------------------------------------------ the collector
SOURCE = {"ciamBindingRole": "collect-keyvault", "ciamImporter": "azure/keyvault-certificates",
          "ciamSourceRef": VAULT}


def _alpha(**over):
    _, alpha, _ = model(alpha=(entry(ALPHA, SRC, "ciamCollectionSource", **{**SOURCE, **over}),))
    return alpha


def _argv(call):
    return call.argv[call.argv.index("--url") + 1], call.argv[call.argv.index("--resource") + 1]


def test_the_collector_lists_then_reads_each_certificate_with_gets_only():
    m = _alpha()
    first = dict(keyvault_steps(m.d, m, {}, {}))
    assert list(first) == [page_path(SRC, 0), vault_path(SRC, "contacts"), vault_path(SRC, "issuers")]
    call = first[page_path(SRC, 0)]
    assert isinstance(call, Command) and call.argv[:4] == ("az", "rest", "--method", "get")
    assert _argv(call) == (f"{VAULT}/certificates?api-version={API_VERSION}&includePending=true&maxresults=25",
                           "https://vault.azure.net")
    assert "Forbidden" in first[vault_path(SRC, "contacts")].absent
    done = {page_path(SRC, 0): _page([_item("sp-signing"), {"id": f"{VAULT}/certificates/new-one"}],
                                     f"{VAULT}/certificates?api-version={API_VERSION}&$skiptoken=p2")}
    second = dict(keyvault_steps(m.d, m, done, {}))
    assert _argv(second[page_path(SRC, 1)])[0].endswith("$skiptoken=p2")
    assert _argv(second[versions_path(SRC, "sp-signing", 0)])[0] == (
        f"{VAULT}/certificates/sp-signing/versions?api-version={API_VERSION}&maxresults=25")
    assert _argv(second[policy_path(SRC, "sp-signing")])[0] == (
        f"{VAULT}/certificates/sp-signing/policy?api-version={API_VERSION}")
    assert second[pending_path(SRC, "sp-signing")].absent == ("Not Found", "NotFound")
    assert not any("new-one" in p for p in second)            # pending only: no version to read yet
    done = {**done, versions_path(SRC, "sp-signing", 0): export()[versions_path(SRC, "sp-signing", 0)]}
    third = dict(keyvault_steps(m.d, m, done, {}))
    assert _argv(third[version_path(SRC, "sp-signing", V1)])[0] == (
        f"{VAULT}/certificates/sp-signing/{V1}?api-version={API_VERSION}")
    elsewhere = {page_path(SRC, 0): _page([], "https://attacker.example/certificates?$skiptoken=x")}
    assert page_path(SRC, 1) not in dict(keyvault_steps(m.d, m, elsewhere, {}))
    many = {page_path(SRC, 0): _page([_item("sp-signing")]),
            versions_path(SRC, "sp-signing", 0): json.dumps({"value": [
                {"id": f"{VAULT}/certificates/sp-signing/{n:032x}"} for n in range(2000)]})}
    assert sum(1 for p in dict(keyvault_steps(m.d, m, many, {})) if "/certificates/sp-signing/" in p) == DETAIL_CALLS


def test_answers_are_trimmed_to_what_the_importer_reads():
    page = json.loads(kept_page(VAULT, json.dumps({"value": [{**_item("sp-signing"), "tags": {"cc": "x"}}],
                                                   "nextLink": None})))
    assert page == {"Vault": VAULT, "value": [_item("sp-signing")], "nextLink": None}
    version = json.loads(kept_version(json.dumps({**json.loads(_version(V1)), "kid": f"{VAULT}/keys/sp-signing/x",
                                                  "sid": f"{VAULT}/secrets/sp-signing/x", "policy": {}, "tags": {}})))
    assert set(version) == {"id", "x5t", "cer", "attributes"}
    policy = json.loads(kept_policy(json.dumps({"key_props": {"exportable": True}, "secret_props": {"contentType": "x"},
                                                "issuer": {"name": "Self"}, "lifetime_actions": []})))
    assert policy == {"issuer": {"name": "Self"}, "lifetime_actions": []}
    pending = json.loads(kept_pending(json.dumps({"status": "failed", "csr": "MIIB", "request_id": "r",
                                                  "error": {"code": "c", "message": "m", "innererror": {}}})))
    assert pending == {"status": "failed", "error": {"code": "c", "message": "m"}}
    contacts = json.loads(kept_contacts(json.dumps({"contacts": [{"email": "a@x", "name": "A", "phone": "555"}]})))
    assert contacts == {"contacts": [{"email": "a@x", "name": "A"}]}
    assert kept_page(VAULT, "not json") == "not json" and kept_version("nope") == "nope"
    assert json.loads(kept_page(VAULT, json.dumps({"error": {"code": "Forbidden"}}))) == {
        "Vault": VAULT, "error": {"code": "Forbidden"}}


def test_the_sources_problems_and_clouds():
    assert vault_of(VAULT, "public") == (VAULT, "https://vault.azure.net")
    assert vault_of("https://KV-Gov.vault.usgovcloudapi.net/", "usgovernment") == (
        "https://kv-gov.vault.usgovcloudapi.net", "https://vault.usgovcloudapi.net")
    assert vault_of("https://kv-gov.vault.usgovcloudapi.net", "public") is None
    assert vault_of(f"{VAULT}/certificates", "public") is None and vault_of("http://kv.vault.azure.net", None) is None
    gov = _alpha(ciamSourceRef="https://kv-gov.vault.usgovcloudapi.net")
    assert keyvault_steps(gov.d, gov, {}, {}) == ()
    assert keyvault_problems(gov.d, gov, {}) == (
        f"collection source `{SRC}`: https://kv-gov.vault.usgovcloudapi.net names no vault of the public cloud "
        "(https://<vault>.vault.azure.net)",)
    assert keyvault_problems(None, _alpha(), {}) == ()
    assert KEYVAULT_COLLECTOR.importer == "keyvault-certificates" and KEYVAULT_COLLECTOR.verify is not None

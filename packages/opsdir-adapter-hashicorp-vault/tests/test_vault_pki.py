"""Vault PKI inventory (hashicorp-vault/pki): the importer reads a mount's answers into its CA (named after the default
issuer's CN, else the mount), revocation endpoints (the issuer's AIA overrides, else config/urls, template variables
filled or kept), roles as that CA's own templates (validity, usages, subject from the request, the ACL policies that
let them be requested: broad through default) and the certificates it keeps (facts from the public PEM, a revocation
unspecified); complete only for what Vault keeps (no_store roles, unread certificates or a missing listing leave it
incomplete; a refused listing denied). Directory-wide template imports keep the CA's roles; a role gone leaves the
record. The ACL policy reader follows Vault's priority matching; the collector makes only GETs, trims every answer and
reads nothing where no source names a mount."""
import datetime as dt
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import get, one, ou_entry, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.inventory import PRESENT
from opsdir.domains.pki.issued import REVOKED, SUPERSEDED, reconciled, template_entry, templates_group
from opsdir.domains.pki.naming import TEMPLATES, authority_dn, issued_inventory_dn, template_dn
from opsdir.domains.pki.templates import check_template_risk
from opsdir_adapter_hashicorp_vault.adapter import ADAPTER
from opsdir_adapter_hashicorp_vault.pki import PKI_IMPORTER, aia_endpoints, listing, mounts, read_pki
from opsdir_adapter_hashicorp_vault.pki_collect import (PKI_COLLECTORS, TOKEN_HEADER, mount_of, pki_steps,
                                                        source_problems, trimmed)
from opsdir_adapter_hashicorp_vault.policies import (BROAD_POLICY, RESTRICTED, UNKNOWN, enrollment, grants,
                                                     path_matches, policy_rules, role_paths)
from opsdir_adapter_hashicorp_vault.roles import max_validity_days, role_usages, subject_from_request
import mini_estate
from network_fixtures import ALPHA, entry, model
from support import after_import

AT = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)
AS_OF = dt.date(2026, 10, 1)
CA = "Example Aero CIAM Internal CA"
MOUNT = "pki-internal"
ISSUER = "6c1f0b0e-0000-4000-8000-000000000001"
SERVER, CLIENT = "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"
KEY = ec.generate_private_key(ec.SECP256R1())


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn, serial, start="2026-09-01", days=365, ca=False, usages=(ExtendedKeyUsageOID.SERVER_AUTH,)):
    begin = dt.datetime.fromisoformat(start).replace(tzinfo=dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(CA)).public_key(KEY.public_key())
         .serial_number(serial).not_valid_before(begin).not_valid_after(begin + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    b = b.add_extension(x509.ExtendedKeyUsage(list(usages)), critical=False) if usages else b
    return b.sign(KEY, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def _colons(serial):
    text = f"{serial:040x}"
    return ":".join(text[i:i + 2] for i in range(0, 40, 2))


CA_PEM = _cert(CA, 0x01, "2026-01-15", 3650, ca=True, usages=())
WEB, WEB_NEW, PORTAL, BOB = 0x5EB1, 0x5EB2, 0x7E57, 0xB0B
PEMS = {WEB: _cert("sso.lab.example-aero.test", WEB, "2026-09-01"),
        WEB_NEW: _cert("sso.lab.example-aero.test", WEB_NEW, "2026-09-20"),
        PORTAL: _cert("portal.lab.example-aero.test", PORTAL, "2026-09-10"),
        BOB: _cert("bob", BOB, "2026-09-12", 1, usages=(ExtendedKeyUsageOID.CLIENT_AUTH,))}
ROLES = {"web-server": {"max_ttl": 2592000, "server_flag": True, "client_flag": False, "allowed_domains":
                        ["lab.example-aero.test"], "no_store": False},
         "ciam-client": {"max_ttl": "24h", "server_flag": False, "client_flag": True, "allow_any_name": True,
                         "no_store": False}}
POLICIES = {"default": 'path "sys/capabilities-self" { capabilities = ["update"] }\n'
                       'path "pki-internal/issue/ciam-client" { capabilities = ["update"] }\n',
            "web-issuers": 'path "pki-internal/issue/*" {\n  capabilities = ["create", "update"]\n'
                           '  allowed_parameters = { "common_name" = [] }\n}\n'
                           'path "pki-internal/issue/ciam-client" { capabilities = ["deny"] }\n',
            "root": ""}


def answer(data):
    """A Vault answer as the API (and `vault read -format=json`) gives it."""
    return json.dumps({"request_id": "r-1", "lease_id": "", "data": data, "wrap_info": None, "warnings": None})


def export(roles=ROLES, certs=(WEB, WEB_NEW, PORTAL, BOB), revoked=(BOB,), issuer_urls=None, urls=None,
           drop=(), extra=None, policies=POLICIES):
    """A mount's export as the collector saves it (keys files of the API's data, the rest whole answers)."""
    at = lambda name: f"pki/{MOUNT}/{name}"       # noqa: E731
    files = {at("issuers.json"): answer({"keys": [ISSUER]}),
             at(f"issuers/{ISSUER}.json"): answer({"issuer_id": ISSUER, "issuer_name": "internal-2026",
                                                   "key_id": "k-1", "certificate": CA_PEM,
                                                   **(issuer_urls or {"crl_distribution_points": [],
                                                                      "ocsp_servers": [],
                                                                      "issuing_certificates": []})}),
             at("config/issuers.json"): answer({"default": ISSUER}),
             at("config/urls.json"): answer(urls or {
                 "crl_distribution_points": ["http://pki.lab.example-aero.test/v1/pki-internal/crl"],
                 "ocsp_servers": ["http://pki.lab.example-aero.test/v1/pki-internal/ocsp"],
                 "issuing_certificates": ["{{cluster_aia_path}}/issuer/{{issuer_id}}/der"],
                 "enable_templating": True}),
             at("config/cluster.json"): answer({"path": "https://vault.lab.example-aero.test:8200/v1/pki-internal",
                                                "aia_path": "http://pki.lab.example-aero.test/v1/pki-internal"}),
             at("config/crl.json"): answer({"disable": False, "ocsp_disable": False}),
             at("config/auto-tidy.json"): answer({"enabled": True, "tidy_cert_store": True, "safety_buffer": 259200}),
             at("roles.json"): json.dumps(sorted(roles)),
             **{at(f"roles/{n}.json"): answer(r) for n, r in roles.items()},
             at("certs.json"): answer({"keys": [_colons(s) for s in certs]}),
             **{at(f"certs/{_colons(s).replace(':', '-')}.json"): answer(
                 {"certificate": PEMS[s], "revocation_time": 1790000000 if s in revoked else 0,
                  "revocation_time_rfc3339": "2026-09-20T08:00:00.123456789Z" if s in revoked else "",
                  "revocation_reason": 0}) for s in certs},
             **({at("policies.json"): answer({"keys": sorted(policies)}),
                 **{at(f"policies/{n}.json"): answer({"name": n, "policy": p}) for n, p in policies.items()}}
                if policies is not None else {}),
             **(extra or {})}
    return {p: t for p, t in files.items() if p not in {at(x) for x in drop}}


def _record(*certificates):
    head = ("dn: ou=owners,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: owners\n",
            "dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n")
    return mini_estate.directory(tuple(parse("\n".join((*head, *certificates)))))


def _imported(d, files):
    return after_import(d, read_pki(files, d, (), AT))


def _facts(serial):
    from opsdir_adapter_x509.certificates import certificate_facts
    return certificate_facts(PEMS[serial])


def _recorded(cn, serial):
    f = _facts(serial)
    return (f"dn: cn={cn},ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
            f"objectClass: ciamCertificate\ncn: {cn}\nciamFingerprint: {f['sha256']}\nciamNotAfter: {f['not_after']}\n"
            f"ciamNotBefore: {f['not_before']}\nciamCertPurpose: tls-server\nciamSubject: {f['subject']}\n"
            f"ciamIssuer: CN={CA}\n")


def test_registered_beside_the_kv_inventory():
    assert [i.name for i in ADAPTER.importers] == ["kv-metadata", "pki"]
    assert [c.importer for c in ADAPTER.collectors] == ["kv-metadata", "pki"]
    assert ADAPTER.kind == "secret-store" and PKI_IMPORTER.name == "pki" and PKI_COLLECTORS[0].scope == "environment"


def test_a_mount_becomes_its_ca_endpoints_roles_and_inventory():
    d = _imported(_record(), export())
    ca = get(d, authority_dn(CA))
    assert one(ca, "ciamProviderRef") == MOUNT
    assert values(ca, "ciamTemplateName") == (f"{CA}/ciam-client", f"{CA}/web-server")
    ends = {one(e, "cn"): one(e, "ciamEndpointUrl") for e in d.entries.values() if e.dn.endswith(ca.dn)
            and e.dn != ca.dn}
    assert ends == {"crl-1": "http://pki.lab.example-aero.test/v1/pki-internal/crl",
                    "ocsp-1": "http://pki.lab.example-aero.test/v1/pki-internal/ocsp",
                    "ca-issuers-1": f"http://pki.lab.example-aero.test/v1/pki-internal/issuer/{ISSUER}/der"}
    inv = get(d, issued_inventory_dn(CA))
    assert (one(inv, "ciamInventoryState"), one(inv, "ciamProviderRef")) == ("complete", MOUNT)
    web = get(d, f"cn={_colons(WEB)},{inv.dn}")
    f = _facts(WEB)
    assert (one(web, "ciamSerialNumber"), one(web, "ciamFingerprint"), one(web, "ciamSubject"),
            one(web, "ciamNotAfter")) == ("5eb1", f["sha256"], "CN=sso.lab.example-aero.test", f["not_after"])
    assert one(web, "ciamTemplateName") is None and one(web, "ciamRequester") is None
    assert one(web, "ciamRevocationReason") is None
    bob = get(d, f"cn={_colons(BOB)},{inv.dn}")
    assert (one(bob, "ciamRevocationReason"), one(bob, "ciamRevokedAt")) == ("unspecified", "20260920080000Z")


def test_roles_are_the_cas_own_templates():
    d = _imported(_record(), export())
    web, client = get(d, template_dn(f"{CA}/web-server")), get(d, template_dn(f"{CA}/ciam-client"))
    assert one(web, "ciamTemplateAuthority") == authority_dn(CA)
    assert (one(web, "ciamMaxValidityDays"), values(web, "ciamExtendedKeyUsage")) == ("30", (SERVER,))
    assert (one(web, "ciamSubjectFromRequest"), one(web, "ciamApprovalRequired"),
            one(web, "ciamRequiredSignatures")) == ("TRUE", "FALSE", "0")
    assert (values(web, "ciamEnrollee"), one(web, "ciamEnrollmentScope")) == (("policy web-issuers",), RESTRICTED)
    assert (values(client, "ciamEnrollee"), one(client, "ciamEnrollmentScope")) == (("policy default",),
                                                                                    BROAD_POLICY)
    assert (one(client, "ciamMaxValidityDays"), values(client, "ciamExtendedKeyUsage")) == ("1", (CLIENT,))


def test_the_broad_client_role_is_an_action():
    d = _imported(_record(), export())
    found = check_template_risk(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF,
                                            {}, {}, ()))
    (action,) = found.actions
    assert f"`{CA}/ciam-client`" in action[1] and "policy default" in action[1] and f"{CA} issues from it" in action[1]


def test_record_certificates_reconcile_through_the_core():
    d = _imported(_record(_recorded("sso-tls-lab", WEB), _recorded("portal-lab", PORTAL),
                          _recorded("bob-client", BOB)), export())
    states = {r.cert.attrs["cn"][0]: r.state for r in reconciled(d, AS_OF)}
    assert states == {"sso-tls-lab": SUPERSEDED, "portal-lab": PRESENT, "bob-client": REVOKED}


def test_without_policies_who_may_request_is_unknown():
    files = export(policies=None)
    imported = read_pki(files, _record(), (), AT)
    d = after_import(_record(), imported)
    assert one(get(d, template_dn(f"{CA}/web-server")), "ciamEnrollmentScope") == UNKNOWN
    assert f"{CA}/web-server: who may request from it is unknown (the ACL policies weren't read)" in imported.notices


def test_what_vault_doesnt_keep_leaves_the_inventory_incomplete():
    roles = {**ROLES, "ephemeral": {"max_ttl": 3600, "no_store": True}}
    inv = lambda files: get(_imported(_record(), files), issued_inventory_dn(CA))       # noqa: E731
    stored = inv(export(roles=roles))
    assert one(stored, "ciamInventoryState") == "incomplete"
    assert values(stored, "ciamInventoryProblem") == (
        "role ephemeral keeps none of the certificates it issues (no_store): they can't be listed",)
    unread = inv(export(drop=(f"certs/{_colons(PORTAL).replace(':', '-')}.json",)))
    assert values(unread, "ciamInventoryProblem") == (f"1 listed certificate(s) not read or not a certificate: "
                                                       f"{_colons(PORTAL)}",)
    assert one(inv(export(drop=("certs.json",))), "ciamInventoryState") == "incomplete"
    refused = inv(export(extra={f"pki/{MOUNT}/certs.json": '{"errors":["1 error occurred:\\n\\t* permission '
                                                            'denied\\n\\n"]}'}))
    assert one(refused, "ciamInventoryState") == "denied"


def test_issuer_overrides_and_unfilled_templates():
    own = {"crl_distribution_points": ["http://crl.example.test/{{issuer_id}}.crl"], "ocsp_servers": [],
           "issuing_certificates": ["{{cluster_path}}/ca"], "enable_aia_url_templating": True}
    found = aia_endpoints(own, {"crl_distribution_points": ["http://ignored"]}, {"path": ""}, "abc")
    assert found == (("crl", 1, "http://crl.example.test/abc.crl", None),
                     ("ca-issuers", 1, "{{cluster_path}}/ca", "{{cluster_path}}/ca"))
    d = _imported(_record(), export(issuer_urls=own, extra={f"pki/{MOUNT}/config/cluster.json": answer({})}))
    kept = get(d, f"cn=ca-issuers-1,{authority_dn(CA)}")
    assert one(kept, "description") == "the CA's template: {{cluster_path}}/ca"


def test_without_a_default_issuer_certificate_the_ca_is_the_mount():
    files = export(drop=(f"issuers/{ISSUER}.json",))
    d = _imported(_record(), files)
    assert get(d, authority_dn(MOUNT)) is not None and get(d, authority_dn(CA)) is None


def test_directory_templates_keep_the_cas_roles_and_a_role_gone_leaves():
    d = _imported(_record(), export())
    d = after_import(d, Imported((ou_entry(TEMPLATES),), (templates_group(d, (template_entry(d, "WebServer"),)),), ()))
    assert get(d, template_dn("WebServer")) is not None
    assert get(d, template_dn(f"{CA}/web-server")) is not None
    d = _imported(d, export(roles={"web-server": ROLES["web-server"]}))
    assert get(d, template_dn(f"{CA}/ciam-client")) is None and get(d, template_dn("WebServer")) is not None
    unread = export(drop=("roles/web-server.json",))
    d = _imported(d, {**unread, f"pki/{MOUNT}/roles.json": json.dumps(["web-server"])})
    assert get(d, template_dn(f"{CA}/web-server")) is not None


def test_an_import_is_dated_and_names_an_empty_export():
    assert read_pki(export(), _record(), (), None).notices == ("an inventory is dated: give --at (when the mount was "
                                                               "read)",)
    assert read_pki({}, _record(), (), AT).notices == ("no PKI mounts (pki/<mount>/issuers.json, as `opsdir collect` "
                                                        "saves them)",)


def test_a_mounts_config_issuers_is_no_mount():
    assert mounts(export()) == (MOUNT,)
    assert mounts({"pki/team/config/issuers.json": "[]"}) == ("team/config",)


def test_listings_read_the_api_and_the_cli():
    assert listing(answer({"keys": ["a", "b"]})) == ("a", "b") == listing('["a", "b"]')
    assert listing("permission denied") is None and listing(answer({})) is None


# ------------------------------------------------------------------ roles and policies
def test_role_facts():
    assert max_validity_days({"max_ttl": 90000}) == (2, None)
    assert max_validity_days({"max_ttl": "720h"}) == (30, None)
    assert max_validity_days({"max_ttl": 0})[0] is None
    assert role_usages({"server_flag": True, "client_flag": True, "ext_key_usage": ["ExtKeyUsageCodeSigning",
                                                                                     "Bogus"],
                        "ext_key_usage_oids": ["1.2.3.4"]}) == ((SERVER, CLIENT, "1.3.6.1.5.5.7.3.3", "1.2.3.4"),
                                                                ("Bogus",))
    assert role_usages({}) == ((), ())
    assert subject_from_request({"allowed_domains": ["example.test"]})
    assert not subject_from_request({"allowed_domains_template": True,
                                     "allowed_domains": ["{{identity.entity.name}}.users.example.test"]})
    assert subject_from_request({"allowed_domains_template": True, "allow_any_name": True,
                                 "allowed_domains": ["{{identity.entity.name}}"]})


def test_policies_follow_vaults_priority_matching():
    rules = policy_rules(POLICIES["web-issuers"])
    assert rules == (("pki-internal/issue/*", ("create", "update")), ("pki-internal/issue/ciam-client", ("deny",)))
    assert grants(rules, "pki-internal/issue/web-server") and not grants(rules, "pki-internal/issue/ciam-client")
    assert grants((("pki/issue/*", ("update",)), ("pki/+/web", ("read",))), "pki/issue/web")
    assert not grants((("pki/+/web", ("update",)), ("pki/issue/w*", ("read",))), "pki/issue/web")
    assert policy_rules('{"path": {"pki/sign/+": {"capabilities": ["create"]}}}') == (("pki/sign/+", ("create",)),)
    assert policy_rules('path "pki/*" { policy = "write" }')[0][1][:3] == ("create", "read", "update")
    assert policy_rules('# path "x" {\npath "pki/*" {\n  capabilities = ["read"]') is None
    assert path_matches("pki/issue/{{identity.entity.name}}", "pki/issue/bob")
    assert not path_matches("pki/+", "pki/issue/x")
    paths = role_paths("pki", "web", ("default",))
    assert "pki/issuer/default/sign/web" in paths
    assert enrollment(None, paths) == ((), UNKNOWN, "the ACL policies weren't read")
    assert enrollment({"ops": None}, paths)[1:] == (UNKNOWN, "policies ops couldn't be read")
    assert enrollment({"root": (("*", ("sudo", "update")),)}, paths) == ((), RESTRICTED, None)


# ------------------------------------------------------------------ the collector
SOURCE = {"ciamBindingRole": "collect-pki", "ciamImporter": "hashicorp-vault/pki",
          "ciamSourceRef": "https://vault.lab.example-aero.test:8200/pki-internal", "ciamCredentialRole": "pki-reader",
          "ciamCredentialScheme": "api-key"}


def _alpha(**over):
    _, alpha, _ = model(alpha=(entry(ALPHA, "collect-pki", "ciamCollectionSource", **{**SOURCE, **over}),
                               entry(ALPHA, "pki-reader", "ciamSecretRef", ciamBindingRole="pki-reader",
                                     ciamRefUri="fake://vault/pki-reader")))
    return alpha


def test_the_collector_lists_then_reads_each_item_with_gets_only():
    m = _alpha()
    first = dict(pki_steps(m.d, m, {}, {}))
    base = "https://vault.lab.example-aero.test:8200/v1/"
    assert {p: c.url for p, c in first.items()} == {
        "pki/pki-internal/issuers.json": f"{base}pki-internal/issuers?list=true",
        "pki/pki-internal/roles.json": f"{base}pki-internal/roles?list=true",
        "pki/pki-internal/certs.json": f"{base}pki-internal/certs?list=true",
        **{f"pki/pki-internal/config/{c}.json": f"{base}pki-internal/config/{c}"
           for c in ("urls", "issuers", "cluster", "crl", "auto-tidy")},
        "pki/pki-internal/policies.json": f"{base}sys/policies/acl?list=true"}
    call = first["pki/pki-internal/certs.json"]
    assert call.credential == ("api-key", "fake://vault/pki-reader", None, TOKEN_HEADER) and call.absent == (404,)
    assert first["pki/pki-internal/policies.json"].absent == (403, 404)
    files = export()
    done = {p: trimmed(("keys",))(files[p]) for p in ("pki/pki-internal/issuers.json", "pki/pki-internal/certs.json")}
    done["pki/pki-internal/roles.json"] = answer({"keys": ["web-server"]})
    second = dict(pki_steps(m.d, m, done, {}))
    assert second[f"pki/pki-internal/certs/{_colons(WEB).replace(':', '-')}.json"].url == \
        f"{base}pki-internal/cert/{_colons(WEB).replace(':', '%3A')}"
    assert second["pki/pki-internal/roles/web-server.json"].url == f"{base}pki-internal/roles/web-server"
    assert second[f"pki/pki-internal/issuers/{ISSUER}.json"].url == f"{base}pki-internal/issuer/{ISSUER}"


def test_answers_are_trimmed_to_what_the_importer_reads():
    m = _alpha()
    done = {"pki/pki-internal/certs.json": answer({"keys": [_colons(WEB)]})}
    call = dict(pki_steps(m.d, m, done, {}))[f"pki/pki-internal/certs/{_colons(WEB).replace(':', '-')}.json"]
    kept = json.loads(call.keep(answer({"certificate": PEMS[WEB], "revocation_time": 0, "ca_chain": [CA_PEM],
                                        "private_key": "never"})))
    assert kept == {"data": {"certificate": PEMS[WEB], "revocation_time": 0}}
    assert call.keep("not json") == "not json"


def test_bearer_tokens_and_the_sources_problems():
    m = _alpha(ciamCredentialScheme="bearer")
    assert dict(pki_steps(m.d, m, {}, {}))["pki/pki-internal/certs.json"].credential == (
        "bearer", "fake://vault/pki-reader", None)
    assert source_problems(m.d, _alpha(ciamCredentialScheme="basic"), {}) == (
        "collection source `collect-pki`: credential scheme `basic`: Vault takes a token: api-key (sent as "
        "X-Vault-Token) or bearer",)
    bare = _alpha(ciamSourceRef="https://vault.lab.example-aero.test:8200/")
    assert pki_steps(bare.d, bare, {}, {}) == ()
    assert source_problems(bare.d, bare, {}) == (
        "collection source `collect-pki`: https://vault.lab.example-aero.test:8200/ names no mount "
        "(https://<vault>:<port>/<mount>)",)
    assert mount_of("https://v:8200/pki/int") == ("https://v:8200", "pki/int")


def test_a_vault_used_only_for_secrets_is_never_read_for_pki():
    _, alpha, _ = model(alpha=(entry(ALPHA, "vault", "ciamSecretStore", ciamBindingRole="vault", ciamRefScheme="vault",
                                     ciamStoreEndpoint="https://vault.example.test:8200"),))
    assert pki_steps(alpha.d, alpha, {}, {}) == () and source_problems(alpha.d, alpha, {}) == ()

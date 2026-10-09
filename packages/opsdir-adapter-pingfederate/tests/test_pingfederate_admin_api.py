"""PingFederate rendered as Admin API requests (render target admin-api): every object in the order PingFederate needs
them, a PUT creatable by POST for objects and a PUT for settings; checked against the spec of the environment's
version, what it refuses named; integrations rendered from the settings PingFederate holds with the record's facts put
back (an edit in the record wins, a removed claim is gone everywhere, what the record can't hold is kept), and those the
record made itself given only harmless defaults, what is missing named; secrets as their environment's references."""
import importlib.util
import json
import pathlib
from types import SimpleNamespace

from opsdir.core.directory import get, make_entry
from opsdir_adapter_pingfederate.admin_api import OUTPUT, admin_api_files, rendered_bodies, requests
from opsdir_adapter_pingfederate.importer import read_export

_SPEC = importlib.util.spec_from_file_location("pf_import_fixtures",
                                               pathlib.Path(__file__).with_name("test_pingfederate_import.py"))
_FX = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_FX)
PORTAL, INTEGRATIONS, USER_SCHEMA = _FX.PORTAL, _FX.INTEGRATIONS, _FX.USER_SCHEMA


def _after():
    d = _FX._record()
    return _FX._after(d, read_export(_FX._files(), d, ()))


def _env(d, *versions, bindings=()):
    servers = tuple(make_entry(f"cn=pf-{n},env=prod,cloud=main,ou=environments,dc=ciam-ops", ("top", "ciamServer"),
                               {"cn": (f"pf-{n}",), "ciamServerRole": ("pf-admin",), "ciamProductVersion": (v,)})
                    for n, v in enumerate(versions))
    return SimpleNamespace(d=d, servers=servers, bindings=tuple(bindings))


def _doc(m):
    return json.loads(admin_api_files(m)[OUTPUT])


def _with(d, *entries):
    return d._replace(entries={**d.entries, **{e.norm: e for e in entries}})


def _changed(d, dn, **attrs):
    e = get(d, dn)
    return _with(d, make_entry(e.dn, e.classes, {**e.attrs, **{k: (v if isinstance(v, tuple) else (v,))
                                                                for k, v in attrs.items()}}))


def test_objects_in_the_order_pingfederate_needs_them_put_and_creatable_by_post():
    reqs = requests(_env(_after(), "PingFederate 12.1.4"))
    paths = [r.path for r in reqs]
    first = {kind: next(n for n, p in enumerate(paths) if p.startswith(kind))
             for kind in ("/dataStores", "/idp/adapters", "/oauth/accessTokenManagers", "/oauth/clients",
                          "/idp/spConnections", "/sp/idpConnections")}
    assert first["/dataStores"] < first["/idp/adapters"] < first["/oauth/accessTokenManagers"] < \
        first["/oauth/clients"] < first["/idp/spConnections"] < first["/sp/idpConnections"]
    store = reqs[0]
    assert (store.method, store.path, store.create_with) == ("PUT", "/dataStores/grants-db", "POST /dataStores")
    assert next(r for r in reqs if r.path == "/idp/spConnections/portal-sp").create_with == "POST /idp/spConnections"


def test_checked_against_the_spec_of_the_environments_version():
    d = _after()
    doc = _doc(_env(d, "PingFederate 12.1.4"))
    assert (doc["pingFederate"], doc["adminApi"]) == ("PingFederate 12.1.4", "12.1.0.4")
    assert "PUT /oauth/accessTokenManagers/default: $: lacks configuration" in doc["problems"]  # the fixture's is bare
    assert all(p.split(":", 1)[0].split(" ", 1)[0] in ("PUT", "POST") for p in doc["problems"]
               if not p.startswith("key pair "))                   # the fixture's key pairs name no key role
    old = _doc(_env(d, "PingFederate 11.3.2"))
    assert old["adminApi"] is None and old["problems"][-1] == \
        "no Admin API spec for PingFederate 11.3.2: the requests are not checked"
    mixed = _doc(_env(d, "PingFederate 12.1.4", "PingFederate 13.1.0"))
    assert mixed["problems"][0] == "servers run other versions too (PingFederate 13.1.0): checked against " \
                                   "PingFederate 12.1.4"
    assert rendered_bodies(admin_api_files(_env(d, "13.1"))[OUTPUT])["/dataStores"][0]["id"] == "grants-db"


def _portal(d):
    return next(b for b in rendered_bodies(admin_api_files(_env(d, "PingFederate 12.1.4"))[OUTPUT])["/idp/spConnections"]
                if b["id"] == "portal-sp")


def test_the_records_facts_win_over_the_held_settings_and_a_removed_claim_is_gone_everywhere():
    d = _after()
    held = _portal(d)
    assert held["credentials"]["signingSettings"]["signingKeyPairRef"] == {"id": "signing-2025"}   # PingFederate's own
    assert held["spBrowserSso"]["adapterMappings"][0]["attributeContractFulfillment"]["email"] == \
        {"source": {"id": "user-directory", "type": "LDAP_DATA_STORE"}, "value": "mail"}       # as PingFederate held it
    edited = _changed(d, PORTAL, ciamAcsUrl="https://new.example.test/acs", ciamSamlBinding="HTTP-Redirect")
    edited = edited._replace(entries={n: e for n, e in edited.entries.items()
                                      if n != f"cn=org,ou=claims,{PORTAL}".lower()})
    body = _portal(edited)
    acs = next(e for e in body["spBrowserSso"]["ssoServiceEndpoints"] if e["isDefault"])
    assert (acs["url"], acs["binding"]) == ("https://new.example.test/acs", "REDIRECT")
    names = [a["name"] for a in body["spBrowserSso"]["attributeContract"]["extendedAttributes"]]
    fulfilled = body["spBrowserSso"]["adapterMappings"][0]["attributeContractFulfillment"]
    assert "org" not in names and "org" not in fulfilled                       # removed in the record: gone
    assert "tier" in names and "tier" in fulfilled                             # the record can't hold it: kept
    assert body["credentials"] == held["credentials"]


def test_what_the_record_cant_say_about_a_client_is_kept_and_its_secret_is_its_roles_reference():
    d = _after()
    batch_dn = f"cn=batch,{INTEGRATIONS}"
    batch = lambda d, b=(): next(c for c in rendered_bodies(admin_api_files(_env(d, "12.1", bindings=b))[OUTPUT])[
        "/oauth/clients"] if c["clientId"] == "batch")                                         # noqa: E731
    assert batch(d)["grantTypes"] == ["CLIENT_CREDENTIALS", "EXTENSION"]       # EXTENSION: two standard grants
    assert batch(d)["clientAuth"] == {"secret": "${withheld}", "type": "SECRET"}
    d = _changed(d, batch_dn, pingfedCredentialRole="batch-client-secret")
    assert batch(d)["clientAuth"]["secret"] == "UNBOUND:batch-client-secret"
    vault = make_entry("cn=batch-secret,ou=bindings,env=prod,cloud=main,ou=environments,dc=ciam-ops",
                       ("top", "ciamSecretRef"), {"cn": ("batch-secret",), "ciamBindingRole": ("batch-client-secret",),
                                                  "ciamRefUri": ("vault://kv/pf/batch#secret",)})
    assert batch(d, (vault,))["clientAuth"]["secret"] == "${secret:vault://kv/pf/batch#secret}"


def test_integrations_the_record_made_get_harmless_defaults_and_whats_missing_is_named():
    d = _with(_after(), *(make_entry(dn, ("top", "ciamIntegration"), attrs) for dn, attrs in (
        (f"cn=new-sp,{INTEGRATIONS}", {"cn": ("new-sp",), "ciamProtocolType": ("saml2-sp",),
                                       "ciamEntityId": ("https://new.example.test/sp",),
                                       "ciamAcsUrl": ("https://new.example.test/acs",)}),
        (f"cn=new-idp,{INTEGRATIONS}", {"cn": ("new-idp",), "ciamProtocolType": ("saml2-idp",),
                                        "ciamEntityId": ("https://idp.partner.example/",)}))))
    doc = _doc(_env(d, "PingFederate 12.1.4"))
    sp = next(r["body"] for r in doc["requests"] if r["path"] == "/idp/spConnections/new-sp")
    assert sp["spBrowserSso"]["assertionLifetime"] == {"minutesBefore": 5, "minutesAfter": 5}
    assert not [p for p in doc["problems"] if p.startswith("PUT /idp/spConnections/new-sp")]
    assert "PUT /sp/idpConnections/new-idp: $.idpBrowserSso: lacks idpIdentityMapping" in doc["problems"]


def test_key_pairs_are_imported_first_from_where_the_environment_keeps_their_material():
    from opsdir.domains.pki.naming import CREDENTIALS
    d = _after()
    creds = (make_entry(f"cn=pf-signing-key,{CREDENTIALS}", ("top", "ciamCredential"), {
        "cn": ("pf-signing-key",), "ciamBindingRole": ("pf-signing-key",), "ciamCredentialType": ("private-key",),
        "ciamContinuity": ("carry-over",), "ciamMaterialFormat": ("pkcs12",),
        "ciamPasswordRole": ("pf-signing-key-password",)}),
             make_entry(f"cn=sso-tls-keystore,{CREDENTIALS}", ("top", "ciamCredential"), {
                 "cn": ("sso-tls-keystore",), "ciamBindingRole": ("sso-tls-keystore",), "ciamCredentialType": ("keystore",),
                 "ciamContinuity": ("per-environment",), "ciamMaterialFormat": ("pkcs12",)}))
    vault = tuple(make_entry(f"cn={r},ou=bindings,env=prod,cloud=main,ou=environments,dc=ciam-ops", ("top", "ciamSecretRef"),
                             {"cn": (r,), "ciamBindingRole": (r,), "ciamRefUri": (f"vault://kv/pf/{r}",)})
                  for r in ("pf-signing-key", "pf-signing-key-password"))
    doc = _doc(_env(_with(d, *creds), "PingFederate 12.1.4", bindings=vault))
    first, second = doc["requests"][:2]
    assert (first["method"], first["path"], "createWith" in first) == ("POST", "/keyPairs/signing/import", False)
    assert first["body"] == {"id": "signing-2025", "fileData": "${secret:vault://kv/pf/pf-signing-key}",
                             "format": "PKCS12", "password": "${secret:vault://kv/pf/pf-signing-key-password}"}
    assert second["path"] == "/keyPairs/sslServer/import" and second["body"]["fileData"] == "UNBOUND:sso-tls-keystore"
    assert second["body"]["password"] == "${withheld}"
    assert "key pair sso-tls: its PKCS#12 key (sso-tls-keystore) has no password role (ciamPasswordRole): its " \
           "password is withheld" in doc["problems"]
    assert not [p for p in doc["problems"] if p.startswith("POST /keyPairs")]       # valid against the 12.1 spec

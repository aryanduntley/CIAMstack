"""PingFederate data stores: imported from the bulk export (hosts that are service names become roles, the bind account
its consumer record, encrypted values and passwords withheld), rendered for each environment (hosts and secret
references from its bindings), imported back unchanged, and the planner's findings about what the target lacks."""
import datetime as dt
import json

import pytest

from opsdir.connectors.fixes import chosen
from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import ADAPTERS, core_fragments
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir_adapter_pingfederate.adapter import ADAPTER
from opsdir_adapter_pingfederate.checks import check_data_stores
from opsdir_adapter_pingfederate.naming import DATA_STORES, named
from opsdir_adapter_pingfederate.admin_api import OUTPUT as REQUESTS, rendered_bodies
from opsdir_adapter_pingfederate.render import render_env
from opsdir_adapter_pingfederate.schema import FRAGMENT
import mini_estate
from support import build_directory

REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BIND_DN = "uid=pf-svc,ou=service-accounts,dc=example,dc=test"
# alpha publishes the directory and the grant database and keeps the directory password; beta binds none of them
EXTRA = f"""dn: cn=svc-ldaps,ou=bindings,{ALPHA}
objectClass: top
objectClass: ciamServiceName
cn: svc-ldaps
ciamBindingRole: ds-ldaps-service
ciamFqdn: ldap.example.test
ciamPort: 1636
ciamTargetRole: ds

dn: cn=svc-grants-db,ou=bindings,{ALPHA}
objectClass: top
objectClass: ciamServiceName
cn: svc-grants-db
ciamBindingRole: pf-grants-db
ciamFqdn: grants.db.example.test
ciamPort: 5432
ciamTargetRole: db

dn: cn=secret-pf-ds,ou=bindings,{ALPHA}
objectClass: top
objectClass: ciamSecretRef
cn: secret-pf-ds
ciamBindingRole: pf-ds-bind-password
ciamRefUri: fake://secrets/alpha/pf-ds

dn: ou=consumers,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: consumers

dn: cn=pf-ds-svc,ou=consumers,dc=ciam-ops
objectClass: top
objectClass: ciamConsumer
cn: pf-ds-svc
ciamBindDn: {BIND_DN}
"""
STORES = [
    {"type": "LDAP", "id": "users", "name": "User directory", "ldapType": "PING_DIRECTORY",
     "hostnames": ["ldap.example.test:1636"], "useSsl": True, "userDN": BIND_DN, "maxConnections": 100,
     "encryptedPassword": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..not-a-real-value"},
    {"type": "JDBC", "id": "grants", "name": "Grant store", "driverClass": "org.postgresql.Driver",
     "connectionUrl": "jdbc:postgresql://grants.db.example.test:5432/pf?ssl=true", "userName": "pf",
     "encryptedPassword": "OBF:JWE:not-a-real-password-value"},
    {"type": "LDAP", "id": "legacy", "name": "Legacy directory", "hostnames": ["old-ds.corp.example.test:389"],
     "useSsl": False, "userDN": "cn=Directory Manager", "password": "not-a-real-password"},
    {"type": "CUSTOM", "id": "profile-api", "name": "Profile API",
     "pluginDescriptorRef": {"id": "com.example.pf.RestDataStore"},
     "configuration": {"fields": [{"name": "Base URL", "value": "https://profiles.example.test"},
                                  {"name": "API Token", "encryptedValue": "eyJhbGciOiJkaXIifQ..token"}]}}]
USERS, GRANTS, LEGACY, PROFILE = (named(DATA_STORES, n) for n in ("users", "grants", "legacy", "profile-api"))
SET_ROLE = tuple(parse(f"dn: {USERS}\nchangetype: modify\nreplace: pingfedCredentialRole\n"
                       "pingfedCredentialRole: pf-ds-bind-password\n-\n"))


def _bodies(d, env):
    """{resource type: [bodies]} of what PingFederate's render for an environment requests."""
    return rendered_bodies(render_env(env_model(d, env), None).get(REQUESTS, '{"requests": []}'))


def export(stores=STORES):
    return {"data.json": json.dumps({"metadata": {"pfVersion": "12.1.4.0"}, "operations": [
        {"operationType": "SAVE", "resourceType": "/dataStores", "items": stores}]})}


def records():
    return parse(mini_estate.LDIF + "\n" + EXTRA)


def imported(changes=(), files=None):
    """(the record after importing (then the changes), the import's change records, notices)."""
    base = build_directory(REGISTRY, records())
    import_changes, notices = preview_import(base, "pingfederate/bulk", files or export(), (ADAPTER,))
    return build_directory(REGISTRY, records(), (*import_changes, *changes)), import_changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def _config(e):
    return json.loads(one(e, "pingfedConfig"))


def test_registered_with_its_schema_render_and_check():
    assert ADAPTER in ADAPTERS and ADAPTER.schema.arc == "1.3.6.1.4.1.32473.3.4"
    assert ADAPTER.render_env is render_env and check_data_stores in ADAPTER.checks


def test_a_directory_store_names_its_role_port_and_consumer_and_withholds_its_password(after):
    d, notices = after
    s = get(d, USERS)
    assert (one(s, "pingfedStoreType"), one(s, "pingfedTargetRole"), one(s, "pingfedPort"), one(s, "pingfedConsumer")) \
        == ("LDAP", "ds-ldaps-service", "1636", "cn=pf-ds-svc,ou=consumers,dc=ciam-ops")
    config = _config(s)
    assert "hostnames" not in config and "encryptedPassword" not in config and config["password"] is None
    assert (config["maxConnections"], values(s, "pingfedWithheld")) == (100, ("/password",))
    assert "LDAP data store User directory: its credentials are withheld; set pingfedCredentialRole to the secret " \
           "role that holds them" in notices


def test_a_database_store_keeps_its_url_less_the_host(after):
    d, _ = after
    s = get(d, GRANTS)
    assert (one(s, "pingfedTargetRole"), one(s, "pingfedPort"), one(s, "pingfedConsumer")) == \
        ("pf-grants-db", "5432", None)
    assert _config(s)["connectionUrl"] == "jdbc:postgresql:///pf?ssl=true"


def test_a_fixed_host_and_plain_ldap_are_named(after):
    d, notices = after
    s = get(d, LEGACY)
    assert one(s, "pingfedTargetRole") is None and _config(s)["hostnames"] == ["old-ds.corp.example.test:389"]
    assert {"LDAP data store Legacy directory: binds as cn=Directory Manager, which no consumer records",
            "LDAP data store Legacy directory: reaches old-ds.corp.example.test, which is neither a service name nor "
            "a server in the record",
            "LDAP data store Legacy directory: no single service name for its hosts, so it reaches the same place "
            "from every environment",
            "LDAP data store Legacy directory: connects without TLS"} <= set(notices)


def test_a_custom_store_withholds_its_encrypted_fields(after):
    d, _ = after
    s = get(d, PROFILE)
    fields = _config(s)["configuration"]["fields"]
    assert fields == [{"name": "Base URL", "value": "https://profiles.example.test"}, {"name": "API Token", "value": None}]
    assert values(s, "pingfedWithheld") == ("/configuration/fields/1/value",)


def test_no_secret_is_read(after):
    d, _ = after
    dump = json.dumps([dict(e.attrs) for e in d.entries.values()])
    assert not any(v in dump for v in ("OBF:", "not-a-real", "eyJhbGci"))


def test_data_stores_render_per_environment():
    d, _, _ = imported(SET_ROLE)
    alpha = {s["id"]: s for s in _bodies(d, "alpha/prod")["/dataStores"]}
    beta = {s["id"]: s for s in _bodies(d, "beta/prod")["/dataStores"]}
    assert (alpha["users"]["hostnames"], alpha["users"]["password"], alpha["users"]["type"]) == \
        (["ldap.example.test:1636"], "${secret:fake://secrets/alpha/pf-ds}", "LDAP")
    assert (beta["users"]["hostnames"], beta["users"]["password"]) == \
        (["UNBOUND:ds-ldaps-service:1636"], "UNBOUND:pf-ds-bind-password")
    assert (alpha["grants"]["connectionUrl"], alpha["grants"]["password"]) == \
        ("jdbc:postgresql://grants.db.example.test:5432/pf?ssl=true", "${withheld}")
    assert alpha["legacy"]["hostnames"] == beta["legacy"]["hostnames"] == ["old-ds.corp.example.test:389"]
    assert alpha["profile-api"]["configuration"]["fields"][1]["value"] == "${withheld}"


def test_no_data_stores_render_nothing():
    d = build_directory(REGISTRY, records())
    assert render_env(env_model(d, "alpha/prod"), None) == {}


@pytest.mark.parametrize("env", ["alpha/prod", "beta/prod"])
def test_what_it_renders_imports_back_unchanged(env):
    d, _, _ = imported(SET_ROLE)
    rendered = {p: t for p, t in render_env(env_model(d, env), None).items() if p.endswith(".json")}
    again, _ = preview_import(d, "pingfederate/bulk", rendered, (ADAPTER,))
    assert again == ()


def plan(d, dst="beta/prod"):
    return check_data_stores(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, dst), None, dt.date(2026, 10, 1),
                                         {}, {}, ()))


def test_the_planner_names_what_the_target_lacks():
    d, _, _ = imported(SET_ROLE)
    f = plan(d)
    assert [t for _, t, _ in f.blockers] == [
        "Data store `grants` has withheld credentials but no credential role: nothing says which secret beta/prod "
        "gives it. Set pingfedCredentialRole.",
        "Data store `grants` needs role `pf-grants-db`, which beta/prod doesn't bind.",
        "Data store `legacy` has withheld credentials but no credential role: nothing says which secret beta/prod "
        "gives it. Set pingfedCredentialRole.",
        "Data store `profile-api` has withheld credentials but no credential role: nothing says which secret "
        "beta/prod gives it. Set pingfedCredentialRole.",
        "Data store `users` needs role `ds-ldaps-service`, which beta/prod doesn't bind.",
        "Data store `users` needs role `pf-ds-bind-password`, which beta/prod doesn't bind."]
    assert [t for _, t, _, _ in f.actions] == [
        "Data store `legacy` reaches a fixed host from every environment (no target role): confirm beta/prod can "
        "reach it, or record the system's service name.",
        "Data store `legacy` connects to the directory without TLS: turn on LDAPS or StartTLS."]


def test_a_fixed_host_is_recorded_as_an_external_system_and_the_next_import_names_its_role():
    d, _, _ = imported(SET_ROLE)
    fix = next(f for f in plan(d).fixes if f.key == "external-host:data-stores/legacy")
    with pytest.raises(ValueError, match="needs values: --input role=… \\(e.g. old-ds\\)"):
        chosen(fix)
    recorded = chosen(fix, given={"role": ("legacy-directory",)}).records
    assert recorded[-1].attrs == {"objectClass": ("top", "ciamExternalHost"),
                                  "cn": ("ext-old-ds-corp-example-test",), "ciamFqdn": ("old-ds.corp.example.test",),
                                  "ciamBindingRole": ("legacy-directory",)}
    again, changes, _ = imported((*SET_ROLE, *recorded))
    store = get(build_directory(REGISTRY, records(), (*changes, *SET_ROLE, *recorded,
                                                      *preview_import(again, "pingfederate/bulk", export(),
                                                                      (ADAPTER,))[0])), LEGACY)
    assert (one(store, "pingfedTargetRole"), one(store, "pingfedPort")) == ("legacy-directory", "389")
    assert "hostnames" not in _config(store)


def test_stores_the_target_can_serve_are_ok():
    d, _, _ = imported(SET_ROLE, export(STORES[:1]))
    f = plan(d, "alpha/prod")
    assert (f.blockers, f.actions, f.ok) == ((), (), ("PingFederate's 1 data store(s) reach their systems through "
                                                      "roles alpha/prod binds.",))


CORP_AD = {"type": "LDAP", "id": "corp-ad", "name": "Corporate AD", "useSsl": True, "userDN": "cn=pf,dc=corp",
           "hostnames": ["dc1.corp.example.test:636", "DC2.corp.example.test:3269", "dc1.corp.example.test:636"]}
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
BETA_AD = tuple(parse(f"dn: ou=bindings,{BETA}\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
                      f"ou: bindings\n\ndn: cn=ext-ad,ou=bindings,{BETA}\nchangetype: add\nobjectClass: top\n"
                      "objectClass: ciamExternalHost\ncn: ext-ad\nciamBindingRole: corp-ad\n"
                      "ciamFqdn: ad.beta.example.test\nciamPort: 636\n"))


def test_a_store_reaching_several_fixed_hosts_records_one_binding_each_and_renders_every_one_in_order():
    d, _, _ = imported((), export([CORP_AD]))
    (fix,) = (f for f in plan(d).fixes if f.key == "external-host:data-stores/corp-ad")
    assert fix.title == ("Record `dc1.corp.example.test`, `DC2.corp.example.test`, which data store `corp-ad` reaches, "
                         "as alpha/prod's hosts of a role")
    recorded = chosen(fix, given={"role": ("corp-ad",)}).records
    assert [r.attrs for r in recorded[-2:]] == [
        {"objectClass": ("top", "ciamExternalHost"), "cn": ("ext-dc1-corp-example-test",),
         "ciamFqdn": ("dc1.corp.example.test",), "ciamPort": ("636",), "ciamHostOrder": ("1",),
         "ciamBindingRole": ("corp-ad",)},
        {"objectClass": ("top", "ciamExternalHost"), "cn": ("ext-dc2-corp-example-test",),
         "ciamFqdn": ("DC2.corp.example.test",), "ciamPort": ("3269",), "ciamHostOrder": ("2",),
         "ciamBindingRole": ("corp-ad",)}]
    base = build_directory(REGISTRY, records(), (*recorded, *BETA_AD))
    changes, notices = preview_import(base, "pingfederate/bulk", export([CORP_AD]), (ADAPTER,))
    d = build_directory(REGISTRY, records(), (*recorded, *BETA_AD, *changes))
    store = get(d, named(DATA_STORES, "corp-ad"))
    assert (one(store, "pingfedTargetRole"), one(store, "pingfedPort")) == ("corp-ad", None)
    assert not any("corp-ad" in n and "neither" in n for n in notices)
    hosts = lambda env: _bodies(d, env)["/dataStores"][0]["hostnames"]  # noqa: E731
    assert hosts("alpha/prod") == ["dc1.corp.example.test:636", "DC2.corp.example.test:3269"]
    assert hosts("beta/prod") == ["ad.beta.example.test:636"]          # one host there: the default
    assert not any(f.key.startswith("external-host:") for f in plan(d).fixes)
    rendered = render_env(env_model(d, "alpha/prod"), None)
    assert preview_import(d, "pingfederate/bulk", {"data.json": json.dumps({
        "metadata": {"pfVersion": "12.1.4.0"}, "operations": [{"operationType": "SAVE", "resourceType": "/dataStores",
                                                               "items": rendered_bodies(rendered[REQUESTS])["/dataStores"]}]})},
                          (ADAPTER,))[0] == ()


def test_hosts_sharing_a_port_keep_it_on_the_store_and_a_partly_named_setting_gets_no_fix():
    shared = {**CORP_AD, "hostnames": ["dc1.corp.example.test:636", "dc2.corp.example.test:636"]}
    d, _, _ = imported((), export([shared]))
    (fix,) = (f for f in plan(d).fixes if f.key == "external-host:data-stores/corp-ad")
    recorded = chosen(fix, given={"role": ("corp-ad",)}).records
    assert all("ciamPort" not in r.attrs for r in recorded[-2:])
    base = build_directory(REGISTRY, records(), recorded)
    d = build_directory(REGISTRY, records(), (*recorded, *preview_import(base, "pingfederate/bulk", export([shared]),
                                                                          (ADAPTER,))[0]))
    assert one(get(d, named(DATA_STORES, "corp-ad")), "pingfedPort") == "636"
    assert _bodies(d, "alpha/prod")["/dataStores"][0][
        "hostnames"] == ["dc1.corp.example.test:636", "dc2.corp.example.test:636"]
    mixed = {**CORP_AD, "hostnames": ["ldap.example.test:1636", "dc9.corp.example.test:636"]}
    d, _, _ = imported((), export([mixed]))
    assert not any(f.key == "external-host:data-stores/corp-ad" for f in plan(d).fixes)

"""The PingIDM adapter: registered and chosen from data; an IDM project imported (managed objects, connectors linked
to the directory's service name and consumer record, mappings, schedules; other conf/ files and resolver/ properties
captured; scripts named
as code; credentials withheld); the record rendered back (connectors per environment), which imports again with no
change; and the planner's findings about what the deployment or the target lacks."""
import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from opsdir.connectors.fixes import chosen
from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import ADAPTERS, core_fragments
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir_adapter_pingidm.adapter import ADAPTER
from opsdir_adapter_pingidm.checks import check_idm
from opsdir_adapter_pingidm.naming import CONNECTORS, MAPPINGS, SCHEDULES, named
from opsdir_adapter_pingidm.render import render_env, render_neutral
from opsdir_adapter_pingidm.schema import FRAGMENT
import mini_estate
from support import build_directory

PROJECT = Path(__file__).resolve().parent / "idm-project"
REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BIND_DN = "uid=idm-sync,ou=service-accounts,dc=example,dc=test"
# alpha publishes the directory at ldap.example.test and keeps the connectors' secrets; beta binds neither
EXTRA = f"""dn: cn=svc-ldaps,ou=bindings,{ALPHA}
objectClass: top
objectClass: ciamServiceName
cn: svc-ldaps
ciamBindingRole: ds-ldaps-service
ciamFqdn: ldap.example.test
ciamPort: 1636
ciamTargetRole: ds

dn: cn=secret-idm-ds,ou=bindings,{ALPHA}
objectClass: top
objectClass: ciamSecretRef
cn: secret-idm-ds
ciamBindingRole: idm-ds-bind-password
ciamRefUri: fake://secrets/alpha/idm-ds

dn: ou=consumers,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: consumers

dn: cn=idm-sync,ou=consumers,dc=ciam-ops
objectClass: top
objectClass: ciamConsumer
cn: idm-sync
ciamBindDn: {BIND_DN}
"""
LDAP = named(CONNECTORS, "ldap")
HRDB = named(CONNECTORS, "hrdb")
SET_ROLE = tuple(parse(f"dn: {LDAP}\nchangetype: modify\nreplace: pingidmCredentialRole\n"
                       "pingidmCredentialRole: idm-ds-bind-password\n-\n"))


def files_of(root):
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def records():
    return parse(mini_estate.LDIF + "\n" + EXTRA)


def imported(changes=(), files=None):
    """(the record after importing (then the changes), the import's change records, notices)."""
    base = build_directory(REGISTRY, records())
    import_changes, notices = preview_import(base, "pingidm", files or files_of(PROJECT), (ADAPTER,))
    return build_directory(REGISTRY, records(), (*import_changes, *changes)), import_changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def test_registered_and_chosen_from_the_products_on_the_servers():
    assert ADAPTER in ADAPTERS and ADAPTER.schema.arc == "1.3.6.1.4.1.32473.3.2"
    server = lambda v: SimpleNamespace(attrs={"ciamProductVersion": (v,)})   # noqa: E731
    assert ADAPTER.applies(SimpleNamespace(servers=(server("PingIDM 7.5.0"),)))
    assert not ADAPTER.applies(SimpleNamespace(servers=(server("PingAM 7.5.1"),)))


def test_a_connector_to_the_directory_names_its_role_and_consumer_and_withholds_its_credentials(after):
    d, notices = after
    c = get(d, LDAP)
    assert (one(c, "pingidmTargetRole"), one(c, "pingidmConsumer")) == ("ds-ldaps-service",
                                                                         "cn=idm-sync,ou=consumers,dc=ciam-ops")
    props = json.loads(one(c, "pingidmConfig"))["configurationProperties"]
    assert "host" not in props and props["credentials"] is None and props["port"] == 1636
    assert values(c, "pingidmWithheld") == ("/configurationProperties/credentials",)
    assert "connector ldap: its credentials are withheld; set pingidmCredentialRole to the secret role that holds " \
           "them" in notices


def test_a_connector_to_a_host_the_record_doesnt_know_is_named(after):
    d, notices = after
    h = get(d, HRDB)
    assert one(h, "pingidmTargetRole") is None and values(h, "pingidmWithheld") == ("/configurationProperties/password",)
    assert "connector hrdb: no host that is a service name in the record, so it reaches the same place from every " \
           "environment" in notices


def test_mappings_schedules_and_the_rest_of_conf(after):
    d, notices = after
    m = get(d, named(MAPPINGS, "hr_managedUser"))
    assert (one(m, "pingidmPosition"), one(m, "pingidmSource"), one(m, "pingidmTarget")) == \
        ("0", "system/hrdb/employee", "managed/user")
    s = get(d, named(SCHEDULES, "reconcile-hr"))
    assert json.loads(one(s, "pingidmConfig"))["invokeContext"]["mapping"] == "hr_managedUser"
    assert one(get(d, "cn=idm.conf.audit.json,ou=config-files,dc=ciam-ops"), "ciamTargetRole") == "idm"
    assert "code, not config (record it as a bundle with `opsdir bundle`): script/onCreate-user.js" in notices


def test_resolver_properties_are_captured_too_and_other_files_named():
    boot = "openidm.port.http=8080\nopenidm.http.client.proxy.useSystem=true\nopenidm.keystore.password=changeit\n"
    d, _, notices = imported(files={**files_of(PROJECT), "resolver/boot.properties": boot, "logs/idm.log": "x"})
    f = get(d, "cn=idm.resolver.boot.properties,ou=config-files,dc=ciam-ops")
    assert (one(f, "ciamRepoPath"), one(f, "ciamFormat"), one(f, "ciamTargetRole")) == (
        "pingidm/resolver/boot.properties", "java-properties", "idm")
    assert "idm.resolver.boot.properties: value withheld, needs a secret reference: openidm.keystore.password" \
        in notices
    assert "not IDM configuration, not imported: logs/idm.log" in notices
    assert not any("resolver/boot.properties" in n and "not imported" in n for n in notices)


def test_connectors_render_per_environment(after):
    d, _ = after
    d = build_directory(REGISTRY, records(), (*imported()[1], *SET_ROLE))
    alpha = json.loads(render_env(env_model(d, "alpha/prod"), None)["pingidm/conf/provisioner.openicf-ldap.json"])
    beta = json.loads(render_env(env_model(d, "beta/prod"), None)["pingidm/conf/provisioner.openicf-ldap.json"])
    assert (alpha["configurationProperties"]["host"], alpha["configurationProperties"]["credentials"]) == \
        ("ldap.example.test", "${secret:fake://secrets/alpha/idm-ds}")
    assert (beta["configurationProperties"]["host"], beta["configurationProperties"]["credentials"]) == \
        ("UNBOUND:ds-ldaps-service", "UNBOUND:idm-ds-bind-password")
    assert alpha["connectorRef"]["connectorName"] == "org.identityconnectors.ldap.LdapConnector"


def test_what_it_renders_imports_back_unchanged():
    d, import_changes, _ = imported(SET_ROLE)
    files = {**render_neutral(d), **render_env(env_model(d, "alpha/prod"), None)}
    rendered = {p[len("pingidm/"):]: t for p, t in files.items()}
    again, _ = preview_import(d, "pingidm", rendered, (ADAPTER,))
    assert again == ()


def plan(d, dst="beta/prod"):
    return check_idm(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, dst), None, dt.date(2026, 9, 1),
                                 {}, {}, ()))


def test_the_planner_names_what_the_target_or_the_deployment_lacks():
    d, _, _ = imported()
    f = plan(d)
    assert [t for _, t, _ in f.blockers] == [
        "Connector `hrdb` has withheld credentials but no credential role: nothing says which secret beta/prod gives "
        "it. Set pingidmCredentialRole.",
        "Connector `ldap` has withheld credentials but no credential role: nothing says which secret beta/prod gives "
        "it. Set pingidmCredentialRole.",
        "Connector `ldap` needs role `ds-ldaps-service`, which beta/prod doesn't bind."]
    assert [t for _, t, _, _ in f.actions] == [
        "Connector `hrdb` reaches a fixed host from every environment (no target role): confirm beta/prod can reach "
        "it, or record the system's service name."]
    assert f.fixes == ()                                                  # the target binds no secret to offer
    secret = tuple(parse("dn: cn=idm-ds,ou=bindings,env=prod,cloud=beta,ou=environments,dc=ciam-ops\n"
                         "changetype: add\nobjectClass: top\nobjectClass: ciamSecretRef\ncn: idm-ds\n"
                         "ciamBindingRole: idm-ds-bind-password\nciamRefUri: fake://idm-ds\n"))
    fixes = plan(imported(secret)[0]).fixes
    assert [(x.key, [o.key for o in x.options]) for x in fixes] == [
        ("credential-role:connector/hrdb", ["idm-ds-bind-password"]),
        ("credential-role:connector/ldap", ["idm-ds-bind-password"])]
    ldap = chosen(fixes[1], "idm-ds-bind-password").records
    assert not any("`ldap` has withheld credentials" in t for _, t, _ in plan(imported((*secret, *ldap))[0]).blockers)
    broken = parse(f"dn: {named(MAPPINGS, 'hr_managedUser')}\nchangetype: modify\nreplace: pingidmTarget\n"
                   "pingidmTarget: managed/person\n-\n")
    d2, _, _ = imported(broken)
    assert "`hr_managedUser`: managed/person names managed object 'person', which the record doesn't have." in \
        [t for _, t, _ in plan(d2, "alpha/prod").blockers]

"""The PingAccess adapter: registered and chosen from the servers' products; Admin API reads imported (objects named by
name, references by ${pingaccess-id:...}, hosts that are roles in the record, the web session linked to its client,
secrets withheld whole); requests rendered per environment, which import again with no change; the planner's
findings."""
import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import ADAPTERS, core_fragments
from opsdir.connectors.roundtrip import read_back
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, make_directory, one, values
from opsdir.core.environment import as_seen, env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir_adapter_pingaccess.adapter import ADAPTER
from opsdir_adapter_pingaccess.checks import check_pingaccess
from opsdir_adapter_pingaccess.naming import entry_dn
from opsdir_adapter_pingaccess.render import OUTPUT, render_env, render_notes
from opsdir_adapter_pingaccess.schema import FRAGMENT
import mini_estate
from support import build_directory

ADMIN_API = Path(__file__).resolve().parent / "admin-api"
REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
PORTAL_WEB = "cn=portal-web,ou=integrations,dc=ciam-ops"


def server(env, name, role, version):
    return f"""dn: cn={name},{env}
objectClass: top
objectClass: ciamServer
cn: {name}
ciamServerRole: {role}
ciamHostname: {name}.example.test
ciamSubnet: cn=net,ou=bindings,{env}
ciamProductVersion: PingAccess {version}
"""


# alpha publishes the portal and its backend; beta publishes only the portal. Both run PingAccess (alpha 8.3.6, beta
# 9.1.1). The record has the client (registered for client_secret_basic) and the OpenID provider.
EXTRA = f"""dn: cn=svc-portal,ou=bindings,{ALPHA}
objectClass: top
objectClass: ciamServiceName
cn: svc-portal
ciamBindingRole: portal-service
ciamFqdn: portal.example.test
ciamPort: 443
ciamTargetRole: pa-engine

dn: cn=svc-portal-backend,ou=bindings,{ALPHA}
objectClass: top
objectClass: ciamServiceName
cn: svc-portal-backend
ciamBindingRole: portal-backend
ciamFqdn: portal-backend.example.test
ciamPort: 8443
ciamTargetRole: app

dn: cn=svc-portal,ou=bindings,{BETA}
objectClass: top
objectClass: ciamServiceName
cn: svc-portal
ciamBindingRole: portal-service
ciamFqdn: portal.beta.example.test
ciamPort: 443
ciamTargetRole: pa-engine

{server(ALPHA, "pa-admin-1", "pa-admin", "8.3.6")}
{server(ALPHA, "pa-engine-1", "pa-engine", "8.3.6")}
{server(BETA, "pa-admin-1", "pa-admin", "9.1.1")}
{server(BETA, "pa-engine-1", "pa-engine", "9.1.1")}
dn: cn=login,ou=identity-services,dc=ciam-ops
objectClass: top
objectClass: ciamIdentityService
cn: login
ciamBaseUrl: https://login.example.test
ciamOidcIssuer: https://login.example.test/as

dn: ou=integrations,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: integrations

dn: {PORTAL_WEB}
objectClass: top
objectClass: ciamIntegration
cn: portal-web
ciamProtocolType: oidc-client
ciamClientId: portal-web
ciamTokenAuthMethod: client_secret_basic
"""


def files_of(root):
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def records():
    return parse(mini_estate.LDIF + "\n" + EXTRA)


def imported(changes=(), files=None, importer="pingaccess/admin-api"):
    base = build_directory(REGISTRY, records(), ())
    import_changes, notices = preview_import(base, importer, files or files_of(ADMIN_API), (ADAPTER,))
    return build_directory(REGISTRY, records(), (*import_changes, *changes)), import_changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def config(d, dn):
    return json.loads(one(get(d, dn), "paConfig"))


NO_RECORDS = make_directory((), {}, ())


def test_registered_and_chosen_from_the_products_on_the_servers():
    assert ADAPTER in ADAPTERS and ADAPTER.schema.arc == "1.3.6.1.4.1.32473.3.5"
    host = lambda v: SimpleNamespace(attrs={"ciamProductVersion": (v,)})   # noqa: E731
    assert ADAPTER.applies(SimpleNamespace(servers=(host("PingAccess 9.1.1"),), d=NO_RECORDS))
    assert not ADAPTER.applies(SimpleNamespace(servers=(host("PingGateway 2026.9.0"),), d=NO_RECORDS))


def test_objects_are_named_by_name_and_name_each_other_by_reference(after):
    d, _ = after
    app = get(d, entry_dn("application", "portal"))
    assert one(app, "paContextRoot") == "/"
    held = config(d, app.dn)
    assert (held["siteId"], held["virtualHostIds"], held["webSessionId"], held["identityMappingIds"]) == (
        "${pingaccess-id:sites/portal-backend}", ["${pingaccess-id:virtualhosts/portal-service:443}"],
        "${pingaccess-id:webSessions/portal-session}", {"Web": "${pingaccess-id:identityMappings/portal-headers}"})
    assert held["policy"]["Web"] == [{"type": "Ruleset", "id": "${pingaccess-id:rulesets/staff-on-corp}"}]
    assert "id" not in held and "contextRoot" not in held
    assert set(values(app, "paUses")) == {entry_dn(k, n) for k, n in (
        ("site", "portal-backend"), ("virtual-host", "portal-service:443"), ("web-session", "portal-session"),
        ("identity-mapping", "portal-headers"), ("rule-set", "staff-on-corp"))}
    assert config(d, entry_dn("rule-set", "staff-on-corp"))["policy"] == [
        "${pingaccess-id:rules/staff-only}", "${pingaccess-id:rules/corp-network}"]
    docs = get(d, entry_dn("resource", "docs", application="portal"))
    assert json.loads(one(docs, "paConfig"))["policy"]["Web"] == [{"type": "Rule",
                                                                   "id": "${pingaccess-id:rules/corp-network}"}]


def test_hosts_that_are_roles_become_them_and_others_stay_fixed(after):
    d, notices = after
    site = get(d, entry_dn("site", "portal-backend"))
    assert (one(site, "paBackendRole"), one(site, "paPort")) == ("portal-backend", "8443")
    assert "targets" not in config(d, site.dn)
    assert config(d, entry_dn("site", "docs-cdn"))["targets"] == ["cdn.docs.example.net:443"]
    assert "sites docs-cdn: its targets are no single service name in the record, so it sends requests to the same " \
           "place from every environment" in notices
    vhost = get(d, entry_dn("virtual-host", "portal-service:443"))
    assert one(vhost, "paServiceRole") == "portal-service" and "host" not in config(d, vhost.dn)


def test_the_web_session_is_linked_to_its_client_and_provider_and_secrets_are_withheld(after):
    d, notices = after
    s = get(d, entry_dn("web-session", "portal-session"))
    assert (one(s, "paIntegration"), one(s, "paIssuer")) == (PORTAL_WEB, "https://login.example.test/as")
    held = config(d, s.dn)
    assert held["clientCredentials"] == {"credentialsType": "SECRET", "clientSecret": {"value": None}}
    assert values(s, "paWithheld") == ("/clientCredentials/clientSecret/value",)
    text = json.dumps({e.dn: dict(e.attrs) for e in d.entries.values()})
    assert "encryptedValue" not in text and "c2VjcmV0LWNpcGhlcnRleHQ=" not in text
    assert "webSessions portal-session: its secrets are withheld; set paCredentialRole to the secret role that " \
           "holds them" in notices
    assert "PingAccess 8.3.6" in notices and one(s, "paSourceVersion") == "8.3.6"


def test_environment_bound_objects_are_held_as_is_and_marked(after):
    d, notices = after
    key = get(d, entry_dn("held", "portal-tls", "keyPairs"))
    assert (one(key, "paObjectType"), one(key, "paEnvironmentBound")) == ("keyPairs", "TRUE")
    assert one(get(d, entry_dn("held", "Default", "availabilityProfiles")), "paEnvironmentBound") is None
    assert config(d, entry_dn("held", "Corporate", "trustedCertificateGroups"))["certificateIds"] == [
        "${pingaccess-id:certificates/corp-root}"]
    assert "not an Admin API response, not imported: README.txt" in notices
    mapping = get(d, entry_dn("identity-mapping", "portal-headers"))
    assert values(mapping, "paHeaderContract") == ()
    assert "identityMappings portal-headers: it sets header X-Portal-User, which no header contract in the record " \
           "names" in notices


def render(d, env):
    return json.loads(render_env(env_model(d, env), None)[OUTPUT])


def test_requests_render_per_environment_in_order_and_read_back_unchanged(after):
    d, _ = after
    alpha, beta = render(d, "alpha/prod"), render(d, "beta/prod")
    assert (alpha["pingAccess"], alpha["adminApi"], alpha["verified"]) == ("PingAccess 8.3.6", "v3", False)
    paths = [r["path"] for r in alpha["requests"]]
    assert "/keyPairs/${pingaccess-id:keyPairs/portal-tls}" not in paths     # environment-bound: never rendered
    order = [p.split("/")[1] for p in paths]
    assert order.index("rules") < order.index("rulesets") < order.index("sites") < order.index("applications")
    by_path = {r["path"]: r for r in alpha["requests"]}
    site = by_path["/sites/${pingaccess-id:sites/portal-backend}"]
    assert site["createWith"] == "POST /sites" and site["body"]["targets"] == ["portal-backend.example.test:8443"]
    assert by_path["/virtualhosts/${pingaccess-id:virtualhosts/portal-service:443}"]["body"]["host"] == \
        "portal.example.test"
    session = by_path["/webSessions/${pingaccess-id:webSessions/portal-session}"]["body"]
    assert session["clientCredentials"] == {"clientId": "portal-web", "credentialsType": "SECRET",
                                            "clientSecret": {"value": "${withheld}"}}
    resource = "/applications/${pingaccess-id:applications/portal}/resources"
    assert by_path[f"{resource}/${{pingaccess-id:{resource[1:]}/docs}}"]["createWith"] == f"POST {resource}"
    beta_site = next(r for r in beta["requests"] if r["path"] == "/sites/${pingaccess-id:sites/portal-backend}")
    assert beta_site["body"]["targets"] == ["UNBOUND:portal-backend:8443"]
    assert "role `portal-backend` isn't bound in beta/prod" in beta["problems"]
    (rt,) = read_back(d, ADAPTER, render_env(env_model(d, "alpha/prod"), None), (ADAPTER,))
    assert rt.files and rt.changes == ()


def test_render_notes_say_what_is_left_to_a_person(after):
    d, _ = after
    notes = render_notes(env_model(d, "beta/prod"), None)
    assert [(n.severity, n.subject) for n in notes if "unverified for PingAccess 9.1.1" in n.text] == [
        ("action", f"`{OUTPUT}`")]
    bound = {n.subject: n.text for n in notes}
    assert bound["environment-bound objects"] == (
        "not rendered: create certificates `corp-root`; trustedCertificateGroups `Corporate`; keyPairs `portal-tls`; "
        "engines `engine-1` in beta/prod before applying the requests")
    assert any(n.severity == "blocker" and n.entry == entry_dn("web-session", "portal-session") for n in notes)


def plan(d, src="alpha/prod", dst="beta/prod"):
    return check_pingaccess(PlanContext(d, env_model(d, src), env_model(d, dst), None, dt.date(2026, 9, 1),
                                        {}, {}, ()))


def test_the_planner_names_what_the_target_or_the_record_lacks(after):
    d, _ = after
    f = plan(d)
    blockers = [t for _, t, _ in f.blockers]
    assert "Site `portal-backend` sends requests to role `portal-backend`, which beta/prod doesn't bind." in blockers
    assert "`webSessions portal-session` holds secrets no credential role supplies (paCredentialRole): its request " \
           "carries ${withheld}." in blockers
    actions = [t for _, t, _, _ in f.actions]
    assert any(t.startswith("Site `docs-cdn` sends requests to `cdn.docs.example.net:443` from every environment")
               for t in actions)
    assert any(t.startswith("Identity mapping `portal-headers` sets header `X-Portal-User`") for t in actions)
    keys = {x.key for x in f.fixes}
    assert {"external-host:pa-site/docs-cdn", "header-contract:pa/portal-headers/X-Portal-User"} <= keys


def test_a_session_authenticating_otherwise_than_its_client_is_registered_is_a_blocker():
    public = parse(f"dn: {PORTAL_WEB}\nchangetype: modify\nreplace: ciamTokenAuthMethod\nciamTokenAuthMethod: none\n"
                   "-\nreplace: ciamPkceRequired\nciamPkceRequired: TRUE\n-\n")
    d, _, _ = imported(public)
    text = next(t for _, t, _ in plan(d, dst="alpha/prod").blockers if t.startswith("Web session"))
    assert "it authenticates to the token endpoint as client_secret_basic or client_secret_post (SECRET), but " \
           "integration `portal-web` is registered for none: the token request fails" in text
    assert "requires PKCE" not in text           # the session sends SHA256


def test_the_header_contract_fix_records_who_sets_and_trusts_the_header(after):
    d, _ = after
    fix = next(x for x in plan(d).fixes if x.key == "header-contract:pa/portal-headers/X-Portal-User")
    added = fix.records[-1]
    assert added.attrs["ciamSetByRole"] == ("pa-engine",) and added.attrs["ciamHeaderKind"] == ("identity",)
    assert added.attrs["ciamTrustedByRole"] == ("app",) and added.attrs["ciamHeaderValue"] == ("attribute sub",)


def test_a_target_running_no_engine_leaves_the_applications_unprotected(after):
    d, _ = after
    no_engine = parse(f"dn: cn=pa-engine-1,{BETA}\nchangetype: delete\n")
    d2 = build_directory(REGISTRY, records(), (*imported()[1], *no_engine))
    assert "beta/prod runs no PingAccess engine (`pa-engine`): the 1 applications it protects would go unprotected." \
        in [t for _, t, _ in plan(d2).blockers]


def test_what_an_upgrade_touches():
    d, _, _ = imported()
    by = {c.has: c for c in ADAPTER.version_changes}
    assert by[">=8.2.1"].touches(d, None, "pa-engine") == ("portal-tls",)
    assert by[">=9.1"].touches is None and by[">=9.1"].effect == "action"


def test_the_logs_its_servers_write():
    """The server log on both roles, the admin API's audit on the admin node, the engines' audit logs (resources by
    their Audit setting, sideband only when it's on), as text under the install root's log/."""
    logs = {(s.server_role, s.path): (s.format, s.kind, s.requires) for s in ADAPTER.logs}
    assert {(r, p) for r, p in logs if p == "log/pingaccess.log"} == {("pa-admin", "log/pingaccess.log"),
                                                                      ("pa-engine", "log/pingaccess.log")}
    assert logs[("pa-admin", "log/pingaccess_api_audit.log")] == ("text", "admin", None)
    assert {p: k for (r, p), (_, k, _) in logs.items() if r == "pa-engine" and k == "audit"} == {
        "log/pingaccess_engine_audit.log": "audit", "log/pingaccess_agent_audit.log": "audit",
        "log/pingaccess_sideband_client_audit.log": "audit", "log/pingaccess_sideband_audit.log": "audit"}
    assert all("sideband.http.enabled" in logs[("pa-engine", p)][2]
               for p in ("log/pingaccess_sideband_client_audit.log", "log/pingaccess_sideband_audit.log"))
    assert all(s.on == "servers" and s.line_start is None and s.versions is None for s in ADAPTER.logs)


# ------------------------------------------------------------------ the neutral protected-application layer
APPS = "ou=protected-applications,dc=ciam-ops"
RULES = f"ou=access-rules,{APPS}"
CREW = f"cn=crew,{APPS}"
# an application recorded by hand (no product holds it), enforced by an agent alpha runs; beta has PingAccess take it
# over, and has the gateways (another role) take the portal over from PingAccess
TAKEN = f"""dn: {APPS}
objectClass: top
objectClass: organizationalUnit
ou: protected-applications

dn: {RULES}
objectClass: top
objectClass: organizationalUnit
ou: access-rules

dn: cn=crew-group,{RULES}
objectClass: top
objectClass: ciamObject
objectClass: ciamAccessRule
cn: crew-group
ciamEffect: allow
ciamWho: group cn=crew,ou=groups,dc=example,dc=test

dn: cn=no-contractors,{RULES}
objectClass: top
objectClass: ciamObject
objectClass: ciamAccessRule
cn: no-contractors
ciamEffect: deny
ciamWho: attribute employeeType=contractor

dn: {CREW}
objectClass: top
objectClass: ciamObject
objectClass: ciamProtectedApp
cn: crew
ciamBasePath: /crew/
ciamEnforcedByRole: old-agent
ciamPublishedAs: portal-service
ciamBackendRole: portal-backend
ciamBackendPort: 8443
ciamSignOn: form
ciamSignInAs: {PORTAL_WEB}
ciamIdleTimeout: 1800
ciamRuleRef: cn=no-contractors,{RULES}

dn: cn=pages,{CREW}
objectClass: top
objectClass: ciamObject
objectClass: ciamPathResource
cn: pages
ciamPathPattern: /pages/
ciamMatchKind: prefix
ciamRuleRef: cn=crew-group,{RULES}

dn: ou=overrides,{BETA}
objectClass: top
objectClass: organizationalUnit
ou: overrides

dn: cn=crew-enforcer,ou=overrides,{BETA}
objectClass: top
objectClass: ciamOverride
cn: crew-enforcer
ciamOverrides: {CREW}
ciamOverrideAttribute: ciamEnforcedByRole
ciamOverrideValue: pa-engine
"""
PORTAL_TO_GATEWAY = parse(f"""dn: cn=portal-enforcer,ou=overrides,{BETA}
changetype: add
objectClass: top
objectClass: ciamOverride
cn: portal-enforcer
ciamOverrides: cn=portal,{APPS}
ciamOverrideAttribute: ciamEnforcedByRole
ciamOverrideValue: ig
""")


def test_applications_resources_and_rules_are_projected_onto_the_neutral_layer(after):
    d, _ = after
    portal = get(d, f"cn=portal,{APPS}")
    assert (one(portal, "ciamBasePath"), one(portal, "ciamEnforcedByRole"), values(portal, "ciamPublishedAs"),
            one(portal, "ciamBackendRole"), one(portal, "ciamBackendPort"), one(portal, "ciamSignOn"),
            one(portal, "ciamSignInAs"), one(portal, "ciamServedBy"), one(portal, "ciamMaxSessionTime"),
            values(portal, "ciamRuleRef"), one(portal, "ciamProjectedFrom")) == (
        "/", "pa-engine", ("portal-service",), "portal-backend", "8443", "oidc", PORTAL_WEB,
        "cn=login,ou=identity-services,dc=ciam-ops", "14400", (f"cn=staff-on-corp,{RULES}",),
        entry_dn("application", "portal"))
    docs = get(d, f"cn=docs,cn=portal,{APPS}")
    assert (values(docs, "ciamPathPattern"), one(docs, "ciamMatchKind"), values(docs, "ciamHttpMethod"),
            one(docs, "ciamAccessMode")) == (("/docs/*",), "wildcard", ("GET",), "unprotected")
    assert values(get(d, f"cn=Root Resource,cn=portal,{APPS}"), "ciamHttpMethod") == ()      # '*': every method
    rule_set = get(d, f"cn=staff-on-corp,{RULES}")
    assert (one(rule_set, "ciamRuleMatch"), values(rule_set, "ciamIncludesRule")) == (
        "all", (f"cn=staff-only,{RULES}", f"cn=corp-network,{RULES}"))
    assert values(get(d, f"cn=staff-only,{RULES}"), "ciamWho") == ("attribute groups=staff",)
    assert values(get(d, f"cn=corp-network,{RULES}"), "ciamWho") == ("network 10.0.0.0/8",)


def seen_render(d, env):
    """The requests as `opsdir render` gives them: the environment's overrides applied."""
    return json.loads(render_env(as_seen(env_model(d, env)), None)[OUTPUT])


def taken_over(changes=()):
    base = build_directory(REGISTRY, parse(mini_estate.LDIF + "\n" + EXTRA + "\n" + TAKEN), ())
    import_changes, _ = preview_import(base, "pingaccess/admin-api", files_of(ADMIN_API), (ADAPTER,))
    return build_directory(REGISTRY, parse(mini_estate.LDIF + "\n" + EXTRA + "\n" + TAKEN),
                           (*import_changes, *changes))


def test_an_application_taken_over_renders_from_the_neutral_layer_where_pingaccess_enforces_it():
    d = taken_over()
    alpha = {r["path"]: r["body"] for r in seen_render(d, "alpha/prod")["requests"]}
    assert not any("crew" in p for p in alpha)                       # alpha keeps its agent: nothing of it here
    beta = {r["path"]: r["body"] for r in seen_render(d, "beta/prod")["requests"]}
    app = beta["/applications/${pingaccess-id:applications/crew}"]
    assert (app["contextRoot"], app["siteId"], app["virtualHostIds"], app["webSessionId"]) == (
        "/crew/", "${pingaccess-id:sites/crew-backend}", ["${pingaccess-id:virtualhosts/portal-service:443}"],
        "${pingaccess-id:webSessions/crew-session}")
    assert app["policy"]["Web"] == [{"type": "Rule", "id": "${pingaccess-id:rules/no-contractors}"}]
    assert beta["/rules/${pingaccess-id:rules/no-contractors}"]["configuration"] == {
        "attributeName": "employeeType", "attributeValue": "contractor", "negate": True}
    assert "/rules/${pingaccess-id:rules/crew-group}" not in beta                # a directory group: not testable
    session = beta["/webSessions/${pingaccess-id:webSessions/crew-session}"]
    assert (session["clientCredentials"]["clientId"], session["idleTimeoutInMinutes"]) == ("portal-web", 30)
    resource = "/applications/${pingaccess-id:applications/crew}/resources"
    pages = beta[f"{resource}/${{pingaccess-id:{resource[1:]}/pages}}"]
    assert pages["pathPatterns"] == [{"type": "WILDCARD", "pattern": "/pages/*"}] and pages["methods"] == ["*"]
    notes = {(n.severity, n.text.split(",")[0]) for n in render_notes(as_seen(env_model(d, "beta/prod")), None)
             if n.subject == "protected application `crew`"}
    assert ("blocker", "rule `crew-group` admits `group cn=crew") in notes
    assert ("action", "users sign in with form today; PingAccess signs them in through the identity service") in notes


def test_an_application_another_role_enforces_is_left_out_and_still_reads_back():
    d = taken_over(PORTAL_TO_GATEWAY)
    beta = [r["path"] for r in seen_render(d, "beta/prod")["requests"]]
    assert "/applications/${pingaccess-id:applications/portal}" not in beta
    assert "/applications/${pingaccess-id:applications/portal}" in [r["path"] for r in seen_render(d, "alpha/prod")
                                                                     ["requests"]]
    seen = as_seen(env_model(d, "beta/prod"))
    (rt,) = read_back(seen.d, ADAPTER, render_env(seen, None), (ADAPTER,), environment="beta/prod")
    assert rt.files and rt.changes == ()


def test_pingaccess_offers_to_protect_what_nothing_in_the_target_would():
    d = build_directory(REGISTRY, parse(mini_estate.LDIF + "\n" + EXTRA + "\n" + TAKEN.split(f"dn: ou=overrides")[0]
                                        + "\n" + server(ALPHA, "agent-1", "old-agent", "8.3.6")), ())
    fix = next(x for x in plan(d).fixes if x.key == "protect:pa/crew")
    assert fix.records[-1].attrs["ciamOverrideValue"] == ("pa-engine",)

"""The PingGateway adapter: registered and chosen from data; a gateway configuration imported (routes linked to the
application's backend role, the integration whose client they use and the OpenID provider they trust; config/
captured); routes rendered per environment, which import again with no change; and the planner's findings."""
import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import ADAPTERS, core_fragments
from opsdir.connectors.roundtrip import read_back
from opsdir.core.contract import PlanContext
from opsdir.core.directory import children, get, make_directory, one, rdn_value, values
from opsdir.core.environment import as_seen, env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir_adapter_pinggateway.adapter import ADAPTER
from opsdir_adapter_pinggateway.checks import check_routes
from opsdir_adapter_pinggateway.naming import route_dn
from opsdir_adapter_pinggateway.render import render_env
from opsdir_adapter_pinggateway.schema import FRAGMENT
import mini_estate
from support import build_directory

CONFIG = Path(__file__).resolve().parent / "gateway-config"
REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
LOGIN = "cn=login,ou=identity-services,dc=ciam-ops"
PORTAL_WEB = "cn=portal-web,ou=integrations,dc=ciam-ops"
# alpha publishes the portal's backend; beta doesn't. The record has the client and the OpenID provider.
EXTRA = f"""dn: cn=svc-portal-backend,ou=bindings,{ALPHA}
objectClass: top
objectClass: ciamServiceName
cn: svc-portal-backend
ciamBindingRole: portal-backend
ciamFqdn: portal-backend.example.test
ciamPort: 8443
ciamTargetRole: web

dn: {LOGIN}
objectClass: top
objectClass: ciamIdentityService
cn: login
ciamBaseUrl: https://login.example.test
ciamOidcIssuer: https://login.example.test/am/oauth2

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
"""


def files_of(root):
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def records():
    return parse(mini_estate.LDIF + "\n" + EXTRA)


def imported(changes=(), files=None, extra=()):
    base = build_directory(REGISTRY, records(), extra)
    import_changes, notices = preview_import(base, "pinggateway", files or files_of(CONFIG), (ADAPTER,))
    return build_directory(REGISTRY, records(), (*extra, *import_changes, *changes)), import_changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


NO_RECORDS = make_directory((), {}, ())        # an environment's directory with nothing in it


def test_registered_and_chosen_from_the_products_on_the_servers():
    assert ADAPTER in ADAPTERS and ADAPTER.schema.arc == "1.3.6.1.4.1.32473.3.3"
    server = lambda v: SimpleNamespace(attrs={"ciamProductVersion": (v,)})   # noqa: E731
    assert ADAPTER.applies(SimpleNamespace(servers=(server("PingGateway 2024.11.0"),), d=NO_RECORDS))
    assert not ADAPTER.applies(SimpleNamespace(servers=(server("PingIDM 7.5.0"),), d=NO_RECORDS))


def test_a_route_names_its_backend_role_client_and_provider(after):
    d, _ = after
    r = get(d, route_dn("portal"))
    assert (one(r, "pinggwBackendRole"), one(r, "pinggwBackendScheme"), one(r, "pinggwIntegration"),
            one(r, "pinggwIssuer")) == ("portal-backend", "https", PORTAL_WEB, "https://login.example.test/am/oauth2")
    assert "baseURI" not in json.loads(one(r, "pinggwConfig"))


def test_a_route_to_a_host_the_record_doesnt_know_keeps_it_and_says_so(after):
    d, notices = after
    assert json.loads(one(get(d, route_dn("docs")), "pinggwConfig"))["baseURI"] == "https://docs.internal.example.test"
    assert "route docs: its backend is no service name in the record, so it goes to the same place from every " \
           "environment" in notices
    assert one(get(d, "cn=ig.config.admin.json,ou=config-files,dc=ciam-ops"), "ciamTargetRole") == "ig"
    assert "not gateway configuration, not imported: README.txt" in notices


def test_routes_render_per_environment_and_import_back_unchanged(after):
    d, _ = after
    alpha = json.loads(render_env(env_model(d, "alpha/prod"), None)["pinggateway/routes/portal.json"])
    beta = json.loads(render_env(env_model(d, "beta/prod"), None)["pinggateway/routes/portal.json"])
    assert (alpha["baseURI"], beta["baseURI"]) == ("https://portal-backend.example.test:8443", "UNBOUND:portal-backend")
    (rt,) = read_back(d, ADAPTER, render_env(env_model(d, "alpha/prod"), None), (ADAPTER,))
    assert rt.files and rt.changes == ()


def plan(d, dst="beta/prod"):
    return check_routes(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, dst), None, dt.date(2026, 9, 1),
                                    {}, {}, ()))


def test_the_planner_names_what_the_target_or_the_record_lacks(after):
    d, _ = after
    f = plan(d)
    assert [t for _, t, _ in f.blockers] == [
        "Route `portal` protects role `portal-backend`, which beta/prod doesn't bind."]
    assert [t for _, t, _, _ in f.actions] == [
        "Route `docs` sends requests to a fixed backend from every environment (no backend role): confirm beta/prod "
        "can reach it, or record the application's service name."]
    no_provider = parse(f"dn: {LOGIN}\nchangetype: modify\nreplace: ciamOidcIssuer\n"
                        "ciamOidcIssuer: https://login.example.test/elsewhere\n-\n")
    d2, _, _ = imported(no_provider)
    assert "Route `portal` can't sign users in: it trusts https://login.example.test/am/oauth2, which is no identity " \
           "service's issuer in the record." in [t for _, t, _ in plan(d2, "alpha/prod").blockers]


def test_what_an_upgrade_of_the_gateway_touches_in_its_routes():
    legacy = json.dumps({"name": "legacy", "baseURI": "http://legacy.example.test", "handler": {"type": "Chain",
        "config": {"filters": [{"type": "OAuth2ClientFilter", "config": {}},
                               {"type": "ScriptableFilter", "config": {"file": "check.groovy", "type":
                                                                       "application/x-groovy"}}],
                   "handler": {"type": "ReverseProxyHandler", "config": {"protocolVersion": "HTTP/1.1"}}}},
        "heap": [{"name": "uma", "type": "UmaService", "config": {}}]})
    d, _, _ = imported(files={**files_of(CONFIG), "routes/legacy.json": legacy})
    by = {c.change.split(" ")[0] + c.has: c for c in ADAPTER.version_changes}
    touched = {k: (c.touches(d, None, "ig") if c.touches else None) for k, c in by.items()}
    assert touched == {"OAuth2ClientFilter>=7.2": ("legacy",), "scripts>=2023.6": ("legacy",),
                       "inline>=2024.3": None, "the>=2025.3": None, "issuer>=2025.3": ("portal",),
                       "the>=2026.3": None, "ClientHandler>=2026.9": ("docs", "portal"),
                       "UmaService>=2026.9": ("legacy",)}
    assert all(c.touches(d, None, "am") == () for c in ADAPTER.version_changes if c.touches)


# ------------------------------------------------------------------ the neutral protected-application layer
APPS = "ou=protected-applications,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
CREW = f"cn=crew,{APPS}"


def server(env, name, role):
    return f"dn: cn={name},{env}\nobjectClass: top\nobjectClass: ciamServer\ncn: {name}\nciamServerRole: {role}\n" \
           f"ciamHostname: {name}.example.test\nciamSubnet: cn=net,ou=bindings,{env}\n"


def override(env, name, entry, value):
    return f"dn: cn={name},ou=overrides,{env}\nobjectClass: top\nobjectClass: ciamOverride\ncn: {name}\n" \
           f"ciamOverrides: {entry}\nciamOverrideAttribute: ciamEnforcedByRole\nciamOverrideValue: {value}\n"


# an application recorded by hand, enforced by an agent alpha runs; beta runs gateways and publishes the crew portal
CREW_APP = f"""{server(ALPHA, "agent-1", "old-agent")}
{server(BETA, "ig-1", "ig")}
dn: cn=svc-crew,ou=bindings,{BETA}
objectClass: top
objectClass: ciamServiceName
cn: svc-crew
ciamBindingRole: crew-service
ciamFqdn: crew.example.test
ciamPort: 443
ciamTargetRole: ig

dn: cn=crew-app,ou=bindings,{BETA}
objectClass: top
objectClass: ciamExternalHost
cn: crew-app
ciamBindingRole: crew-app
ciamFqdn: crew-app.example.test
ciamPort: 8443

dn: ou=header-contracts,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: header-contracts

dn: cn=crew-user,ou=header-contracts,dc=ciam-ops
objectClass: top
objectClass: ciamHeaderContract
cn: crew-user
ciamHeaderName: X-Crew-User
ciamHeaderKind: identity
ciamSetByRole: old-agent
ciamHeaderValue: claim sub

dn: {APPS}
objectClass: top
objectClass: organizationalUnit
ou: protected-applications

dn: ou=access-rules,{APPS}
objectClass: top
objectClass: organizationalUnit
ou: access-rules

dn: cn=crew-staff,ou=access-rules,{APPS}
objectClass: top
objectClass: ciamObject
objectClass: ciamAccessRule
cn: crew-staff
ciamEffect: allow
ciamWho: attribute groups=crew

dn: {CREW}
objectClass: top
objectClass: ciamObject
objectClass: ciamProtectedApp
cn: crew
ciamBasePath: /crew/
ciamEnforcedByRole: old-agent
ciamPublishedAs: crew-service
ciamBackendRole: crew-app
ciamSignOn: oidc
ciamSignInAs: {PORTAL_WEB}
ciamServedBy: {LOGIN}
ciamIdleTimeout: 1800
ciamMaxSessionTime: 28800
ciamSetsHeader: cn=crew-user,ou=header-contracts,dc=ciam-ops
ciamRuleRef: cn=crew-staff,ou=access-rules,{APPS}

dn: cn=pages,{CREW}
objectClass: top
objectClass: ciamObject
objectClass: ciamPathResource
cn: pages
ciamPathPattern: /*
ciamMatchKind: wildcard
ciamHttpMethod: GET

dn: cn=public,{CREW}
objectClass: top
objectClass: ciamObject
objectClass: ciamPathResource
cn: public
ciamPathPattern: /public/
ciamMatchKind: prefix
ciamAccessMode: anonymous
"""
MOVED = f"dn: ou=overrides,{BETA}\nobjectClass: top\nobjectClass: organizationalUnit\nou: overrides\n\n" \
        + override(BETA, "crew-enforcer", CREW, "ig")


def with_crew(*extra):
    text = "\n".join((mini_estate.LDIF, EXTRA, CREW_APP, *extra))
    base = build_directory(REGISTRY, parse(text), ())
    import_changes, _ = preview_import(base, "pinggateway", files_of(CONFIG), (ADAPTER,))
    return build_directory(REGISTRY, parse(text), import_changes)


def test_routes_are_projected_onto_the_neutral_layer(after):
    d, notices = after
    portal = get(d, f"cn=portal,{APPS}")
    assert (one(portal, "ciamBasePath"), one(portal, "ciamEnforcedByRole"), one(portal, "ciamBackendRole"),
            one(portal, "ciamBackendTls"), one(portal, "ciamSignOn"), one(portal, "ciamSignInAs"),
            one(portal, "ciamServedBy"), one(portal, "ciamProjectedFrom")) == (
        "/", "ig", "portal-backend", "TRUE", "oidc", PORTAL_WEB, LOGIN, route_dn("portal"))
    (everything,) = children(d, portal.dn, "ciamPathResource")
    assert (rdn_value(everything), values(everything, "ciamPathPattern"), one(everything, "ciamMatchKind")) == (
        "all", ("/",), "prefix")
    assert one(get(d, f"cn=docs,{APPS}"), "ciamBasePath") == "/docs"


def seen(d, env):
    return as_seen(env_model(d, env))


def test_an_application_taken_over_renders_as_a_route_where_the_gateways_enforce_it():
    d = with_crew(MOVED)
    assert "pinggateway/routes/crew.json" not in render_env(seen(d, "alpha/prod"), None)
    route = json.loads(render_env(seen(d, "beta/prod"), None)["pinggateway/routes/crew.json"])
    assert route["condition"] == ("${find(request.uri.host, '^crew\\\\.example\\\\.test$') and "
                                  "find(request.uri.path, '^/crew(?:/|$)')}")
    assert route["baseURI"] == "https://crew-app.example.test:8443"
    assert route["session"] == {"type": "JwtSessionManager", "config": {"sessionTimeout": "1800 seconds"}}
    filters = route["handler"]["config"]["filters"]
    assert [f["type"] for f in filters] == ["ConditionalFilter", "AllowOnlyFilter", "ConditionEnforcementFilter",
                                            "HeaderFilter"]
    assert filters[0]["config"]["condition"] == "${not (find(request.uri.path, '^/crew/public/'))}"
    assert filters[0]["config"]["delegate"]["config"]["registrations"][0]["config"]["clientId"] == "portal-web"
    assert filters[1]["config"]["rules"] == [            # most specific first
        {"name": "public", "destination": {"paths": ["^/crew/public/"]}},
        {"name": "pages", "destination": {"paths": ["^/crew/.*$"], "methods": ["GET"]}}]
    assert filters[2]["config"]["condition"] == "${contains(contexts.oauth2Info.userInfo['groups'], 'crew')}"
    assert filters[3]["config"]["replace"] == {"X-Crew-User": ["${contexts.oauth2Info.userInfo['sub']}"]}
    notes = [n.text for n in ADAPTER.notes(seen(d, "beta/prod"), None)]
    assert any(t.startswith("its max session limit (28800s) isn't enforced by PingGateway") for t in notes)


def test_a_route_another_role_enforces_is_left_out_and_the_render_still_reads_back():
    d = with_crew(MOVED, override(BETA, "portal-enforcer", f"cn=portal,{APPS}", "pa-engine"))
    files = render_env(seen(d, "beta/prod"), None)
    assert "pinggateway/routes/portal.json" not in files and "pinggateway/routes/crew.json" in files
    (rt,) = read_back(seen(d, "beta/prod").d, ADAPTER, files, (ADAPTER,), environment="beta/prod")
    assert rt.changes == ()


def test_the_gateways_offer_to_protect_what_nothing_in_the_target_would():
    d = with_crew()
    ctx = PlanContext(d, seen(d, "alpha/prod"), seen(d, "beta/prod"), None, dt.date(2026, 9, 1), {}, {}, ())
    fix = next(x for x in check_routes(ctx).fixes if x.key == "protect:pinggateway/crew")
    assert fix.records[-1].attrs["ciamOverrideValue"] == ("ig",)

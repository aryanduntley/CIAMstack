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
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, make_directory, one
from opsdir.core.environment import env_model
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
    rendered = {p[len("pinggateway/"):]: t for p, t in render_env(env_model(d, "alpha/prod"), None).items()}
    assert preview_import(d, "pinggateway", rendered, (ADAPTER,))[0] == ()


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

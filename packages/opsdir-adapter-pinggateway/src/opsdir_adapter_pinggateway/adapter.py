"""PingGateway (ForgeRock Identity Gateway) adapter: applies to environments whose servers run PingGateway."""
from opsdir.core.contract import Adapter
from opsdir.domains.compute.workloads import runs_product
from .checks import check_routes
from .gateway import GATEWAY_CONFIG
from .listeners import listeners
from .proxy import proxy_settings
from .naming import ENDPOINTS, SERVER_ROLES
from .render import FORMATS, render_env
from .schema import FRAGMENT

PRODUCTS = ("PingGateway", "ForgeRock Identity Gateway")
REQUIRED_ROLES = ("subnet-ig", "ig-service", "ig-keystore")


def applies(m):
    return runs_product(m, PRODUCTS)


ADAPTER = Adapter(name="pinggateway", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=None, render_env=render_env, checks=(check_routes,), ref_schemes=(),
                  secret_schemes={}, renders="gateway routes to each environment's applications", neutral_label=None,
                  vocabulary={"ciamServerRole": SERVER_ROLES, "ciamTargetRole": SERVER_ROLES}, schema=FRAGMENT,
                  formats=FORMATS,
                  products=(("PingGateway", ">=2023,<2027"), ("ForgeRock Identity Gateway", ">=7,<8")),
                  secret_patterns=(), importers=(GATEWAY_CONFIG,), profile_terms=None, access=None,
                  endpoints=ENDPOINTS, listeners=listeners,
                  proxy_settings=proxy_settings)

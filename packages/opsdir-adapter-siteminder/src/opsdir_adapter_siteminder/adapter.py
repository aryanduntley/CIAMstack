"""SiteMinder adapter: applies to environments whose servers run SiteMinder (its Policy Servers, Web Agents, Access
Gateway), as the source of a migration away from it. It renders nothing: it reads the policy store's export and adds
the planner's checks for a plan from such an environment (source_checks)."""
from opsdir.core.contract import Adapter
from opsdir.domains.compute.workloads import runs_product
from .checks import check_user_directories
from .importer import VERSIONS, XPS
from .naming import PRODUCT, SERVER_ROLES
from .schema import FRAGMENT

# the products whose versions its servers record (ciamProductVersion "<product> <version>")
PRODUCTS = ((PRODUCT, VERSIONS), (f"{PRODUCT} Web Agent", VERSIONS), (f"{PRODUCT} Access Gateway", VERSIONS))


def applies(m):
    return runs_product(m, PRODUCT)


ADAPTER = Adapter(name="siteminder", kind="product", applies=applies, required_roles=(),
                  render_neutral=None, render_env=None, checks=(), ref_schemes=(), secret_schemes={},
                  renders="", neutral_label=None,
                  vocabulary={"ciamServerRole": SERVER_ROLES, "ciamTargetRole": SERVER_ROLES}, schema=FRAGMENT,
                  formats=(), products=PRODUCTS, secret_patterns=(), importers=(XPS,), profile_terms=None,
                  access=None, roles=(("server", SERVER_ROLES),),
                  source_checks=(check_user_directories,))

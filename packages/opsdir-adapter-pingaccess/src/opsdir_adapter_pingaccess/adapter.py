"""PingAccess adapter: applies to environments whose servers (or workloads) run PingAccess."""
from opsdir.core.contract import Adapter, ReadBack
from opsdir.domains.compute.workloads import runs_product
from .checks import check_pingaccess
from .collect import COLLECTORS
from .importer import ADMIN_API, EXPORT
from .listeners import listeners
from .logs import LOGS
from .naming import ENDPOINTS, SERVER_ROLES
from .render import FORMATS, own_requests, render_env, render_notes
from .schema import FRAGMENT
from .versions import VERSION_CHANGES

PRODUCTS = ("PingAccess",)


def applies(m):
    """Whether environment m runs PingAccess (on servers or Kubernetes)."""
    return runs_product(m, PRODUCTS)


ADAPTER = Adapter(name="pingaccess", kind="product", applies=applies, required_roles=(), render_neutral=None,
                  render_env=render_env, checks=(check_pingaccess,), ref_schemes=(), secret_schemes={},
                  renders="PingAccess Admin API requests for the applications it protects", neutral_label=None,
                  vocabulary={"ciamServerRole": SERVER_ROLES, "ciamTargetRole": SERVER_ROLES}, schema=FRAGMENT,
                  formats=FORMATS, products=(("PingAccess", ">=8.2,<10"),), roles=(("server", SERVER_ROLES),),
                  secret_patterns=(), importers=(ADMIN_API, EXPORT), profile_terms=None, access=None,
                  endpoints=ENDPOINTS, listeners=listeners, collectors=COLLECTORS, notes=render_notes, logs=LOGS,
                  version_changes=VERSION_CHANGES,
                  reads_back=(ReadBack("admin-api", "pingaccess/admin-api/*.json", "pingaccess/admin-api/",
                                       prepare=own_requests),))

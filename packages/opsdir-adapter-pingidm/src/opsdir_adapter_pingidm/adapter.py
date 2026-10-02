"""PingIDM (ForgeRock IDM) adapter: applies to environments whose servers run PingIDM."""
from opsdir.core.contract import Adapter
from opsdir.core.directory import one
from .checks import check_idm
from .naming import SERVER_ROLES
from .project import IDM_PROJECT
from .render import FORMATS, render_env, render_neutral
from .schema import FRAGMENT

PRODUCTS = ("PingIDM", "ForgeRock IDM")
REQUIRED_ROLES = ("subnet-idm", "idm-admin-password", "idm-keystore")


def applies(m):
    return any(one(s, "ciamProductVersion", "").startswith(PRODUCTS) for s in m.servers)


ADAPTER = Adapter(name="pingidm", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=render_neutral, render_env=render_env, checks=(check_idm,), ref_schemes=(),
                  secret_schemes={}, renders="IDM connector configuration for each environment",
                  neutral_label="PingIDM",
                  vocabulary={"ciamServerRole": SERVER_ROLES, "ciamTargetRole": SERVER_ROLES}, schema=FRAGMENT,
                  formats=FORMATS,
                  products=(("PingIDM", ">=7,<9"), ("ForgeRock IDM", ">=7,<8")),
                  secret_patterns=(), importers=(IDM_PROJECT,), profile_terms=None)

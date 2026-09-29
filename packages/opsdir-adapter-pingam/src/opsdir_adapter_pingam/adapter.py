"""PingAM (ForgeRock AM) adapter: applies to environments whose servers run PingAM."""
from opsdir.core.contract import Adapter, SecretPattern
from opsdir.core.directory import one
from opsdir_base_oidc.render import FORMATS as OIDC_FORMATS
from opsdir_base_saml.render import FORMATS as SAML_FORMATS
from .amster import AMSTER
from .checks import check_journeys
from .realms import SERVER_ROLES
from .render import FORMATS, render_neutral
from .schema import FRAGMENT

PRODUCTS = ("PingAM", "ForgeRock AM")
# An AM session token (the iPlanetDirectoryPro cookie value) is a live credential
SECRET_PATTERNS = (SecretPattern("am-session-token", r"AQIC5[A-Za-z0-9*._-]{40,}", "An AM session token"),)
REQUIRED_ROLES = ("subnet-am", "am-service", "am-admin-password", "am-keystore", "am-ds-bind-password")


def applies(m):
    return any(one(s, "ciamProductVersion", "").startswith(PRODUCTS) for s in m.servers)


ADAPTER = Adapter(name="pingam", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=render_neutral, render_env=None, checks=(check_journeys,), ref_schemes=(),
                  secret_schemes={}, renders=None, neutral_label="PingAM",
                  vocabulary={"ciamServerRole": SERVER_ROLES, "ciamTargetRole": SERVER_ROLES}, schema=FRAGMENT,
                  formats=(*FORMATS, *SAML_FORMATS, *OIDC_FORMATS),
                  products=(("PingAM", ">=7,<9"), ("ForgeRock AM", ">=7,<8")),
                  secret_patterns=SECRET_PATTERNS, importers=(AMSTER,))

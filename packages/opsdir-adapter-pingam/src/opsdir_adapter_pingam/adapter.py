"""PingAM (ForgeRock AM) adapter: applies to environments whose servers run PingAM."""
from opsdir.core.contract import Adapter, ReadBack, SecretPattern
from opsdir.domains.compute.workloads import runs_product
from .collect import COLLECTORS
from .detections import DETECTIONS
from opsdir_base_oidc.render import FORMATS as OIDC_FORMATS
from opsdir_base_saml.render import FORMATS as SAML_FORMATS
from .amster import AMSTER
from .certificates import amster_read_back, certificate_notes, render_certificate_journeys
from .checks import check_journeys
from .listeners import listeners
from .logs import LOGS
from .proxy import proxy_settings
from .realms import ENDPOINTS, SERVER_ROLES
from .render import FORMATS, PROFILE, render_neutral
from .schema import FRAGMENT
from .signals import SIGNALS
from .versions import VERSION_CHANGES

PRODUCTS = ("PingAM", "ForgeRock AM")
# An AM session token (the iPlanetDirectoryPro cookie value) is a live credential
SECRET_PATTERNS = (SecretPattern("am-session-token", r"AQIC5[A-Za-z0-9*._-]{40,}", "An AM session token"),)
KEYSTORE_ROLE = "am-keystore"          # the secret role holding AM's keystore (Adapter.roles, kind keystore)
REQUIRED_ROLES = ("subnet-am", "am-service", "am-admin-password", KEYSTORE_ROLE, "am-ds-bind-password")


def applies(m):
    return runs_product(m, PRODUCTS)


ADAPTER = Adapter(name="pingam", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=render_neutral, render_env=render_certificate_journeys,
                  checks=(check_journeys,), ref_schemes=(),
                  secret_schemes={}, renders=None, neutral_label="PingAM",
                  vocabulary={"ciamServerRole": SERVER_ROLES, "ciamTargetRole": SERVER_ROLES}, schema=FRAGMENT,
                  formats=(*FORMATS, *SAML_FORMATS, *OIDC_FORMATS),
                  products=(("PingAM", ">=7,<9"), ("ForgeRock AM", ">=7,<8")),
                  roles=(("server", SERVER_ROLES), ("keystore", (KEYSTORE_ROLE,))),
                  secret_patterns=SECRET_PATTERNS, importers=(AMSTER,), profile_terms=None, access=None,
                  endpoints=ENDPOINTS, listeners=listeners,
                  proxy_settings=proxy_settings, collectors=COLLECTORS, signals=SIGNALS,
                  logs=LOGS, version_changes=VERSION_CHANGES, detections=DETECTIONS,
                  profile=PROFILE, notes=certificate_notes,
                  reads_back=(ReadBack("amster", "am/*", "am/", prepare=amster_read_back),))

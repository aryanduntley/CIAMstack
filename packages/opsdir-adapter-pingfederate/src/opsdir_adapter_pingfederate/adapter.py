"""PingFederate adapter: applies to environments whose servers run PingFederate."""
from opsdir.core.contract import Adapter, SecretPattern
from opsdir.core.directory import one
from opsdir_base_oidc.render import FORMATS as OIDC_FORMATS
from opsdir_base_saml.render import FORMATS as SAML_FORMATS
from .checks import check_cluster, check_data_stores, check_references
from .discovery import CHOICES
from .importer import BULK
from .naming import SERVER_ROLES
from .nodes import NODE_FILES
from .render import render_env, render_neutral
from .schema import FRAGMENT

PRODUCT = "PingFederate"
# PingFederate's obfuscated or encrypted secrets (OBF:..., as its configuration files store them) are secret material
SECRET_PATTERNS = (SecretPattern("pingfederate-obfuscated", r"OBF:[A-Za-z0-9:._-]{16,}",
                                 "A PingFederate obfuscated or encrypted secret"),)
REQUIRED_ROLES = ("subnet-pf", "pf-sso-service", "pf-egress", "sso-tls-keystore", "pf-signing-key", "pf-admin-password")


def applies(m):
    return any(one(s, "ciamProductVersion", "").startswith(PRODUCT) for s in m.servers)


ADAPTER = Adapter(name="pingfederate", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=render_neutral, render_env=render_env,
                  checks=(check_data_stores, check_references, check_cluster), ref_schemes=(),
                  secret_schemes={},
                  renders="PingFederate data stores, plugin instances, cluster discovery and other resources for each "
                          "environment",
                  neutral_label="PingFederate",
                  vocabulary={"ciamServerRole": SERVER_ROLES, "ciamTargetRole": SERVER_ROLES,
                              "pingfedDiscoveryProtocol": CHOICES}, schema=FRAGMENT,
                  formats=(("pingfederate/*.json", "json"), ("pingfederate/cluster/*.properties", "java-properties"),
                           *SAML_FORMATS, *OIDC_FORMATS),
                  products=(("PingFederate", ">=11,<13"),),
                  secret_patterns=SECRET_PATTERNS, importers=(BULK, NODE_FILES), profile_terms=None, access=None)

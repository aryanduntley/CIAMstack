"""PingFederate adapter: applies to environments whose servers run PingFederate."""
from opsdir.core.contract import Adapter, ReadBack, SecretPattern
from opsdir.domains.compute.workloads import runs_product
from .collect import COLLECTORS
from opsdir_base_oidc.render import FORMATS as OIDC_FORMATS
from opsdir_base_saml.render import FORMATS as SAML_FORMATS
from .checks import (check_client_auth, check_cluster, check_data_stores, check_jdbc_drivers, check_kit_discovery,
                     check_references, check_service_roles, check_smtp_auth, credential_roles)
from .discovery import CHOICES
from .discovery_import import CLUSTER
from .importer import BULK
from .listeners import listeners
from .logs import LOGS
from .proxy import proxy_settings
from .naming import DISCOVERY_ROLE, PRODUCT, SERVER_ROLES
from .nodes import NODE_FILES
from .render import ENDPOINTS, PROFILE, TARGETS, render_env, render_neutral
from .schema import FRAGMENT
from .versions import VERSION_CHANGES

# PingFederate's obfuscated or encrypted secrets (OBF:..., as its configuration files store them) are secret material
SECRET_PATTERNS = (SecretPattern("pingfederate-obfuscated", r"OBF:[A-Za-z0-9:._-]{16,}",
                                 "A PingFederate obfuscated or encrypted secret"),)
REQUIRED_ROLES = ("subnet-pf", "pf-sso-service", "pf-egress", "sso-tls-keystore", "pf-signing-key", "pf-admin-password")


def applies(m):
    return runs_product(m, PRODUCT)


ADAPTER = Adapter(name="pingfederate", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=render_neutral, render_env=render_env,
                  checks=(check_kit_discovery, check_data_stores, check_references, check_cluster,
                          check_client_auth, check_smtp_auth, check_service_roles, check_jdbc_drivers),
                  roles_used=credential_roles,
                  ref_schemes=(),
                  secret_schemes={},
                  renders="PingFederate's configuration for each environment as Admin API requests checked against its "
                          "version's spec, as Terraform for its provider or, on request, as a bulk import document, "
                          "and cluster discovery",
                  neutral_label="PingFederate",
                  vocabulary={"ciamServerRole": SERVER_ROLES, "ciamTargetRole": SERVER_ROLES,
                              "pingfedDiscoveryProtocol": CHOICES}, schema=FRAGMENT,
                  formats=(("pingfederate/admin-api/*.json", "json"), ("pingfederate/bulk-config/*.json", "json"),
                           ("pingfederate/bulk-config-problems.json", "json"),
                           ("pingfederate/terraform/*.tf", "hcl"),
                           ("pingfederate/cluster/*.properties", "java-properties"),
                           *SAML_FORMATS, *OIDC_FORMATS),
                  products=(("PingFederate", ">=11,<14"),),
                  roles=(("server", SERVER_ROLES), ("cluster-discovery", (DISCOVERY_ROLE,))),
                  secret_patterns=SECRET_PATTERNS, importers=(BULK, NODE_FILES, CLUSTER), profile_terms=None,
                  access=None, endpoints=ENDPOINTS, listeners=listeners,
                  proxy_settings=proxy_settings, collectors=COLLECTORS, render_targets=TARGETS,
                  logs=LOGS, version_changes=VERSION_CHANGES,
                  profile=PROFILE,
                  # its bulk importer reads back the Admin API requests (bulk-config/data.json holds the same)
                  reads_back=(ReadBack("bulk", "pingfederate/admin-api/*.json"),
                              ReadBack("cluster", "pingfederate/cluster/jgroups.properties", "pingfederate/cluster/",
                                       "{environment}/", True)))

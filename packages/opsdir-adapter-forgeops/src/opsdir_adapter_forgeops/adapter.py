"""ForgeOps adapter: PingAM, PingIDM, PingDS and PingGateway workloads an environment runs on Kubernetes, deployed
with ForgeOps (Ping Identity's Helm charts and Kustomize bases) at the pinned release, from the record's workloads
and their bindings."""
from opsdir.core.contract import Adapter
from .checks import check_forgeops
from .ds_profile import ds_notes
from .listeners import listeners
from .logs import LOGS
from .profiles import render_profiles
from .render import TARGETS, applies, render
from .routes import routes

# a config profile's files by their kind (the products' own: JSON, properties, scripts; DS's image inputs: LDIF and
# its build step; anything else as text), then the values and overlay
_PROFILES = "forgeops/config-profiles/"
FORMATS = ((_PROFILES + "*/Dockerfile", "dockerfile"), (_PROFILES + "*.json", "json"),
           (_PROFILES + "*.properties", "java-properties"), (_PROFILES + "*.md", "markdown"),
           (_PROFILES + "*.groovy", "groovy"), (_PROFILES + "*.js", "javascript"), (_PROFILES + "*.xml", "xml"),
           (_PROFILES + "*.ldif", "ldif"), (_PROFILES + "*.sh", "shell"),
           (_PROFILES + "*", "text"), ("forgeops/*", "yaml"))

ADAPTER = Adapter(name="forgeops", kind="platform", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_forgeops,), ref_schemes=(),
                  secret_schemes={},
                  renders="ForgeOps Helm values (identity-platform, ping-gateway), a Kustomize overlay and, on "
                          "request, the products' config profiles for the workloads run on Kubernetes",
                  neutral_label=None, vocabulary={}, schema=None, formats=FORMATS, products=(),
                  secret_patterns=(), importers=(), profile_terms=None, access=None, render_targets=TARGETS,
                  listeners=listeners, routes=routes, logs=LOGS, render_profiles=render_profiles,
                  notes=ds_notes)

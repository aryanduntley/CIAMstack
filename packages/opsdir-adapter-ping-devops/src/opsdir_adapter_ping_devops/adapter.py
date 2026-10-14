"""ping-devops adapter: PingFederate admin and engine workloads an environment runs on Kubernetes, deployed with
Ping Identity's ping-devops Helm chart at the pinned release, from the record's workloads and their bindings."""
from opsdir.core.contract import Adapter
from .checks import check_ping_devops
from .helm import render
from .listeners import listeners
from .logs import LOGS
from .profiles import render_profiles
from .products import applies
from .release import SERVER_PROFILE
from .routes import routes

# a server profile's files by their kind (.subst files by the kind they are once substituted), then the values
_PROFILE = "ping-devops/server-profile/"
FORMATS = ((_PROFILE + "*/Dockerfile", "dockerfile"), (_PROFILE + "*.json.subst", "json"),
           (_PROFILE + "*.json", "json"), (_PROFILE + "*.properties.subst", "java-properties"),
           (_PROFILE + "*.properties", "java-properties"), (_PROFILE + "*.xml.subst", "xml"),
           (_PROFILE + "*.xml", "xml"), (_PROFILE + "*.md", "markdown"), (_PROFILE + "*", "text"),
           ("ping-devops/*", "yaml"))

TARGETS = ((SERVER_PROFILE, "PingFederate's configuration as a server profile (its instance/ tree, secrets "
                            "substituted at start) with the Dockerfile building it into the image where no profile "
                            "repository is recorded", False),)

ADAPTER = Adapter(name="ping-devops", kind="platform", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_ping_devops,), ref_schemes=(),
                  secret_schemes={},
                  renders="ping-devops Helm values and, on request, a server profile for the PingFederate admin "
                          "and engine run on Kubernetes",
                  neutral_label=None, vocabulary={}, schema=None, formats=FORMATS, products=(),
                  secret_patterns=(), importers=(), profile_terms=None, access=None, render_targets=TARGETS,
                  listeners=listeners, routes=routes, logs=LOGS, render_profiles=render_profiles)

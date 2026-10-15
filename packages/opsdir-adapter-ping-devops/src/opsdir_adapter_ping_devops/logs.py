"""The logs of the ping-devops chart's PingFederate pods, by container. Pure.

The image streams the files TAIL_LOG_FILES names to its own output, by default server.log and init.log
(developer.pingidentity.com/devops/docker-images/pingfederate/README.html,
developer.pingidentity.com/devops/reference/containerLogging.html): nothing marks which file a line came from, so the
main container's lines are the server log's kind. Every other file PingFederate writes (the PingFederate adapter's
declarations, read through the registry: where it is under the install root, its kind) is the output of a sidecar of
its own, pf-log-<file>, tailing it from the pod's /opt/out (user decision 2348; helm.py renders the sidecars a log
route picks). The image's server root, SERVER_ROOT_DIR=/opt/out/instance, is the install root's pingfederate/ folder.

PingFederate's server roles and file declarations come from the installed adapters, never from an import: the
adapter's logs are kit_logs, which the registry resolves once over the installed products' declarations
(connectors.registry.resolved_logs); a render reads the same declarations from Services.installed_logs.
"""
import re

from opsdir.core.contract import LogSource

PRODUCT = "PingFederate"                    # the product whose roles and log files the chart's pods run
TAILED = ("server.log", "init.log")         # TAIL_LOG_FILES' default: the main container's output
PRODUCT_DIR = "pingfederate/"               # the install root's folder the image's server root is
OUT_DIR = "/opt/out"                        # what the chart persists (out-dir), the server root under it
SERVER_ROOT = f"{OUT_DIR}/instance"


def file_name(path):
    return path.rsplit("/", 1)[-1]


def sidecar_name(path):
    """The container tailing a log file: pf-log-<file name without .log>, as a DNS label."""
    return "pf-log-" + re.sub(r"[^a-z0-9-]+", "-", file_name(path).removesuffix(".log").lower()).strip("-")


def in_server_root(path):
    """A file's path under the server root (log/audit.log), from its path under the install root."""
    return path.removeprefix(PRODUCT_DIR)


def server_roles(product_roles):
    """PingFederate's server roles, in its adapter's order, from the installed adapters' product roles ((product,
    kind, role), ...: core.environment.product_roles)."""
    return tuple(dict.fromkeys(r for p, k, r in product_roles if p == PRODUCT and k == "server"))


def sidecar_files(sources, roles):
    """((server role, sidecar container, the file's path under the server root, its declaration), ...): every file
    PingFederate's servers write (sources: LogSources of the installed adapters; roles: its server roles) but those
    the main container streams, in declaration order."""
    return tuple((f.server_role, sidecar_name(f.path), in_server_root(f.path), f) for f in sources
                 if f.server_role in roles and f.on == "servers" and file_name(f.path) not in TAILED)


def kit_logs(sources, product_roles):
    """Adapter.logs (resolved by the registry over the installed adapters' static LogSources and product roles): each
    PingFederate role's main container (server.log and init.log), then a sidecar per other file it writes."""
    roles = server_roles(product_roles)
    return (*(LogSource(role, "kubernetes", None, "text", "error") for role in roles),
            *(LogSource(role, "kubernetes", None, f.format, f.kind, f.match, f.line_start, f.requires, container)
              for role, container, _, f in sidecar_files(sources, roles)))

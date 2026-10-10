"""The logs of the ping-devops chart's PingFederate pods, by container. Pure.

The image streams the files TAIL_LOG_FILES names to its own output, by default server.log and init.log
(developer.pingidentity.com/devops/docker-images/pingfederate/README.html,
developer.pingidentity.com/devops/reference/containerLogging.html): nothing marks which file a line came from, so the
main container's lines are the server log's kind. Every other file PingFederate writes (opsdir-adapter-pingfederate's
declarations: where it is under the install root, its kind) is the output of a sidecar of its own, pf-log-<file>,
tailing it from the pod's /opt/out (user decision 2348; helm.py renders the sidecars a log route picks). The image's
server root, SERVER_ROOT_DIR=/opt/out/instance, is the install root's pingfederate/ folder.
"""
import re

from opsdir.core.contract import LogSource
from opsdir_adapter_pingfederate.logs import LOGS as FILES
from opsdir_adapter_pingfederate.naming import SERVER_ROLES

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


# (server role, sidecar container, the file's path under the server root, its declaration): every file but those the
# main container streams.
SIDECAR_FILES = tuple((f.server_role, sidecar_name(f.path), in_server_root(f.path), f) for f in FILES
                      if f.on == "servers" and file_name(f.path) not in TAILED)
LOGS = (*(LogSource(role, "kubernetes", None, "text", "error") for role in SERVER_ROLES),
        *(LogSource(role, "kubernetes", None, f.format, f.kind, f.match, f.line_start, f.requires, container)
          for role, container, _, f in SIDECAR_FILES))

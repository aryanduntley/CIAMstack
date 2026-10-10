"""The container output of the ping-devops chart's PingFederate pods: the image streams the files TAIL_LOG_FILES
names to standard output, by default server.log and init.log
(developer.pingidentity.com/devops/docker-images/pingfederate/README.html,
developer.pingidentity.com/devops/reference/containerLogging.html). Nothing documented marks which file a line came
from, so every line is the server log's kind. Pure."""
from opsdir.core.contract import LogSource

LOGS = tuple(LogSource(role, "kubernetes", None, "text", "error") for role in ("pf-engine", "pf-admin"))

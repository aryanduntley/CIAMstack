"""The log file PingGateway servers write by default, relative to the install root (the instance directory,
$HOME/.openig unless start.sh is given another): logs/route-system.log, PingGateway's and its dependencies' log
(docs.pingidentity.com/pinggateway/2026/maintenance-guide/logging.html,
docs.pingidentity.com/pinggateway/2026/configure/configure.html). Audit files are written only where a route's audit
service names a directory (the default is NoOpAuditService), so none are declared; per-route capture files are for
troubleshooting."""
from opsdir.core.contract import LogSource
from .naming import SERVER_ROLES

IG = SERVER_ROLES[0]

LOGS = (
    LogSource(IG, "servers", "logs/route-system.log", "text", "error"),)

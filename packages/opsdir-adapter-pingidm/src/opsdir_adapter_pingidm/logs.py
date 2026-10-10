"""The log files PingIDM servers write by default, relative to the install root (the openidm directory): the audit
service's JSON files, one per topic, in audit/ (docs.pingidentity.com/pingidm/8/audit-guide/audit-log-topics.html),
and the server log in logs/ (docs.pingidentity.com/pingidm/8.1/monitoring-guide/server-logs.html; rotated files carry
a date, openidm-2025-03-11.log). The reconciliation and synchronization topics' file names aren't stated, so they
aren't declared. The server log's format differs by version (text before 8.0, Logback after), so it is shipped as
text."""
from opsdir.core.contract import LogSource
from .naming import SERVER_ROLES

IDM = SERVER_ROLES[0]

LOGS = (
    LogSource(IDM, "servers", "audit/access.audit.json", "json-lines", "access"),
    LogSource(IDM, "servers", "audit/activity.audit.json", "json-lines", "audit"),
    LogSource(IDM, "servers", "audit/authentication.audit.json", "json-lines", "audit"),
    LogSource(IDM, "servers", "audit/config.audit.json", "json-lines", "admin"),
    LogSource(IDM, "servers", "logs/openidm*.log", "text", "error"))

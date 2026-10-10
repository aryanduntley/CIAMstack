"""The log files PingDS servers write by default, relative to the install root (the opendj directory), as the PingDS 8
logging guide and troubleshooting guide name them (docs.pingidentity.com/pingds/8.1/logging-guide/about-logs.html,
docs.pingidentity.com/pingds/8/maintenance-guide/troubleshooting.html,
docs.pingidentity.com/pingds/8/logging-guide/http-access.html). Rotated files get a timestamp appended, so the exact
names are the live files. The error log's `category=sync` lines (replication) and debug lines are shipped with it as
errors: the record can't tell them apart in a text log. PingDS 7 writes replication repair messages to a file of their
own, logs/replication (DS 7.1 logging guide); PingDS 8 writes them to the error log (category=SYNC,
docs.pingidentity.com/pingds/8.1/maintenance-guide/troubleshooting.html). The audit log is LDIF, one line at a time
(the guides don't state how a record starts), and only once its publisher is enabled (DS 7.1 logging guide: "Enable an
Audit Log"; docs.pingidentity.com/pingds/8.1/logging-guide/manage-logs.html). Container output isn't declared: the
guides state no default for it."""
from opsdir.core.contract import LogSource
from opsdir.domains.directory.naming import DIRECTORY_SERVER_ROLE as DS

LOGS = (
    LogSource(DS, "servers", "logs/ldap-access.audit.json", "json-lines", "access"),
    LogSource(DS, "servers", "logs/http-access.audit.json", "json-lines", "access"),
    LogSource(DS, "servers", "logs/errors", "text", "error", line_start=r"^\["),
    LogSource(DS, "servers", "logs/server.out", "text", "error", line_start=r"^\["),
    LogSource(DS, "servers", "logs/replication", "text", "replication", line_start=r"^\[",
              requires="PingDS 7 (PingDS 8 writes these messages to logs/errors)"),
    LogSource(DS, "servers", "logs/audit", "text", "audit", requires="the File-Based Audit Logger enabled"))

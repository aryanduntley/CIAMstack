"""The log files PingAM servers write by default, relative to the install root (AM's base directory, /path/to/am in
the docs): the audit service's JSON files in var/audit
(docs.pingidentity.com/pingam/8/security/implementing-audit.html), one per topic (access, activity, authentication,
config). Every audit event carries eventName, and access events' start with AM-ACCESS-
(docs.pingidentity.com/pingam/8/security/sec-maint-audit-ref.html); the others are audit. Rotated files get a
-yyyy.MM.dd-kk.mm.ss suffix, so *.json is the live files. Debug logs aren't declared: the docs disagree on their
directory (%BASE_DIR%/%SERVER_URI%/var/debug in the server settings, /path/to/am/var/debug in the deployment
guide)."""
from opsdir.core.contract import LogSource
from .realms import SERVER_ROLES

AM = SERVER_ROLES[0]
AUDIT_MATCH = (("eventName", "AM-ACCESS-", "access"),)

LOGS = (
    LogSource(AM, "servers", "var/audit/*.json", "json-lines", "audit", AUDIT_MATCH),)

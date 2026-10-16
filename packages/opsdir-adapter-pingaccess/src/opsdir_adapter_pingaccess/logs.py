"""The log files PingAccess servers write by default, relative to the install root (<PA_HOME>, holding bin/, conf/ and
log/): the server log and the five security audit logs Ping's monitoring guide lists for 8.2 through 9.1
(docs.pingidentity.com/pingaccess/<version>/pingaccess_monitoring_guide/pa_logging_reporting_and_troubleshooting.html)
under log/ (pa_security_audit_logging.html; the Logging page's prose says logs/, its log4j2.xml example
${sys:pa.home}/log/, followed here: the shipped file wasn't seen). The admin node writes the server log and the admin
API's audit log, the engines the server log and the audit logs of what they serve: resources (each resource's Audit
setting), agents and sideband clients (sideband is off by default: sideband.http.enabled). Text by
default (JSON only with changed Log4j2 appenders, 8.3 and later); audit to a database instead of files is a Log4j2
change too. Rotation is Log4j2's (conf/log4j2.xml), so the names are the live files. Only what the documentation states
is declared: no multi-line rule (the server log's stack traces aren't documented), no garbage-collection log (its path
isn't), none of the optional appenders (error-only, HAR, CEF, Splunk)."""
from opsdir.core.contract import LogSource
from .naming import ADMIN, ENGINE, SERVER_ROLES

SIDEBAND = "sideband enabled (sideband.http.enabled, off by default)"


def _log(role, name, kind, requires=None):
    return LogSource(role, "servers", f"log/{name}", "text", kind, requires=requires)


LOGS = (
    *(_log(role, "pingaccess.log", "error") for role in SERVER_ROLES),
    _log(ADMIN, "pingaccess_api_audit.log", "admin"),
    _log(ENGINE, "pingaccess_engine_audit.log", "audit", "the resource's Audit setting on"),
    _log(ENGINE, "pingaccess_agent_audit.log", "audit"),
    _log(ENGINE, "pingaccess_sideband_client_audit.log", "audit", SIDEBAND),
    _log(ENGINE, "pingaccess_sideband_audit.log", "audit", SIDEBAND))

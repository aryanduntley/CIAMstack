"""The log files PingFederate nodes write by default, relative to the install root (<pf_install>, holding
pingfederate/): pingfederate/log, unless run.properties' pf.log.dir moves it
(docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/pf_log_files.html). The administrative
console's logs are the admin node's; the runtime's (requests, transactions, the security audit log, provisioning) the
engines'; server.log and init.log both. Text by default (JSON only with changed Log4j2 appenders); request.log is the
legacy request log. Rotation is Log4j2's (server/default/conf/log4j2.xml), its suffixes not stated, so the names are
the live files."""
from opsdir.core.contract import LogSource
from .naming import SERVER_ROLES

ENGINE, ADMIN = SERVER_ROLES


def _logs(role, files):
    return tuple(LogSource(role, "servers", f"pingfederate/log/{name}", "text", kind) for name, kind in files)


LOGS = (
    *_logs(ADMIN, (("admin.log", "admin"), ("admin-event-detail.log", "admin"), ("admin-api.log", "admin"),
                   ("admin-request.log", "admin"))),
    *_logs(ENGINE, (("runtime-request.log", "access"), ("request.log", "access"), ("transaction.log", "transaction"),
                    ("audit.log", "audit"), ("provisioner-audit.log", "audit"), ("provisioner.log", "other"))),
    *(s for role in SERVER_ROLES for s in _logs(role, (("server.log", "error"), ("init.log", "error")))))

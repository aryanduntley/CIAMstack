"""The log files OpenDJ servers write by default, relative to the install root (the opendj directory), as the Open
Identity Platform's administration guide names them (doc.openidentityplatform.org/opendj/admin-guide/chap-monitoring,
research note 2354): the text access log logs/access (OpenDJ's default; its JSON access logger ships disabled), the
HTTP access log logs/http-access, the error log logs/errors, the replication log logs/replication and the server's
output logs/server.out, the last three "[datestamp] category=..." lines. The audit log isn't declared: the guide
doesn't state its default. Rotated files get a timestamp appended, so the names are the live files. Pure."""
from opsdir.core.contract import LogSource
from opsdir.domains.directory.naming import DIRECTORY_SERVER_ROLE as DS

LOGS = (
    LogSource(DS, "servers", "logs/access", "text", "access"),
    LogSource(DS, "servers", "logs/http-access", "text", "access"),
    LogSource(DS, "servers", "logs/errors", "text", "error", line_start=r"^\["),
    LogSource(DS, "servers", "logs/replication", "text", "replication", line_start=r"^\["),
    LogSource(DS, "servers", "logs/server.out", "text", "error", line_start=r"^\["))

"""The container output of ForgeOps' pods: each container's log is what it writes to standard output, and AM writes
its debug log there (docs.pingidentity.com/forgeops/7.5/consolidated.html). Audit events join it only where the
product's JSON stdout audit handler is on, which the ForgeOps docs don't state for their images
(docs.pingidentity.com/forgeops/2026.1/consolidated.html: "Turn on audit logging"). Every ForgeRock audit event carries
eventName (docs.pingidentity.com/pingam/8/entity-reference/sec-amster-entity-auditevent.html); AM's access events
start with AM-ACCESS (AM-ACCESS_ATTEMPT, AM-ACCESS-OUTCOME: docs.pingidentity.com/pingam/8.1/monitoring/
audit-logging-ref.html); PingGateway's carry topic
and source (docs.pingidentity.com/pinggateway/2025.11/maintenance-guide/auditing.html). DS isn't declared: its
documentation states no default for container output. Pure."""
from opsdir.core.contract import LogSource

LOGS = (
    LogSource("am", "kubernetes", None, "mixed", "debug",
              (("eventName", "AM-ACCESS", "access"), ("eventName", "", "audit")),
              requires="AM's JSONStdout audit event handler (audit logging service), for its audit events"),
    LogSource("idm", "kubernetes", None, "mixed", "error", (("eventName", "", "audit"),),
              requires="openidm.audit.handler.stdout.enabled=true (JsonStdoutAuditEventHandler), for its audit "
                       "events"),
    LogSource("ig", "kubernetes", None, "mixed", "error", (("topic", "access", "access"), ("source", "audit", "audit")),
              requires="a JsonStdoutAuditEventHandler in the routes' audit service, for its audit events"))

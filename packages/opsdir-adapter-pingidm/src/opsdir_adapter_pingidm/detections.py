"""The detections PingIDM declares (contract.ProductDetection): what its audit service's authentication and config
topics (audit/authentication.audit.json, audit/config.audit.json: logs.py) are watched for, as each version's audit
guide states their events (ForgeRock IDM 7.1 audit guide, PingIDM 7.2-8.1 event property tables and query samples).
Only what the guides establish is declared:

- brute force and password spray: authentication events with result FAILED (SUCCESSFUL or FAILED in every table from
  7.1), per principal, or per source address (context.ipAddress: "the IP address from which the authentication request
  was made") counting distinct principals. The topic holds sign-ins only, but no one event name is established for one
  (the tables say authentication, and from 8.0 also LOGIN, SUCCESS, SESSION or FAILED; the samples LOGIN, SESSION,
  authentication), so the selector is the result alone, on that topic's log. IDM has no realm: per principal only.
  7.0's property table isn't available, so 7.0 isn't declared;
- configuration change: config events (eventName config in the tables, CONFIG in the samples: both are matched), with
  the acting user (userId) and the object (objectId, such as ui). 7.2 is the first version whose table the guides
  give.

Not declared: administrator sign-in failures (context.component internal/user tells an internal user from a managed
one where it's present, but it isn't guaranteed on a failed attempt, and internal isn't administrator); key changes (no
config objectId is documented for secrets.json or session keys)."""
from opsdir.core.contract import DetectionMapping, ProductDetection
from .naming import SERVER_ROLES

IDM = SERVER_ROLES[0]
EVIDENCE = ("https://backstage.forgerock.com/docs/idm/7.1/IDM-7.1-Audit-Guide.pdf",
            "https://docs.pingidentity.com/pingidm/7.2/audit-guide/auth-event-prop.html",
            "https://docs.pingidentity.com/pingidm/8.1/audit-guide/auth-event-prop.html",
            "https://docs.pingidentity.com/pingidm/8.1/audit-guide/audit-schema.html",
            "https://docs.pingidentity.com/pingidm/8.1/audit-guide/querying-audit-over-rest.html")
CONFIG_EVIDENCE = ("https://docs.pingidentity.com/pingidm/7.2/audit-guide/config-event-prop.html",
                   "https://docs.pingidentity.com/pingidm/8.1/audit-guide/config-event-prop.html",
                   "https://docs.pingidentity.com/pingidm/8.1/audit-guide/querying-audit-over-rest.html")
SIGN_IN = (("subject", "principal"), ("source-ip", "context.ipAddress"), ("outcome", "result"))
FAILED = (("outcome", "failure", ("FAILED",)),)
CONFIG = (("actor", "userId"), ("object", "objectId"), ("action", "eventName"))
CONFIG_EVENTS = (("action", "config-change", ("config", "CONFIG")),)
# Brute force: 10 failures of one principal within any 5 minutes; spray: 10 principals failing from one address within
# any 10 minutes (one address trying many accounts once or twice each stays under a brute-force threshold)
BRUTE_FORCE, SPRAY = (10, 300), (10, 600)
SIGN_INS_LOGGED = ("the authentication audit topic is logged (audit/authentication.audit.json); the search reads that "
                   "log only, since its selector is the result alone")
PRODUCTS = (("PingIDM", ">=7.1,<9"), ("ForgeRock IDM", ">=7.1,<8"))
CONFIG_PRODUCTS = (("PingIDM", ">=7.2,<9"), ("ForgeRock IDM", ">=7.2,<8"))


def _mappings(first, fields, said):
    # PingIDM's range is open above: a role recording no version is taken to run the newest release (versions.holds);
    # the declaration's products bound it
    return (DetectionMapping("ForgeRock IDM", f">={first},<8", fields, said),
            DetectionMapping("PingIDM", f">={first}", fields, said))


DETECTIONS = (
    ProductDetection(
        id="brute-force", title="PingIDM brute force",
        description="Repeated failed authentications (result FAILED) for one principal",
        products=PRODUCTS, server_role=IDM, log_source="authentication",
        mappings=_mappings("7.1", SIGN_IN, FAILED),
        selector=(("outcome", ("failure",)),), group_by=("subject",), distinct=None,
        threshold=BRUTE_FORCE[0], window_seconds=BRUTE_FORCE[1], window_kind="sliding",
        tactics=("credential-access",), techniques=("T1110.001",), severity="sev3",
        prerequisites=(SIGN_INS_LOGGED,
                       "a failed authentication's event names the account tried in principal: the guides don't say "
                       "it is always filled on failure, so check a captured failed sign-in"),
        evidence=EVIDENCE, validation="documented"),
    ProductDetection(
        id="password-spray", title="PingIDM password spray",
        description="Failed authentications for many different principals from one source address",
        products=PRODUCTS, server_role=IDM, log_source="authentication",
        mappings=_mappings("7.1", SIGN_IN, FAILED),
        selector=(("outcome", ("failure",)),), group_by=("source-ip",), distinct="subject",
        threshold=SPRAY[0], window_seconds=SPRAY[1], window_kind="sliding",
        tactics=("credential-access",), techniques=("T1110.003",), severity="sev2",
        prerequisites=(SIGN_INS_LOGGED,
                       "context.ipAddress is the client's address: behind a load balancer or proxy, check a captured "
                       "event doesn't name the proxy instead (every failure would then count from one address)"),
        evidence=EVIDENCE, validation="documented"),
    ProductDetection(
        id="config-change", title="PingIDM configuration change",
        description="A change to IDM's configuration (a config audit event): who (userId) changed what (objectId)",
        products=CONFIG_PRODUCTS, server_role=IDM, log_source="config",
        mappings=_mappings("7.2", CONFIG, CONFIG_EVENTS),
        selector=(("action", ("config-change",)),), group_by=(), distinct=None,
        threshold=None, window_seconds=None, window_kind=None,
        tactics=("persistence", "defense-impairment"), techniques=("T1556",), severity="sev3",
        prerequisites=("the config audit topic is logged (audit/config.audit.json)",),
        evidence=CONFIG_EVIDENCE, validation="documented"))

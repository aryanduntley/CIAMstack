"""The detections PingAM declares (contract.ProductDetection): what its audit service's authentication and config topics
(var/audit/authentication.audit.json, config.audit.json: logs.py) are watched for, as each version's audit logging
reference states their events (ForgeRock AM 7.0-7.1 log-files reference, PingAM 7.2-7.5 and 8.0 security guide, 8.1
monitoring guide). Only what the references establish is declared:

- brute force: completed sign-ins with result FAILED, per principal and realm. A journey's completion is
  AM-TREE-LOGIN-COMPLETED in every version from 7.0 to 8.1; an authentication chain's is AM-LOGIN-COMPLETED, in the
  7.x references only (absent from 8.1's event table), so it counts on 7.x alone. Node events
  (AM-NODE-LOGIN-COMPLETED) aren't counted: a journey's failed branches aren't failed sign-ins. Failure is FAILED in
  every reference (success is SUCCESSFUL, or SUCCESS in 8.0/8.1's tree-event table: not used here);
- configuration change: AM-CONFIG-CHANGE, every one, with its objectId. Config events don't record who made the change
  (user.id: "Not used"): the access event with the same transactionId does.

Not declared: password spray (authentication events carry no client address: 7.x shows ipAddress only in a module's
entries[].info, 8.x none; the access topic's client.ip is joined by transactionId, which a declaration can't say);
administrator sign-in failures (nothing in an authentication event tells an administrator from an end user); key
changes (no config objectId is documented as a secret store or key; AM-KEY-MANAGER-RELOAD-NOTIFICATION, activity topic
from 7.4, says a key manager reloaded, not that a key changed)."""
from opsdir.core.contract import DetectionMapping, ProductDetection
from .realms import SERVER_ROLES

AM = SERVER_ROLES[0]
TREE, CHAIN, CONFIG = "AM-TREE-LOGIN-COMPLETED", "AM-LOGIN-COMPLETED", "AM-CONFIG-CHANGE"
# The references the declarations rest on, per version (the 7.0 and 7.1 ones are ForgeRock's archive)
EVIDENCE = ("https://backstage.forgerock.com/docs/am/7/reference/log-files.html",
            "https://backstage.forgerock.com/docs/am/7.1/AM-7.1.4-Security-Guide.pdf",
            "https://docs.pingidentity.com/pingam/7.5/security/sec-maint-audit-ref.html",
            "https://docs.pingidentity.com/pingam/8/security/sec-maint-audit-ref.html",
            "https://docs.pingidentity.com/pingam/8.1/monitoring/audit-logging-ref.html",
            "https://docs.pingidentity.com/pingam/8.1/monitoring/audit-logging.html")
SIGN_IN = (("subject", "principal"), ("realm", "realm"), ("outcome", "result"), ("action", "eventName"))
FAILED = ("outcome", "failure", ("FAILED",))
# Brute force: 10 failed sign-ins of one principal in one realm within any 5 minutes (above typing mistakes, at or
# below common lockout thresholds, so it fires before or as the account locks)
BRUTE_FORCE = (10, 300)


def _sign_ins(product, versions, events):
    return DetectionMapping(product, versions, SIGN_IN, (FAILED, ("action", "login", events)))


def _config(product, versions):
    return DetectionMapping(product, versions, (("object", "objectId"), ("realm", "realm"), ("action", "eventName")),
                            (("action", "config-change", (CONFIG,)),))


PRODUCTS = (("PingAM", ">=7,<9"), ("ForgeRock AM", ">=7,<8"))
# The newest mapping's range is open above: a role recording no version is taken to run the newest release
# (versions.holds); the declaration's products bound it

DETECTIONS = (
    ProductDetection(
        id="brute-force", title="PingAM brute force",
        description="Repeated failed sign-ins (completed journeys, or chains on 7.x, ending FAILED) for one principal "
                    "in one realm",
        products=PRODUCTS, server_role=AM, log_source="authentication",
        mappings=(_sign_ins("PingAM", ">=7,<8", (TREE, CHAIN)), _sign_ins("ForgeRock AM", ">=7,<8", (TREE, CHAIN)),
                  _sign_ins("PingAM", ">=8", (TREE,))),
        selector=(("action", ("login",)), ("outcome", ("failure",))), group_by=("subject", "realm"), distinct=None,
        threshold=BRUTE_FORCE[0], window_seconds=BRUTE_FORCE[1], window_kind="sliding",
        tactics=("credential-access",), techniques=("T1110.001",), severity="sev3",
        prerequisites=("the authentication audit topic is logged (var/audit/authentication.audit.json)",
                       "a failed sign-in's event names the account tried in principal: the references don't say "
                       "it is always filled on failure, so check a captured failed sign-in"),
        evidence=EVIDENCE, validation="documented"),
    ProductDetection(
        id="config-change", title="PingAM configuration change",
        description="A change to AM's configuration (AM-CONFIG-CHANGE): what changed is its objectId and realm; who "
                    "changed it is the access event with the same transactionId",
        products=PRODUCTS, server_role=AM, log_source="config",
        mappings=(_config("ForgeRock AM", ">=7,<8"), _config("PingAM", ">=7")),
        selector=(("action", ("config-change",)),), group_by=(), distinct=None,
        threshold=None, window_seconds=None, window_kind=None,
        tactics=("persistence", "defense-impairment"), techniques=("T1556",), severity="sev3",
        prerequisites=("the config audit topic is logged (var/audit/config.audit.json)",
                       "the access topic is logged too: config events don't record who made a change (user.id is "
                       "not used), the access event with the same transactionId does"),
        evidence=EVIDENCE, validation="documented"))

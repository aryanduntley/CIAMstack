"""The detections PingDS declares (contract.ProductDetection): what its LDAP access log (logs/ldap-access.audit.json,
the Json File-Based Access Logger's, enabled by default: logs.py) is watched for, as the logging guide's JSON schema
states its events from 7.2 to 8.1 (eventName DJ-LDAP; client.ip, request.operation, request.dn, response.status and
response.statusCode, a string). Only what the guides establish is declared:

- brute force and password spray: failed binds, operation BIND with result code 49 (invalid credentials, the LDAP
  result code table): not every failed operation, nor every failed bind (a bind failing for another reason isn't a
  wrong password). Per bind DN, or per client address counting distinct bind DNs. DS has no realm: per bind DN only.

Not declared: administrator bind failures (the bind DN is in request.dn, but which DNs are administrators is the
deployment's, and a selector can't hold a DN); configuration changes (the access log records changes under cn=config
as ordinary operations on DNs ending in it, which a selector can't match, and the configuration audit log the guides
describe is LDIF, not fields); key changes (likewise)."""
from opsdir.core.contract import DetectionMapping, ProductDetection
from opsdir.domains.directory.naming import DIRECTORY_SERVER_ROLE as DS

EVIDENCE = ("https://docs.pingidentity.com/pingds/7.2/logging-guide/about-logs.html",
            "https://docs.pingidentity.com/pingds/8.1/logging-guide/about-logs.html",
            "https://docs.pingidentity.com/pingds/8.1/logging-guide/ldap-access.html",
            "https://docs.pingidentity.com/pingds/8/ldap-reference/ldap-result-codes.html")
PRODUCTS = (("PingDS", ">=7.2,<9"),)
BIND = (("subject", "request.dn"), ("source-ip", "client.ip"), ("outcome", "response.statusCode"),
        ("action", "request.operation"))
# A failed bind: operation BIND, result code 49 (the schema's statusCode is a string)
INVALID_CREDENTIALS = (("outcome", "failure", ("49",)), ("action", "login", ("BIND",)))
# Open above: a role recording no version is taken to run the newest release (versions.holds); PRODUCTS bound it
MAPPINGS = (DetectionMapping("PingDS", ">=7.2", BIND, INVALID_CREDENTIALS),)
SELECTOR = (("action", ("login",)), ("outcome", ("failure",)))
# Brute force: 10 failed binds of one DN within any 5 minutes; spray: 10 DNs failing from one address within any 10
# minutes
BRUTE_FORCE, SPRAY = (10, 300), (10, 600)
LOGGED = ("the Json File-Based Access Logger is enabled (logs/ldap-access.audit.json; the sample DS Docker image logs "
          "to standard output instead)")


DETECTIONS = (
    ProductDetection(
        id="brute-force", title="PingDS brute force",
        description="Repeated binds with invalid credentials (result code 49) for one bind DN",
        products=PRODUCTS, server_role=DS, log_source="ldap-access", mappings=MAPPINGS,
        selector=SELECTOR, group_by=("subject",), distinct=None,
        threshold=BRUTE_FORCE[0], window_seconds=BRUTE_FORCE[1], window_kind="sliding",
        tactics=("credential-access",), techniques=("T1110.001",), severity="sev3",
        prerequisites=(LOGGED,),
        evidence=EVIDENCE, validation="documented"),
    ProductDetection(
        id="password-spray", title="PingDS password spray",
        description="Binds with invalid credentials (result code 49) for many different bind DNs from one client "
                    "address",
        products=PRODUCTS, server_role=DS, log_source="ldap-access", mappings=MAPPINGS,
        selector=SELECTOR, group_by=("source-ip",), distinct="subject",
        threshold=SPRAY[0], window_seconds=SPRAY[1], window_kind="sliding",
        tactics=("credential-access",), techniques=("T1110.003",), severity="sev2",
        prerequisites=(LOGGED,
                       "servers binding as their users (AM's or IDM's LDAP authentication, an LDAP proxy) are the "
                       "client address of those users' binds: exclude them, or tune the threshold, so their users' "
                       "ordinary failures don't read as one source spraying"),
        evidence=EVIDENCE, validation="documented"))

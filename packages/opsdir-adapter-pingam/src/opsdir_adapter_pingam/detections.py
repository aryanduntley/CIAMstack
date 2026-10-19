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
from 7.4, says a key manager reloaded, not that a key changed).

Derived from the record (record_detections: the deployment's own MFA, mfa.py), every one unverified until a lab's
or live system's events confirm it (milestone 7.2's live checks); no product names an "MFA bypass" event:

- route around MFA, per node of an MFA journey with an outcome onto a route that reaches success without passing the
  journey's MFA check (mfa.bypass_edges): its node event (AM-NODE-LOGIN-COMPLETED) with that nodeId and nodeOutcome.
  The 8.1 reference documents node events' entries[].info nodeId and nodeOutcome; that nodeOutcome is the outcome's
  id as the journey names it, and that earlier versions write the same, are unverified;
- MFA configuration change, per realm holding MFA journeys: AM-CONFIG-CHANGE in that realm. The reference lists
  config events' objectId, operation and changed fields but not how objectId names a journey or a node, nor the
  realm's form, so it watches the realm, not the journeys' own objects (narrowed by hand once an event shows it).

MFA device registrations, deletions and resets are watched by none: no audit event the references document names
them (each realm's configuration-change detection says so as a prerequisite)."""
from opsdir.core.contract import DetectionMapping, ProductDetection
from opsdir.core.directory import rdn_value
from .mfa import mfa_journeys, node_label
from .realms import ROOT, SERVER_ROLES, realm_path

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
NODE = "AM-NODE-LOGIN-COMPLETED"
# A node event's fields (8.1 reference): the node and the outcome it left by sit in its entries list
NODE_STEP = (("step", "entries[].info.nodeId"), ("step-outcome", "entries[].info.nodeOutcome"),
             ("subject", "principal"), ("realm", "realm"), ("action", "eventName"))
# What the MFA detections rest on: the 8.1 audit reference (node and config events) and node auditing
MFA_EVIDENCE = ("https://docs.pingidentity.com/pingam/8.1/monitoring/audit-logging-ref.html",
                "https://docs.pingidentity.com/pingam/8.1/monitoring/audit-logging.html",
                "https://docs.pingidentity.com/pingam/8/auth-nodes/post-install-tasks.html")
MFA_TECHNIQUES = ("T1556.006",)         # Modify Authentication Process: Multi-Factor Authentication

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


def _slug(text):
    """A name as part of a detection id: lower case, every run of other characters a hyphen."""
    out = "".join(c if c.isascii() and c.isalnum() else "-" for c in text.lower()).strip("-")
    return "-".join(p for p in out.split("-") if p) or "x"


def realm_slug(service):
    """A realm as part of a detection id: root for /, else its path's segments joined by hyphens."""
    path = realm_path(service)
    return "root" if path == ROOT else _slug(path)


def _node_step(product, versions):
    return DetectionMapping(product, versions, NODE_STEP, (("action", "login-step", (NODE,)),))


def bypass_detection(x, node, outcomes):
    """The detection of sign-ins taking a route around MFA (mfa.bypass_edges) from one node of an MFA journey (x: an
    MfaJourney) by its outcomes: its node event with that node and outcome. Unverified."""
    name, path, label = rdn_value(x.journey), realm_path(x.service), node_label(x, node)
    checks = ", ".join(node_label(x, v) for v in x.verifiers) or "none: no node of it checks a second factor"
    return ProductDetection(
        id=f"mfa-bypass.{realm_slug(x.service)}.{_slug(name)}.{_slug(node)}",
        title=f"PingAM route around MFA in journey {name}",
        description=f"A sign-in in journey `{name}` (realm {path}) left node `{label}` by outcome "
                    f"{' or '.join(outcomes)}, onto a route reaching success without passing its MFA check "
                    f"({checks}): it completes without a second factor",
        products=PRODUCTS, server_role=AM, log_source="authentication",
        mappings=(_node_step("ForgeRock AM", ">=7,<8"), _node_step("PingAM", ">=7")),
        selector=(("action", ("login-step",)), ("step", (node,)), ("step-outcome", tuple(outcomes))),
        group_by=(), distinct=None, threshold=None, window_seconds=None, window_kind=None,
        tactics=("credential-access", "defense-impairment"), techniques=MFA_TECHNIQUES, severity="sev2",
        prerequisites=(
            "the authentication audit topic is logged with node events (AM-NODE-LOGIN-COMPLETED in "
            "var/audit/authentication.audit.json): the 8.1 reference documents them; check a captured node event of "
            f"journey {name}, on the version you run, carries entries[].info.nodeId {node}",
            f"nodeOutcome is the outcome's id as the journey names it ({', '.join(outcomes)}): unverified, check a "
            "captured event",
            "the SIEM searches inside the event's entries list (entries[].info): check the rendered rule matches a "
            "captured event",
            f"unverified: send a sign-in down this route in a lab (node `{label}`, outcome "
            f"{' or '.join(outcomes)}) and check it fires before relying on it"),
        evidence=MFA_EVIDENCE, validation="unverified")


def config_detection(service, found):
    """The detection of configuration changes in a realm holding MFA journeys (found: its MfaJourneys): AM-CONFIG-CHANGE
    there, the journeys and their MFA nodes named so a person can narrow it. Unverified."""
    path = realm_path(service)
    names = ", ".join(rdn_value(j.journey) for j in found)
    nodes = ", ".join(f"{node_label(j, n)} ({n})" for j in found for n in (*j.verifiers, *j.steps))
    return ProductDetection(
        id=f"mfa-config.{realm_slug(service)}", title=f"PingAM configuration change in MFA realm {path}",
        description=f"A change to AM's configuration in realm {path}, whose "
                    f"{'journeys' if len(found) > 1 else 'journey'} {names} "
                    f"{'hold' if len(found) > 1 else 'holds'} its MFA (nodes {nodes}): a change there may remove a "
                    "journey's MFA step or route around it",
        products=PRODUCTS, server_role=AM, log_source="config",
        mappings=(_config("ForgeRock AM", ">=7,<8"), _config("PingAM", ">=7")),
        selector=(("action", ("config-change",)), ("realm", (path,))), group_by=(), distinct=None,
        threshold=None, window_seconds=None, window_kind=None,
        tactics=("persistence", "defense-impairment", "credential-access"), techniques=MFA_TECHNIQUES,
        severity="sev2",
        prerequisites=(
            "the config audit topic is logged (var/audit/config.audit.json), and the access topic for who made a "
            "change (the access event with the same transactionId)",
            f"config events carry the realm as {path}: the reference lists their objectId, operation and changed "
            "fields, not the realm's form; check a captured AM-CONFIG-CHANGE in this realm",
            f"it watches the whole realm: narrow it to the MFA journeys' own objects ({names}; nodes {nodes}) with "
            "object=<objectId> once a captured event shows how objectId names a journey and a node (the references "
            "don't say)",
            "MFA device registrations, deletions and resets aren't watched: no audit event the references document "
            "names them, so they need watching by other means",
            "unverified: change an MFA journey of the realm in a lab and check it fires before relying on it"),
        evidence=MFA_EVIDENCE, validation="unverified")


def record_detections(d):
    """The MFA detections PingAM derives from the record's own journeys (mfa.mfa_journeys), all unverified: a route
    around MFA per node with outcomes onto one (bypass_detection), then a configuration change per realm holding MFA
    journeys (config_detection)."""
    found = mfa_journeys(d)
    by_node = tuple((x, n) for x in found for n in dict.fromkeys(e.node for e in x.bypass))
    services = tuple({x.service.dn: x.service for x in found}.values())
    return (*(bypass_detection(x, n, tuple(e.outcome for e in x.bypass if e.node == n)) for x, n in by_node),
            *(config_detection(s, tuple(x for x in found if x.service.dn == s.dn)) for s in services))

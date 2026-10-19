"""The detections PingFederate declares (contract.ProductDetection): what its engines' security audit log
(pingfederate/log/audit.log: logs.py) is watched for, as the administrator's reference guide's security audit logging
page states its fields (11.3, 12.3, 13.0: trackingid, transactionid, event, subject, ip, app, connectionid, protocol,
host, role, status, adapterid, description, responsetime, pipe-separated by default). Declared:

- brute force and password spray: AUTHN_ATTEMPT events ("an authentication attempt against an identity provider (IdP)
  adapter instance") whose status is failure, per subject, or per ip counting distinct subjects. PingFederate has no
  realm: per subject only.

What the guide doesn't establish, each a prerequisite to confirm on a captured failed attempt (the declarations stay
documented until then): the status values (the guide says only "The status of the transactions"; failure is the
spelling assumed), and the field names a SIEM sees (the layout is pipe-separated text; the JSON template for audit.log
isn't published, and the documented JSON templates rename fields: trackingid as trackingId).

Not declared: administrator sign-in failures and configuration or key changes (admin.log and admin-api.log carry them,
LOGIN_ATTEMPT and MODIFY, CREATE, DELETE among their event types, but neither log's field names nor a failed sign-in's
value are documented).

Derived from the record (record_detections: the deployment's own MFA, mfa.py), each unverified until a lab's or live
system's events confirm it (milestone 7.2's live checks): a route around MFA, per IdP adapter instance whose successes
lead nowhere but past the policy's MFA (an exit): its AUTHN_ATTEMPT with that adapterid and status success (success
is the spelling assumed, as failure is above). Changes to the MFA adapters and the policies running them aren't
declared (admin-api.log's field names aren't published), nor routes no exit watches: the planner names both
(checks.check_mfa_watch)."""
from opsdir.core.contract import DetectionMapping, ProductDetection
from opsdir.core.directory import rdn_value
from .mfa import policy_mfa
from .naming import SERVER_ROLES

ENGINE = SERVER_ROLES[0]
EVIDENCE = ("https://docs.pingidentity.com/pingfederate/11.3/administrators_reference_guide/"
            "pf_security_audit_logging.html",
            "https://docs.pingidentity.com/pingfederate/12.3/administrators_reference_guide/"
            "pf_security_audit_logging.html",
            "https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/"
            "pf_security_audit_logging.html",
            "https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/pf_logging_json_format.html")
PRODUCTS = (("PingFederate", ">=11,<14"),)
ATTEMPT = (("subject", "subject"), ("source-ip", "ip"), ("outcome", "status"), ("action", "event"))
FAILED_ATTEMPT = (("outcome", "failure", ("failure",)), ("action", "login", ("AUTHN_ATTEMPT",)))
# Open above: a role recording no version is taken to run the newest release (versions.holds); PRODUCTS bound it
MAPPINGS = (DetectionMapping("PingFederate", ">=11", ATTEMPT, FAILED_ATTEMPT),)
SELECTOR = (("action", ("login",)), ("outcome", ("failure",)))
# Brute force: 10 failed attempts of one subject within any 5 minutes; spray: 10 subjects failing from one address
# within any 10 minutes
BRUTE_FORCE, SPRAY = (10, 300), (10, 600)
CONFIRM = ("a failed attempt's status says failure: PingFederate's guide doesn't list the status values, so check a "
           "captured failed AUTHN_ATTEMPT line (and correct the mapping if it says otherwise)",
           "audit.log reaches the SIEM as fields named as its pattern names them (event, subject, ip, status): the "
           "default layout is pipe-separated text to parse at ingestion, and a JSON template for audit.log isn't "
           "published (the documented ones rename fields)")


DETECTIONS = (
    ProductDetection(
        id="brute-force", title="PingFederate brute force",
        description="Repeated failed IdP adapter authentication attempts (AUTHN_ATTEMPT) for one subject",
        products=PRODUCTS, server_role=ENGINE, log_source="audit", mappings=MAPPINGS,
        selector=SELECTOR, group_by=("subject",), distinct=None,
        threshold=BRUTE_FORCE[0], window_seconds=BRUTE_FORCE[1], window_kind="sliding",
        tactics=("credential-access",), techniques=("T1110.001",), severity="sev3",
        prerequisites=CONFIRM, evidence=EVIDENCE, validation="documented"),
    ProductDetection(
        id="password-spray", title="PingFederate password spray",
        description="Failed IdP adapter authentication attempts (AUTHN_ATTEMPT) for many different subjects from one "
                    "client address",
        products=PRODUCTS, server_role=ENGINE, log_source="audit", mappings=MAPPINGS,
        selector=SELECTOR, group_by=("source-ip",), distinct="subject",
        threshold=SPRAY[0], window_seconds=SPRAY[1], window_kind="sliding",
        tactics=("credential-access",), techniques=("T1110.003",), severity="sev2",
        prerequisites=(*CONFIRM,
                       "ip is the client's address: behind a load balancer, check a captured line doesn't name the "
                       "balancer instead (every failure would then count from one address)"),
        evidence=EVIDENCE, validation="documented"))


# A successful attempt with one adapter instance (adapterid: the documented field naming it)
STEP = (("step", "adapterid"), *ATTEMPT)
SUCCEEDED = (("outcome", "success", ("success",)), ("action", "login", ("AUTHN_ATTEMPT",)))
MFA_TECHNIQUES = ("T1556.006",)         # Modify Authentication Process: Multi-Factor Authentication


def _slug(text):
    """An adapter id as part of a detection id: lower case, every run of other characters a hyphen."""
    out = "".join(c if c.isascii() and c.isalnum() else "-" for c in text.lower()).strip("-")
    return "-".join(p for p in out.split("-") if p) or "x"


def bypass_detection(found, adapter):
    """The detection of sign-ins taking a route around MFA through an exit (mfa.policy_mfa: found) adapter instance: its
    successful AUTHN_ATTEMPTs. Unverified."""
    trees = ", ".join(dict.fromkeys(rdn_value(r.tree) for r in found.routes if adapter in r.exits))
    return ProductDetection(
        id=f"mfa-bypass.{_slug(adapter)}", title=f"PingFederate route around MFA through adapter {adapter}",
        description=f"A successful authentication attempt (AUTHN_ATTEMPT) with IdP adapter `{adapter}`, whose "
                    f"successes in policy tree {trees} lead to success without an MFA step "
                    f"({', '.join(found.adapters)}): the sign-in completes without a second factor",
        products=PRODUCTS, server_role=ENGINE, log_source="audit",
        mappings=(DetectionMapping("PingFederate", ">=11", STEP, SUCCEEDED),),
        selector=(("action", ("login",)), ("outcome", ("success",)), ("step", (adapter,))), group_by=(),
        distinct=None, threshold=None, window_seconds=None, window_kind=None,
        tactics=("credential-access", "defense-impairment"), techniques=MFA_TECHNIQUES, severity="sev2",
        prerequisites=(
            "a successful attempt's status says success: PingFederate's guide doesn't list the status values, so "
            "check a captured successful AUTHN_ATTEMPT line (and correct the mapping if it says otherwise)",
            CONFIRM[1],
            f"adapter {adapter} runs nowhere else: the record's policies run it only on routes around MFA, but a "
            "connection mapping it directly (outside the authentication policies) counts too",
            f"unverified: sign in through tree {trees} past adapter {adapter} in a lab and check it fires before "
            "relying on it"),
        evidence=EVIDENCE, validation="unverified")


def record_detections(d):
    """The MFA detections PingFederate derives from the record's authentication policies (mfa.policy_mfa): a route
    around MFA per exit adapter instance on one, unverified."""
    found = policy_mfa(d)
    watched = tuple(dict.fromkeys(a for r in found.routes for a in r.exits))
    return tuple(bypass_detection(found, a) for a in watched)

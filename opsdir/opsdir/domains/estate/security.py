"""Cloud security services: what watches and assesses the cloud an environment runs in, as bindings of each
environment (ciamSecurityService). Four kinds: threat detection (what it watches: management activity, identity,
network, compute, containers, storage, databases, key vaults, applications), vulnerability scanning, configuration
recording (resources' configuration and its changes, kept for a time or exported) and posture assessment (against
compliance frameworks by neutral ids the clouds share, and the cloud's own baseline, which never stands in for another
cloud's). Each covers one account or the whole organization, every region or one, sends its findings to a binding's
role (an alert channel, a log destination, an object store, a stream) or keeps them, and keeps its records for a time.
The report, and the planner's check. Pure.

A target without a kind the source runs is a blocker for threat detection and vulnerability scanning (a detective
control lost on the move), for posture when the source is assessed against a regulatory framework, and for
configuration recording when the source exports its history; otherwise an action. A target narrower than the source
(areas watched, frameworks and baselines assessed, organization, regions, findings sent somewhere, records kept) gives
actions, which block the move where the target's data is classified restricted."""
from collections import namedtuple

from ...core.directory import get, one, rdn_value, subtree, values
from ...core.environment import env_model, of_class, one_role
from ...core.findings import findings, responsible
from ...core.naming import branch
from ..observability.audit import INDEFINITE
from .naming import REGULATORY, RESTRICTED, SECURITY_AREAS, SECURITY_KINDS

AREA = "Security"
SERVICE = "ciamSecurityService"
SECURITY_HEADERS = ("environment", "security service", "kind", "scope", "all regions", "watches", "assesses",
                    "findings to", "keep (days)", "kept by")
# What an environment's services of one kind give together: the areas they watch, the frameworks and baselines they
# assess, whether any covers the organization or every region, whether any sends its findings somewhere, and the
# longest any keeps its records (INDEFINITE: forever; None: not recorded).
SecurityCoverage = namedtuple("SecurityCoverage", ("areas", "standards", "baselines", "organization", "all_regions",
                                                   "routed", "days"))
_WHY = {"threat-detection": "threats to the target's cloud would go undetected",
        "vulnerability-scanning": "the target's vulnerabilities would go unfound",
        "config-recording": "changes to the target's resources would go unrecorded",
        "posture": "the target's posture would go unassessed"}


def security_services(m, kind=None):
    """Environment m's security services (of one kind when kind is given)."""
    return [s for s in of_class(m, SERVICE) if kind is None or one(s, "ciamSecurityKind") == kind]


def security_role(resource, roles):
    """The binding role of a security service a cloud reports without one (ImportKind role): its kind."""
    kind = resource.attrs.get("ciamSecurityKind")
    return (kind[0] if isinstance(kind, (tuple, list)) else kind) if kind else None


def findings_destination(m, service):
    """The binding of environment m a security service's findings (or recorded configuration) go to (its
    ciamFindingsRole), or None."""
    role = one(service, "ciamFindingsRole")
    return one_role(m, role) if role else None


def _days(b):
    v = one(b, "ciamRetentionDays") if b is not None else None
    return int(v) if v is not None else None


def _longest(days):
    known = [d for d in days if d is not None]
    return INDEFINITE if INDEFINITE in known else max(known) if known else None


def service_coverage(m, services):
    """The SecurityCoverage of environment m's security services taken together."""
    return SecurityCoverage(
        tuple(a for a in SECURITY_AREAS if any(a in values(s, "ciamSecurityCoverage") for s in services)),
        tuple(sorted({v for s in services for v in values(s, "ciamComplianceStandard")})),
        tuple(sorted({v for s in services for v in values(s, "ciamSecurityBaseline")})),
        any(one(s, "ciamAuditScope") == "organization" for s in services),
        any(one(s, "ciamAllRegions") == "TRUE" for s in services),
        any(findings_destination(m, s) is not None for s in services),
        _longest([d for s in services for d in (_days(s), _days(findings_destination(m, s)))]))


def _missing(ctx, kind, src):
    """(the text for a target running no service of a kind the source runs, whether it blocks the move)."""
    cov = service_coverage(ctx.src, src)
    regulatory = sorted(set(cov.standards) & REGULATORY)
    blocks = (kind in ("threat-detection", "vulnerability-scanning") or (kind == "posture" and bool(regulatory))
              or (kind == "config-recording" and cov.routed))
    why = (f", against {', '.join(regulatory)}" if kind == "posture" and regulatory else
           ", exporting its history" if kind == "config-recording" and cov.routed else "")
    return (f"{ctx.src.label} runs {kind} ({', '.join(rdn_value(s) for s in src)}{why}) and {ctx.dst.label} runs "
            f"none: {_WHY[kind]}. Record the target's (its own, or the organization's the landing zone keeps).",
            blocks)


def _shorter(have, need):
    return have is not None and need is not None and have != INDEFINITE and (need == INDEFINITE or have < need)


def _narrower(ctx, kind, src, dst):
    """What the target's services of a kind give less of than the source's."""
    s, t = service_coverage(ctx.src, src), service_coverage(ctx.dst, dst)
    a, b = ctx.src.label, ctx.dst.label
    areas = [x for x in s.areas if x not in t.areas]
    standards = [x for x in s.standards if x not in t.standards]
    kept = "forever" if s.days == INDEFINITE else f"{s.days} days"
    return [text for text in (
        *((f"{a}'s {kind} watches {', '.join(areas)} and {b}'s doesn't: turn it on in the target (or record what "
           "watches it there).",) if areas else ()),
        *((f"{a} is assessed against {', '.join(standards)} and {b} isn't: assess the target against it (or decide "
           "it no longer applies).",) if standards else ()),
        *((f"{a} is assessed against its cloud's own baseline ({', '.join(s.baselines)}) and {b} against none: turn "
           "on the target cloud's.",) if s.baselines and not t.baselines else ()),
        *((f"{a}'s {kind} covers the whole organization and {b}'s one account: accounts added later would go "
           "uncovered.",) if s.organization and not t.organization else ()),
        *((f"{a}'s {kind} runs in every region and {b}'s in one: the target's other regions would go uncovered.",)
          if s.all_regions and not t.all_regions else ()),
        *((_unrouted(kind, a, b),) if s.routed and not t.routed else ()),
        *((f"{a} keeps its {kind} records {kept} and {b} {t.days} days: keep the target's at least as long.",)
          if _shorter(t.days, s.days) else ()))]


def _unrouted(kind, a, b):
    """The action for a target whose service keeps what the source's sends on (findings, or exported history)."""
    if kind == "config-recording":
        return (f"{a} exports its configuration history and {b} keeps it in the service only: export the target's (or "
                "decide the service's own history is enough).")
    return (f"{a}'s {kind} sends its findings on and {b}'s keeps them in the service: send them where someone acts on "
            "them.")


def _unbound(ctx, dst):
    """Blockers for the target's services whose findings go to a role it doesn't bind."""
    return [(AREA, f"Security service `{rdn_value(s)}` in {ctx.dst.label} sends its findings to role "
                   f"`{one(s, 'ciamFindingsRole')}`, which {ctx.dst.label} doesn't bind: they reach no one. Record "
                   "where they go.", responsible(ctx.d, s, ctx.dst.env))
            for s in dst if one(s, "ciamFindingsRole") and findings_destination(ctx.dst, s) is None]


def check_security(ctx):
    """Per kind: a target running none of a kind the source runs (a blocker or an action, see the module), a target
    service whose findings go to a role it doesn't bind (a blocker), and a target narrower than the source (actions;
    blockers where the target's data is classified restricted). Nothing when neither environment records a service."""
    if not security_services(ctx.src) and not security_services(ctx.dst):
        return findings()
    owner = responsible(ctx.d, ctx.dst.env)
    restricted = one(ctx.dst.env, "ciamDataClassification") == RESTRICTED
    pairs = [(k, security_services(ctx.src, k), security_services(ctx.dst, k)) for k in SECURITY_KINDS]
    missing = [_missing(ctx, k, src) for k, src, dst in pairs if src and not dst]
    narrower = [text for k, src, dst in pairs if src and dst for text in _narrower(ctx, k, src, dst)]
    held = f" {ctx.dst.label}'s data is classified {RESTRICTED}: this blocks the move."
    blockers = [*((AREA, text, owner) for text, blocks in missing if blocks),
                *(_unbound(ctx, security_services(ctx.dst))),
                *((AREA, text + held, owner) for text in narrower if restricted)]
    actions = [*((AREA, text, owner, ctx.cutover) for text, blocks in missing if not blocks),
               *((AREA, text, owner, ctx.cutover) for text in narrower if not restricted)]
    kinds = [k for k, _, dst in pairs if dst]
    return findings(blockers=blockers, actions=actions,
                    ok=() if blockers or actions or not kinds else
                    (f"Security services recorded in {ctx.dst.label}: {', '.join(kinds)}.",))


def _keeper(m, s):
    ref = one(s, "ciamManagedBy")
    keeper = get(m.d, ref) if ref else None
    return rdn_value(keeper) if keeper is not None else "platform"


def _yes(s, attr):
    v = one(s, attr)
    return "yes" if v == "TRUE" else "no" if v == "FALSE" else ""


def security_rows(d, dn=None):
    """One row per security service of every environment: kind, scope, all regions, the areas it watches, the
    frameworks and baselines it assesses, the role its findings go to, how long its records are kept (its own or its
    findings destination's, the longer), and who keeps it (the platform team unless ciamManagedBy names someone)."""
    models = [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")]
    return [(m.label, rdn_value(s), one(s, "ciamSecurityKind"), one(s, "ciamAuditScope", ""),
             _yes(s, "ciamAllRegions"), ", ".join(values(s, "ciamSecurityCoverage")),
             ", ".join((*values(s, "ciamComplianceStandard"), *values(s, "ciamSecurityBaseline"))),
             one(s, "ciamFindingsRole", ""), "" if days is None else "forever" if days == INDEFINITE else str(days),
             _keeper(m, s))
            for m in models for s in security_services(m)
            for days in (_longest((_days(s), _days(findings_destination(m, s)))),)]

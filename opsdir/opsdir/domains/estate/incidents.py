"""Incident reporting: the reporting obligations each environment is held to (ciamReportingObligationRef: ones the
estate defines under ou=reporting-obligations, named by the regime's id: a clock from discovery to report, the
authority reports go to, who files them and with which certificate, where malware goes, how long evidence is preserved
after a report), the findings each security service also sends to the incident process (those at or above its
ciamIncidentSeverity, to its ciamIncidentRole), and the incidents (governance) that fall under an obligation: when each
was discovered, when its report is due and whether it was filed in time. The planner's check and the two reports.
Pure.

A target not held to an obligation the source is held to blocks the move, as does one held to an obligation no one can
meet (no one files, no authority, no certificate to file with) or whose incident process gets nothing: routing the
source has and the target lost blocks where the target is held to an obligation, a role the target doesn't bind
always. A target routing only more severe findings than the source gives an action, a blocker where its data is
classified restricted. Monitoring records (audit trails, threat detection) kept fewer days than an obligation preserves
evidence (the longer of a destination's retention and its immutability lock) block the move unless the obligation names
the runbook placing a preservation hold (then an action)."""
from collections import namedtuple
import datetime as dt

from ...core.directory import get, gtime_at, is_a, one, rdn_value, subtree, values
from ...core.environment import env_model, one_role
from ...core.findings import findings, responsible
from ...core.naming import SUFFIX, branch
from ..governance.domain import display_name
from ..observability.audit import INDEFINITE, audit_trails, trail_destination
from .naming import RESTRICTED, SECURITY_KINDS, SEVERITIES
from .security import findings_destination, security_services

AREA = "Incident reporting"
OBLIGATION = "ciamReportingObligation"
INCIDENT = "ciamIncident"
CERTIFICATE = "ciamCertificate"
DEFAULT_SEVERITY = "high"
REPORTING_HEADERS = ("environment", "obligation", "report within (h)", "internal (h)", "authority", "filed by",
                     "certificate", "expires", "preserve (days)", "incident routes")
INCIDENT_HEADERS = ("incident", "obligations", "environments", "discovered", "report due", "reported",
                    "report number", "status", "malware submitted", "preserved until", "media")
# A security service's route to the incident process: the service, its kind, the least severe finding it sends, the
# role it sends them to and the binding filling that role (None: the environment binds none).
IncidentRoute = namedtuple("IncidentRoute", ("service", "kind", "severity", "role", "binding"))


def _obligation(d, ref):
    e = get(d, ref) if ref else None
    return e if e is not None and is_a(e, OBLIGATION) else None


def obligations_of(m):
    """The reporting obligations environment m is held to, in the order it names them (refs that aren't one are left
    out; the check names them)."""
    return tuple(o for o in (_obligation(m.d, ref) for ref in values(m.env, "ciamReportingObligationRef"))
                 if o is not None)


def severity_rank(severity):
    """Position of a severity in SEVERITIES (low 0 .. critical 3); the default's when the value isn't one."""
    return SEVERITIES.index(severity if severity in SEVERITIES else DEFAULT_SEVERITY)


def incident_routes(m):
    """Environment m's security services that send their findings at or above a severity to the incident process."""
    return tuple(IncidentRoute(s, one(s, "ciamSecurityKind"), one(s, "ciamIncidentSeverity") or DEFAULT_SEVERITY,
                               one(s, "ciamIncidentRole"), one_role(m, one(s, "ciamIncidentRole")))
                 for s in security_services(m) if one(s, "ciamIncidentRole"))


def _threshold(routes, kind):
    """The least severe finding of a kind any of the routes sends on (as a rank), or None when none of them does."""
    ranks = [severity_rank(r.severity) for r in routes if r.kind == kind]
    return min(ranks) if ranks else None


def _affected(d, incident):
    """The environments an incident affected (refs that aren't environments are left out)."""
    return tuple(env_model(d, ref) for ref in values(incident, "ciamAffectedEnvironment")
                 if (e := get(d, ref)) is not None and is_a(e, "ciamEnvironment"))


def incident_obligations(d, incident):
    """The reporting obligations an incident falls under: its own, else those of the environments it affected."""
    own = tuple(o for o in (_obligation(d, ref) for ref in values(incident, "ciamReportingObligationRef")) if o)
    if own:
        return own
    found = (o for m in _affected(d, incident) for o in obligations_of(m))
    return tuple({o.dn: o for o in found}.values())


def _at(e, attr):
    v = one(e, attr)
    return gtime_at(v) if v else None


def report_due(d, incident):
    """When an incident's report is due: discovery + the shortest clock of its obligations (None without either)."""
    discovered, hours = _at(incident, "ciamDiscoveredAt"), [int(one(o, "ciamReportingHours"))
                                                              for o in incident_obligations(d, incident)]
    return discovered + dt.timedelta(hours=min(hours)) if discovered and hours else None


# ------------------------------------------------------------------ planner check
def _not_held(ctx, owner):
    held = {o.dn for o in obligations_of(ctx.dst)}
    return [(AREA, f"{ctx.src.label} is held to reporting obligation `{rdn_value(o)}` and {ctx.dst.label} isn't: its "
                   "incidents would go unreported. Hold the target to it (ciamReportingObligationRef), or record why "
                   "it no longer applies.", owner)
            for o in obligations_of(ctx.src) if o.dn not in held]


def _broken_refs(ctx, owner):
    return [(AREA, f"{ctx.dst.label} names `{ref}` as a reporting obligation, which isn't one (a "
                   f"{OBLIGATION} under ou=reporting-obligations).", owner)
            for ref in values(ctx.dst.env, "ciamReportingObligationRef") if _obligation(ctx.d, ref) is None]


def _party(d, o, attr):
    ref = one(o, attr)
    e = get(d, ref) if ref else None
    return e if e is not None and is_a(e, "ciamParty") else None


def _certificate(d, o):
    ref = one(o, "ciamReportingCertificateRef")
    e = get(d, ref) if ref else None
    return e if e is not None and is_a(e, CERTIFICATE) else None


def _unmet(ctx, owner):
    """Blockers for the target's obligations no one can meet: no one files, no authority, no certificate."""
    gaps = [(o, [what for what, missing in (
        ("no one files its reports (ciamReportingParty)", _party(ctx.d, o, "ciamReportingParty") is None),
        ("it names no authority to report to (ciamReportingAuthority)",
         _party(ctx.d, o, "ciamReportingAuthority") is None),
        ("it names no certificate to file with (ciamReportingCertificateRef)", _certificate(ctx.d, o) is None))
        if missing]) for o in obligations_of(ctx.dst)]
    return [(AREA, f"Reporting obligation `{rdn_value(o)}` ({ctx.dst.label} is held to it) can't be met: "
                   f"{'; '.join(why)}. Record it.", owner) for o, why in gaps if why]


def _unreachable(ctx, owner):
    """Actions for the target's filers no one can reach (no mail, telephone or contact link)."""
    parties = {p.dn: p for o in obligations_of(ctx.dst) for p in (_party(ctx.d, o, "ciamReportingParty"),)
               if p is not None and not _reach(p)}
    return [(AREA, f"`{rdn_value(p)}` files {ctx.dst.label}'s incident reports and the record gives no way to reach "
                   "them (mail, telephoneNumber, ciamContactUrl): record one.", owner, ctx.cutover)
            for p in parties.values()]


def _unbound(ctx):
    return [(AREA, f"Security service `{rdn_value(r.service)}` in {ctx.dst.label} sends {r.severity} and worse "
                   f"findings to the incident process through role `{r.role}`, which {ctx.dst.label} doesn't bind: "
                   "they reach no one. Record where they go.", responsible(ctx.d, r.service, ctx.dst.env))
            for r in incident_routes(ctx.dst) if r.binding is None]


def _routing(ctx, held, restricted):
    """(blockers, actions) for the incident routing the target lost or narrowed, per kind of security service."""
    src, dst = incident_routes(ctx.src), incident_routes(ctx.dst)
    pairs = [(k, _threshold(src, k), _threshold(dst, k)) for k in SECURITY_KINDS]
    a, b = ctx.src.label, ctx.dst.label
    lost = [(f"{a}'s {k} sends {SEVERITIES[s]} and worse findings to the incident process and {b}'s sends none: "
             "they would wait for someone to notice them. Route them (ciamIncidentRole).", bool(held))
            for k, s, t in pairs if s is not None and t is None]
    higher = [(f"{a}'s {k} sends {SEVERITIES[s]} and worse findings to the incident process and {b}'s only "
               f"{SEVERITIES[t]} and worse: lower the target's ciamIncidentSeverity to {SEVERITIES[s]}.", restricted)
              for k, s, t in pairs if s is not None and t is not None and t > s]
    held_text = f" {b} is held to {', '.join(rdn_value(o) for o in held)}: this blocks the move." if held else ""
    restricted_text = f" {b}'s data is classified {RESTRICTED}: this blocks the move."
    return ([*(text + held_text for text, blocks in lost if blocks),
             *(text + restricted_text for text, blocks in higher if blocks)],
            [*(text for text, blocks in lost if not blocks), *(text for text, blocks in higher if not blocks)])


def _kept(*entries):
    """How many days these entries keep records, the longest (INDEFINITE: forever; None: none of them says): each
    keeps them its retention (ciamRetentionDays) or, when longer, its immutability lock (ciamStorageLockDays)."""
    days = [int(v) for e in entries if e is not None for v in (one(e, "ciamRetentionDays"), one(e, "ciamStorageLockDays"))
            if v is not None]
    return INDEFINITE if any(one(e, "ciamRetentionDays") == str(INDEFINITE) for e in entries if e is not None) \
        else max(days) if days else None


def _records(m):
    """(what keeps monitoring evidence, the days it keeps it or None when not recorded) for environment m: its audit
    trails (their destinations) and threat detection (the service, or where its findings go)."""
    return [*((f"audit trail `{rdn_value(t)}`", _kept(trail_destination(m, t))) for t in audit_trails(m)),
            *((f"threat-detection `{rdn_value(s)}`", _kept(s, findings_destination(m, s)))
              for s in security_services(m, "threat-detection"))]


def _short(days, need):
    return days is None or (days != INDEFINITE and days < need)


def _preservation(ctx, owner):
    """(blockers, actions) for the target's records kept fewer days than an obligation preserves evidence."""
    found = [(o, int(one(o, "ciamPreservationDays")), [(what, days) for what, days in _records(ctx.dst)
                                                        if _short(days, int(one(o, "ciamPreservationDays")))])
             for o in obligations_of(ctx.dst) if one(o, "ciamPreservationDays")]
    texts = [(o, f"Reporting obligation `{rdn_value(o)}` preserves evidence {need} days after a report and "
                 f"{ctx.dst.label} keeps less: "
                 f"{', '.join(f'{what} ' + ('(not recorded)' if days is None else f'{days} days') for what, days in short)}."
                 f" Keep them at least {need} days") for o, need, short in found if short]
    return ([(AREA, text + ", or record the runbook placing a preservation hold at discovery (ciamRunbookRef).", owner)
             for o, text in texts if not values(o, "ciamRunbookRef")],
            [(AREA, text + f", or confirm the hold runbook copies them within {ctx.dst.label}'s retention.", owner,
              ctx.cutover) for o, text in texts if values(o, "ciamRunbookRef")])


def check_incident_reporting(ctx):
    """The target's incident reporting against the source's (see the module). Nothing when neither environment is held
    to an obligation, routes findings to the incident process, or (the target) holds restricted data."""
    held = obligations_of(ctx.dst)
    restricted = one(ctx.dst.env, "ciamDataClassification") == RESTRICTED
    if not (obligations_of(ctx.src) or held or incident_routes(ctx.src) or incident_routes(ctx.dst) or restricted
            or values(ctx.dst.env, "ciamReportingObligationRef")):
        return findings()
    owner = responsible(ctx.d, ctx.dst.env)
    route_blockers, route_actions = _routing(ctx, held, restricted)
    kept_blockers, kept_actions = _preservation(ctx, owner)
    blockers = [*_not_held(ctx, owner), *_broken_refs(ctx, owner), *_unmet(ctx, owner), *_unbound(ctx),
                *((AREA, text, owner) for text in route_blockers), *kept_blockers]
    actions = [*(((AREA, f"{ctx.dst.label}'s data is classified {RESTRICTED} and it is held to no reporting "
                         "obligation: confirm none applies (DFARS 252.204-7012 does wherever covered defense "
                         "information is held), or hold it to the ones that do.", owner, ctx.cutover),)
                 if restricted and not held else ()),
               *_unreachable(ctx, owner), *((AREA, text, owner, ctx.cutover) for text in route_actions),
               *kept_actions]
    return findings(blockers=blockers, actions=actions,
                    ok=() if blockers or actions or not held else
                    (f"{ctx.dst.label} is held to {', '.join(rdn_value(o) for o in held)}, with its incident "
                     "routing and evidence kept as long as the source's.",))


def _reach(p):
    """How a party is reached: its mail, telephone and contact link, those it has."""
    return tuple(v for v in (one(p, "mail"), one(p, "telephoneNumber"), one(p, "ciamContactUrl")) if v)


# ------------------------------------------------------------------ reports
def _name(e):
    """A party's name and how to reach it."""
    if e is None:
        return ""
    reach = _reach(e)
    return f"{display_name(e)} ({', '.join(reach)})" if reach else display_name(e)


def _routes_text(m):
    return "; ".join(f"{rdn_value(r.service)}: {r.severity}+ to {r.role}" + ("" if r.binding is not None else
                                                                            " (unbound)")
                     for r in incident_routes(m))


def incident_reporting_rows(d, dn=None):
    """One row per environment and reporting obligation it is held to (one with no obligation for an environment that
    only routes findings to the incident process): the clocks, the authority and who files the reports (each with how
    to reach them: mail, telephone, where reports are filed), the certificate and its expiry, how long evidence is preserved, and the environment's incident routes."""
    models = [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")]
    return [(m.label, rdn_value(o) if o is not None else "",
             one(o, "ciamReportingHours", "") if o is not None else "",
             one(o, "ciamInternalReportingHours", "") if o is not None else "",
             _name(_party(d, o, "ciamReportingAuthority")) if o is not None else "",
             _name(_party(d, o, "ciamReportingParty")) if o is not None else "",
             rdn_value(cert) if cert is not None else "",
             one(cert, "ciamNotAfter", "")[:8] if cert is not None else "",
             one(o, "ciamPreservationDays", "") if o is not None else "", _routes_text(m))
            for m in models for o in (obligations_of(m) or ((None,) if incident_routes(m) else ()))
            for cert in ((_certificate(d, o) if o is not None else None),)]


def _when(at):
    return at.strftime("%Y-%m-%d %H:%MZ") if at else ""


def _status(due, reported, as_of):
    if due is None:
        return "discovery not recorded"
    if reported is not None:
        return "on time" if reported <= due else "late"
    return "overdue" if due.date() < as_of else "open"


def reportable_incident_rows(d, dn=None, as_of=None):
    """One row per incident under a reporting obligation: the obligations, the environments it affected, when it was
    discovered, its report's due time, when it was reported and the authority's number, its status (on time, late,
    open, overdue as of the day), malware submitted, until when its media are preserved and what the authority asked
    of them."""
    day = as_of or dt.date.today()
    return [(rdn_value(i), ", ".join(rdn_value(o) for o in obligations),
             ", ".join(m.label for m in _affected(d, i)),
             _when(_at(i, "ciamDiscoveredAt")), _when(due), _when(_at(i, "ciamReportedAt")), one(i, "ciamReportRef", ""),
             _status(due, _at(i, "ciamReportedAt"), day), _when(_at(i, "ciamMalwareSubmittedAt")),
             _when(_at(i, "ciamPreservedUntil")), one(i, "ciamMediaRequest", ""))
            for i in subtree(d, SUFFIX, INCIDENT)
            for obligations in (incident_obligations(d, i),) if obligations
            for due in (report_due(d, i),)]

"""Plan of action and milestones, exceptions and compliance assessments: the estate's known weaknesses and how each is
corrected (ciamPoamItem under ou=poam), the deviations a risk authority approved (ciamRiskException under
ou=exceptions: accepted risks, false positives, operational requirements, controls met another way), each for the
environments it names and until a date, and the compliance assessments of the environments (ciamComplianceAssessment
under ou=assessments). A cloud's suppression of findings (ciamSuppression, a binding) carries out an exception there.
The planner's check, its acceptance of findings, and the reports. Pure.

An exception in force (approved, by whom, under which risk authority, owned, until a date not yet past) accepts the
planner findings it names for its environments: they are shown as accepted, not counted, never hidden; a blocker of a
broken contract, a key kept wrongly, a reporting obligation, a security service, an exception or POA&M itself, or one
naming withheld credentials is never accepted. Exceptions belong to the environments they name: the source's don't
carry to the target. CMMC Level 2 (32 CFR 170.21): a Conditional status needs a score of at least 0.8 of the maximum,
no POA&M requirement worth more than 1 point (SC.L2-3.13.11, encryption not FIPS-validated: 3), none of six
requirements on the POA&M, and the POA&M closed out within 180 days of the Conditional status date."""
import datetime as dt

from ...core.directory import date_of, get, is_a, norm_dn, one, rdn_value, subtree, values
from ...core.environment import env_model, of_class
from ...core.findings import findings, responsible
from ...core.naming import SUFFIX
from ..governance.domain import display_name
from .naming import (CMMC_CLOSEOUT_DAYS, CMMC_FIPS_EXCEPTION, CMMC_FRAMEWORK, CMMC_MIN_RATIO, CMMC_NEVER_POAM,
                     EXCEPTIONS, SUPPRESSION_PREFIX, UNACCEPTABLE_AREAS, UNACCEPTABLE_PHRASES)
from .security import security_services

AREA_EXCEPTIONS, AREA_POAM = "Exceptions", "POA&M"
ITEM, EXCEPTION, ASSESSMENT, SUPPRESSION = ("ciamPoamItem", "ciamRiskException", "ciamComplianceAssessment",
                                            "ciamSuppression")
NIST_171 = "nist-800-171-r2"
POAM_HEADERS = ("POA&M item", "environments", "controls", "weakness", "risk", "found", "scheduled", "status",
                "points", "exceptions")
EXCEPTION_HEADERS = ("exception", "kind", "status", "environments", "covers", "accepts", "risk authority",
                     "approved", "expires", "in force")
ASSESSMENT_HEADERS = ("assessment", "framework", "kind", "score", "status", "assessed", "closeout due",
                      "full score by", "environments")


def exception_dn(cn):
    """The DN of the exception named cn."""
    return f"cn={cn},{EXCEPTIONS}"


def suppression_name(s):
    """The name a cloud gives a suppression binding: exc-<the cn of the exception it carries out> (its own cn when it
    names none)."""
    ref = one(s, "ciamExceptionRef")
    return f"{SUPPRESSION_PREFIX}{ref.split(',', 1)[0].split('=', 1)[1]}" if ref else rdn_value(s)


def exception_of(name):
    """The exception cn a cloud suppression's name carries (exc-<cn>), or None."""
    return name[len(SUPPRESSION_PREFIX):] if name and name.startswith(SUPPRESSION_PREFIX) else None


def suppression_role(resource, roles):
    """The binding role of a suppression a cloud reports without one (ImportKind role): suppression-<exception>."""
    exc = resource.attrs.get("ciamExceptionRef")
    exc = exc[0] if isinstance(exc, (tuple, list)) else exc
    return f"suppression-{exc}" if exc else f"suppression-{resource.name}"


def suppression_prepare(d, dn, r):
    """A suppression read from a cloud names its exception by cn: it links it (ciamExceptionRef) when the record holds
    that exception, else drops the name (the planner then says no exception covers it)."""
    exc = r.attrs.get("ciamExceptionRef")
    exc = exc[0] if isinstance(exc, (tuple, list)) else exc
    if not exc or "=" in exc:
        return r
    held = get(d, exception_dn(exc))
    attrs = {k: v for k, v in r.attrs.items() if k != "ciamExceptionRef"}
    return r._replace(attrs={**attrs, **({"ciamExceptionRef": (exception_dn(exc),)} if held is not None and
                                         is_a(held, EXCEPTION) else {})})


def _names(e, env_dn):
    return any(norm_dn(ref) == norm_dn(env_dn) for ref in values(e, "ciamAffectedEnvironment"))


def _of(d, oc, env_dn=None):
    return tuple(e for e in subtree(d, SUFFIX, oc) if env_dn is None or _names(e, env_dn))


def exceptions_for(m):
    """The exceptions naming environment m."""
    return _of(m.d, EXCEPTION, m.dn)


def _day(e, attr):
    return date_of(e, attr)


def in_force(e, day):
    """Whether an exception stands on a day: approved, by whom, under which risk authority, owned, until a date not yet
    past."""
    expires = _day(e, "ciamExpiresAt")
    return (one(e, "ciamExceptionStatus") == "approved" and bool(one(e, "ciamApprovedBy"))
            and bool(one(e, "ciamRiskAuthority")) and bool(values(e, "ciamOwner")) and expires is not None
            and expires >= day)


def acceptable(kind, area, text):
    """Whether an exception may accept a planner finding (see the module)."""
    return not (kind == "blocker" and (area in UNACCEPTABLE_AREAS or any(p in text for p in UNACCEPTABLE_PHRASES)))


def _accepts(e):
    """(area, phrase) of each planner finding an exception names."""
    return tuple(tuple(v.split(": ", 1)) for v in values(e, "ciamAcceptsFinding") if ": " in v)


def _authority(d, e):
    ref = one(e, "ciamRiskAuthority")
    party = get(d, ref) if ref else None
    return display_name(party) if party is not None else (ref or "")


def _why(d, e):
    return (f"{rdn_value(e)} ({one(e, 'ciamExceptionKind')}) until {_day(e, 'ciamExpiresAt')} by "
            f"{_authority(d, e)}")


def accept_exceptions(ctx, blockers, actions):
    """(blockers, actions, accepted): the target's exceptions in force accept the findings they name."""
    standing = [e for e in exceptions_for(ctx.dst) if in_force(e, ctx.as_of)]

    def match(kind, area, text):
        return next((e for e in standing for a, phrase in _accepts(e) if a == area and phrase in text
                     and acceptable(kind, area, text)), None)
    b_hits = [(b, match("blocker", b[0], b[1])) for b in blockers]
    a_hits = [(a, match("action", a[0], a[1])) for a in actions]
    return ([b for b, e in b_hits if e is None], [a for a, e in a_hits if e is None],
            [*(("blocker", *b[:3], _why(ctx.d, e)) for b, e in b_hits if e is not None),
             *(("action", *a[:3], _why(ctx.d, e)) for a, e in a_hits if e is not None)])


# ------------------------------------------------------------------ checks
def requirement_number(ref):
    """The NIST SP 800-171 requirement number a CMMC Level 2 or NIST SP 800-171 Rev. 2 control names, else None."""
    framework, _, control = ref.partition(":")
    if framework == CMMC_FRAMEWORK:
        return control.rsplit("-", 1)[-1] if "-" in control else None
    return control if framework == NIST_171 else None


def _frameworks(ref):
    return ref.partition(":")[0]


def _incomplete(ctx, exc):
    """Blockers for the target's approved exceptions missing what makes an approval stand."""
    gaps = [(e, [what for what, missing in (("no approver (ciamApprovedBy)", not one(e, "ciamApprovedBy")),
                                            ("no risk authority (ciamRiskAuthority)", not one(e, "ciamRiskAuthority")),
                                            ("no expiry (ciamExpiresAt)", not one(e, "ciamExpiresAt")),
                                            ("no owner", not values(e, "ciamOwner")))
                 if missing]) for e in exc if one(e, "ciamExceptionStatus") == "approved"]
    return [(AREA_EXCEPTIONS, f"Exception `{rdn_value(e)}` for {ctx.dst.label} is approved with {', '.join(why)}: an "
                              "acceptance nobody can stand behind. Record it, or withdraw the exception.",
             responsible(ctx.d, e, ctx.dst.env)) for e, why in gaps if why]


def _expired(ctx, exc):
    return [(AREA_EXCEPTIONS, f"Exception `{rdn_value(e)}` for {ctx.dst.label} expired on {_day(e, 'ciamExpiresAt')}: "
                              "what it accepted counts again. Renew it under its risk authority, or close it.",
             responsible(ctx.d, e, ctx.dst.env), ctx.cutover)
            for e in exc if one(e, "ciamExceptionStatus") == "approved" and _day(e, "ciamExpiresAt") is not None
            and _day(e, "ciamExpiresAt") < ctx.as_of]


def _beyond_item(ctx, exc):
    """Actions for exceptions that outlast the POA&M item they belong to."""
    found = [(e, item) for e in exc for ref in (one(e, "ciamPoamRef"),) if ref
             for item in (get(ctx.d, ref),) if item is not None and is_a(item, ITEM)]
    return [(AREA_EXCEPTIONS, f"Exception `{rdn_value(e)}` runs until {_day(e, 'ciamExpiresAt')}, past POA&M item "
                              f"`{rdn_value(item)}`'s scheduled completion ({_day(item, 'ciamScheduledCompletion')}): "
                              "shorten it, or record why the risk authority accepts it longer.",
             responsible(ctx.d, e, ctx.dst.env), ctx.cutover)
            for e, item in found if _day(e, "ciamExpiresAt") and _day(item, "ciamScheduledCompletion")
            and _day(e, "ciamExpiresAt") > _day(item, "ciamScheduledCompletion")]


def _covers(e):
    return {*values(e, "ciamControlRef"), *(f"{a}: {p}" for a, p in _accepts(e))}


def _not_carried(ctx):
    """Actions for the source's exceptions in force that no target exception covers the same controls or findings of."""
    target = set().union(*(_covers(e) for e in exceptions_for(ctx.dst)))
    return [(AREA_EXCEPTIONS, f"{ctx.src.label}'s exception `{rdn_value(e)}` ({one(e, 'ciamExceptionKind')}: "
                              f"{', '.join(sorted(_covers(e)) or values(e, 'ciamFindingRef')) or 'no control named'}"
                              f") doesn't carry to {ctx.dst.label}: "
                              "correct the weakness there, or have the risk authority decide for the target.",
             responsible(ctx.d, e, ctx.dst.env), ctx.cutover)
            for e in exceptions_for(ctx.src) if in_force(e, ctx.as_of) and not (_covers(e) & target)]


def _assessed_frameworks(m):
    return {*(v for s in security_services(m, "posture") for v in values(s, "ciamComplianceStandard")),
            *(one(a, "ciamFramework") for a in _of(m.d, ASSESSMENT, m.dn))}


def _items(m):
    return [i for i in _of(m.d, ITEM, m.dn) if one(i, "ciamPoamStatus") == "open"]


def _poam(ctx):
    """Actions for the target's open POA&M items: overdue, or open against a framework the target is assessed
    against."""
    items, assessed = _items(ctx.dst), _assessed_frameworks(ctx.dst)
    overdue = [i for i in items if _day(i, "ciamScheduledCompletion") and _day(i, "ciamScheduledCompletion") <
               ctx.as_of]
    return [*((AREA_POAM, f"POA&M item `{rdn_value(i)}` was to be corrected by "
                          f"{_day(i, 'ciamScheduledCompletion')} and is still open: correct it, or replan it with its "
                          "milestones.", responsible(ctx.d, i, ctx.dst.env), ctx.cutover) for i in overdue),
            *((AREA_POAM, f"POA&M item `{rdn_value(i)}` is open against "
                          f"{', '.join(sorted(fw))}, which {ctx.dst.label} is assessed against: "
                          f"{one(i, 'ciamWeakness')}", responsible(ctx.d, i, ctx.dst.env), ctx.cutover)
              for i in items for fw in ({_frameworks(r) for r in values(i, "ciamControlRef")} & assessed,) if fw)]


def _closeout(a):
    at = _day(a, "ciamAssessedAt")
    return at + dt.timedelta(days=CMMC_CLOSEOUT_DAYS) if at and one(a, "ciamAssessmentStatus") == "conditional" \
        else None


def _cmmc(ctx):
    """Blockers (and actions) for the target's CMMC Level 2 assessments a POA&M can't keep conditional."""
    assessments = [a for a in _of(ctx.d, ASSESSMENT, ctx.dst.dn) if one(a, "ciamFramework") == CMMC_FRAMEWORK]
    if not assessments:
        return [], []
    items = [(i, [n for n in map(requirement_number, values(i, "ciamControlRef")) if n])
             for i in _items(ctx.dst)]
    items = [(i, nums) for i, nums in items if nums]
    owner = responsible(ctx.d, ctx.dst.env)
    fips, fips_points = CMMC_FIPS_EXCEPTION
    never = [(i, n) for i, nums in items for n in nums if n in CMMC_NEVER_POAM]
    heavy = [i for i, nums in items for pts in (one(i, "ciamPointValue"),) if pts and int(pts) > 1
             and not (fips in nums and int(pts) == fips_points)]
    unscored = [i for i, _ in items if not one(i, "ciamPointValue")]
    low = [a for a in assessments if one(a, "ciamAssessmentScore") and one(a, "ciamAssessmentMaxScore")
           and int(one(a, "ciamAssessmentScore")) < CMMC_MIN_RATIO * int(one(a, "ciamAssessmentMaxScore"))]
    lapsed = [a for a in assessments if _closeout(a) and _closeout(a) < ctx.as_of and items]
    due = [a for a in assessments if _closeout(a) and _closeout(a) >= ctx.as_of and items]
    blockers = [*((AREA_POAM, f"POA&M item `{rdn_value(i)}` holds requirement {n}, which CMMC Level 2 never allows "
                              "on a POA&M (32 CFR 170.21(a)(2)(iii)): it must be met before a Conditional status.",
                   owner)
                  for i, n in never),
                *((AREA_POAM, f"POA&M item `{rdn_value(i)}` is worth {one(i, 'ciamPointValue')} points: CMMC Level 2 "
                              "allows only 1-point requirements on a POA&M (SC.L2-3.13.11 at 3 when encryption isn't "
                              "FIPS-validated).", owner) for i in heavy),
                *((AREA_POAM, f"Assessment `{rdn_value(a)}` scored {one(a, 'ciamAssessmentScore')} of "
                              f"{one(a, 'ciamAssessmentMaxScore')}, under the {CMMC_MIN_RATIO:g} a Conditional CMMC "
                              "Level 2 status needs.", owner) for a in low),
                *((AREA_POAM, f"Assessment `{rdn_value(a)}`'s Conditional status passed its {CMMC_CLOSEOUT_DAYS}-day "
                              f"POA&M closeout on {_closeout(a)} with items still open: the status has expired.", owner)
                  for a in lapsed)]
    actions = [*((AREA_POAM, f"Close out `{rdn_value(a)}`'s POA&M by {_closeout(a)} ({CMMC_CLOSEOUT_DAYS} days "
                             "after its Conditional status): a closeout assessment must confirm every item.",
                  owner, _closeout(a))
                 for a in due),
               *((AREA_POAM, f"POA&M item `{rdn_value(i)}` records no point value: CMMC eligibility can't be checked "
                             "(ciamPointValue).", owner, ctx.cutover) for i in unscored)]
    return blockers, actions


def _suppressions(ctx):
    """Blockers for the target's suppressions no exception in force covers, actions for those wider than theirs."""
    def exception(s):
        ref = one(s, "ciamExceptionRef")
        e = get(ctx.d, ref) if ref else None
        return e if e is not None and is_a(e, EXCEPTION) else None
    pairs = [(s, exception(s)) for s in of_class(ctx.dst, SUPPRESSION)]
    blockers = [(AREA_EXCEPTIONS, f"Suppression `{rdn_value(s)}` in {ctx.dst.label} hides "
                                  f"{', '.join(values(s, 'ciamFindingRef')) or 'findings'} and "
                                  + (f"carries out exception `{rdn_value(e)}`, which isn't in force for it"
                                     if e is not None else "no exception covers it")
                                  + ": findings nobody approved hiding. Record the exception, or remove the "
                                    "suppression.",
                 responsible(ctx.d, s, ctx.dst.env))
                for s, e in pairs if e is None or not in_force(e, ctx.as_of) or not _names(e, ctx.dst.dn)]
    wider = [(s, e, sorted(set(values(s, "ciamFindingRef")) - set(values(e, "ciamFindingRef")))) for s, e in pairs
             if e is not None and in_force(e, ctx.as_of) and _names(e, ctx.dst.dn)]
    actions = [(AREA_EXCEPTIONS, f"Suppression `{rdn_value(s)}` hides {', '.join(extra)}, which exception "
                                 f"`{rdn_value(e)}` doesn't cover: narrow it to the exception's findings.",
                responsible(ctx.d, s, ctx.dst.env), ctx.cutover) for s, e, extra in wider if extra]
    return blockers, actions


def check_poam(ctx):
    """The target's exceptions, POA&M, CMMC eligibility and suppressions (see the module). Nothing when the record
    holds none of them for either environment."""
    exc = exceptions_for(ctx.dst)
    if not (exc or exceptions_for(ctx.src) or _of(ctx.d, ITEM, ctx.dst.dn) or _of(ctx.d, ASSESSMENT, ctx.dst.dn)
            or of_class(ctx.dst, SUPPRESSION)):
        return findings()
    cmmc_blockers, cmmc_actions = _cmmc(ctx)
    sup_blockers, sup_actions = _suppressions(ctx)
    return findings(blockers=[*_incomplete(ctx, exc), *cmmc_blockers, *sup_blockers],
                    actions=[*_expired(ctx, exc), *_beyond_item(ctx, exc), *_not_carried(ctx), *_poam(ctx),
                             *cmmc_actions, *sup_actions])


# ------------------------------------------------------------------ reports
def _labels(d, refs):
    return ", ".join(env_model(d, r).label for r in refs
                     if get(d, r) is not None and is_a(get(d, r), "ciamEnvironment"))


def _date(e, attr):
    v = _day(e, attr)
    return str(v) if v else ""


def poam_rows(d, dn=None, as_of=None):
    """One row per POA&M item: environments, controls, weakness, risk, how and when found, scheduled completion,
    status (open, overdue as of the day, closed), points, and the exceptions that belong to it."""
    day = as_of or dt.date.today()
    exc = _of(d, EXCEPTION)
    return [(rdn_value(i), _labels(d, values(i, "ciamAffectedEnvironment")), ", ".join(values(i, "ciamControlRef")),
             one(i, "ciamWeakness"), one(i, "ciamRiskRating", ""),
             " ".join(x for x in (one(i, "ciamDiscoverySource", ""), _date(i, "ciamDiscoveredAt")) if x),
             _date(i, "ciamScheduledCompletion"),
             "closed" if one(i, "ciamPoamStatus") == "closed" else
             "overdue" if _day(i, "ciamScheduledCompletion") and _day(i, "ciamScheduledCompletion") < day else "open",
             one(i, "ciamPointValue", ""),
             ", ".join(rdn_value(e) for e in exc if norm_dn(one(e, "ciamPoamRef") or "") == norm_dn(i.dn)))
            for i in _of(d, ITEM)]


def exception_rows(d, dn=None, as_of=None):
    """One row per exception: kind, status, environments, the controls and cloud findings it covers, the planner
    findings it accepts, the risk authority, approval, expiry and whether it is in force as of the day."""
    day = as_of or dt.date.today()
    return [(rdn_value(e), one(e, "ciamExceptionKind"), one(e, "ciamExceptionStatus"),
             _labels(d, values(e, "ciamAffectedEnvironment")),
             ", ".join((*values(e, "ciamControlRef"), *values(e, "ciamFindingRef"))),
             "; ".join(values(e, "ciamAcceptsFinding")), _authority(d, e),
             " ".join(x for x in (one(e, "ciamApprovedBy", ""), _date(e, "ciamApprovedAt")) if x),
             _date(e, "ciamExpiresAt"), "yes" if in_force(e, day) else "no")
            for e in _of(d, EXCEPTION)]


def assessment_rows(d, dn=None):
    """One row per compliance assessment: framework, who assessed, score of the maximum, status, when, the POA&M
    closeout date of a Conditional CMMC status, when the full score is expected, the environments assessed."""
    return [(rdn_value(a), one(a, "ciamFramework"), one(a, "ciamAssessmentKind"),
             "/".join(x for x in (one(a, "ciamAssessmentScore", ""), one(a, "ciamAssessmentMaxScore", "")) if x),
             one(a, "ciamAssessmentStatus", ""), _date(a, "ciamAssessedAt"),
             str(_closeout(a)) if one(a, "ciamFramework") == CMMC_FRAMEWORK and _closeout(a) else "",
             _date(a, "ciamFullScoreBy"), _labels(d, values(a, "ciamAffectedEnvironment")))
            for a in _of(d, ASSESSMENT)]

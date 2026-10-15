"""SIEM indexes and the detections they run: the planner's check. Pure.

A SIEM is a log destination like any other (ciamLogDestination, ciamDestinationKind siem-index): an environment binds
a log route's destination role to it, with how long it keeps logs searchable (ciamRetentionDays) and in all, archive
included (ciamTotalRetentionDays); logs.check_logs holds it to the route's obligation like any destination. What a
SIEM runs on its logs is a detection: an alarm binding (ciamAlarmBinding) naming the alert rule it realizes
(ciamRealizes), the SIEM index it searches (ciamLogDestinationRole) and the search (ciamMetric: SPL, KQL, ...), which
the SIEM's adapter renders with the rule's condition (alarms.Condition). The detection's search is the environment's
own, as a cloud alarm's metric is: nothing translates one SIEM's search into another's.

The check: a detection the source's SIEM runs that the target records none of (after the move the SIEM no longer
raises it), a target detection searching nothing or recording no search, and logs under legal hold a SIEM keeps in
the target (a retention doesn't prove a hold: a SIEM expires, or an administrator deletes, what it keeps) are
actions. Whether anything renders a SIEM index is a connector's question (connectors.observability.siem_check).
"""
from ...core.directory import one, rdn_value
from ...core.environment import of_class, one_role, role_named
from ...core.findings import findings, responsible
from .alerts import alert_rules
from .logs import log_routes

SIEM_INDEX = "siem-index"           # ciamDestinationKind of a SIEM's index (naming.DESTINATION_KINDS)
REALIZES = "opsdir: realizes alert rule "       # a rendered detection's description: the rule it realizes


def described(rule):
    """The description a SIEM adapter gives the detection it renders for an alert rule (by name): what its importer
    reads back as the rule it realizes (realized_in)."""
    return REALIZES + rule


def realized_in(description):
    """The alert rule (by name) a detection's description says it realizes (described), or None."""
    text = (description or "").strip()
    return text[len(REALIZES):].strip() or None if text.startswith(REALIZES) else None


def is_siem(b):
    """Whether binding b is a log destination of kind siem-index."""
    return b is not None and one(b, "ciamDestinationKind") == SIEM_INDEX


def siem_destinations(m):
    """Environment m's log destinations that are SIEM indexes, in record order."""
    return tuple(b for b in of_class(m, "ciamLogDestination") if is_siem(b))


def detections(m):
    """Environment m's detections: its alarm bindings naming the log destination their search runs on
    (ciamLogDestinationRole), in record order."""
    return tuple(b for b in of_class(m, "ciamAlarmBinding") if one(b, "ciamLogDestinationRole"))


def detection_index(m, b):
    """The SIEM index of environment m a detection searches (the destination its ciamLogDestinationRole names, when
    it is a SIEM index), or None."""
    found = role_named(m, b, "ciamLogDestinationRole")
    return found if is_siem(found) else None


def detection_for(m, rule):
    """Environment m's detection realizing an alert rule (by its name), or None."""
    return next((b for b in detections(m) if one(b, "ciamRealizes") == rule), None)


def _lost(ctx, rules):
    return [("Monitoring", f"{ctx.src.label}'s SIEM runs detection `{rdn_value(b)}` for alert rule "
             f"`{one(b, 'ciamRealizes')}`; {ctx.dst.label} records none: after the move its SIEM no longer raises "
             f"it. Record the search {ctx.dst.label}'s SIEM runs (an alarm binding naming the rule in ciamRealizes, "
             "the SIEM index in ciamLogDestinationRole and the search in ciamMetric).",
             responsible(ctx.d, rules[one(b, "ciamRealizes")], ctx.dst.env), None)
            for b in detections(ctx.src)
            if one(b, "ciamRealizes") in rules and detection_for(ctx.dst, one(b, "ciamRealizes")) is None]


def _broken(ctx, rules):
    def owner(b):
        rule = rules.get(one(b, "ciamRealizes"))
        return responsible(ctx.d, rule, ctx.dst.env) if rule is not None else responsible(ctx.d, ctx.dst.env)
    return [*(("Monitoring", f"{ctx.dst.label}'s detection `{rdn_value(b)}` searches "
               f"`{one(b, 'ciamLogDestinationRole')}`, which {ctx.dst.label} doesn't bind to a SIEM index: it "
               "searches nothing. Bind the role to the SIEM's index (a log destination of kind siem-index).",
               owner(b), None) for b in detections(ctx.dst) if detection_index(ctx.dst, b) is None),
            *(("Monitoring", f"{ctx.dst.label}'s detection `{rdn_value(b)}` records no search (ciamMetric): nothing "
               "renders it. Record the search its SIEM runs.", owner(b), None)
              for b in detections(ctx.dst) if detection_index(ctx.dst, b) is not None and not one(b, "ciamMetric"))]


def _held(ctx):
    return [("Logs", f"Log route `{rdn_value(r)}` is under legal hold, and {ctx.dst.label} keeps its logs in a SIEM "
             f"index (`{one(r, 'ciamLogDestinationRole')}`): its retention doesn't prove a hold (a SIEM expires, or "
             "an administrator deletes, what it keeps). Record how the hold is kept there (an immutable archive, the "
             "SIEM's own hold), or keep the source's copy.", responsible(ctx.d, r, ctx.dst.env), None)
            for r in log_routes(ctx.d)
            if one(r, "ciamLegalHold") == "TRUE" and is_siem(one_role(ctx.dst, one(r, "ciamLogDestinationRole")))]


def check_siem(ctx):
    """Detections the source's SIEM runs that the target records none of, target detections searching nothing or
    recording no search, and logs under legal hold a SIEM keeps in the target are actions."""
    rules = {rdn_value(r): r for r in alert_rules(ctx.d)}
    actions = [*_lost(ctx, rules), *_broken(ctx, rules), *_held(ctx)]
    return findings(actions=actions) if actions else findings()

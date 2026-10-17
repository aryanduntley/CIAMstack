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
from ...core.directory import get, one, rdn_value, values
from ...core.environment import env_dn, env_model, of_class, one_role, role_named
from ...core.findings import findings, responsible
from .alerts import alert_rules
from .logs import log_routes
from .naming import ENTITY_IDENTIFIERS

SIEM_INDEX = "siem-index"           # ciamDestinationKind of a SIEM's index (naming.DESTINATION_KINDS)
REALIZES = "opsdir: realizes alert rule "       # a rendered detection's description: the rule it realizes
UNREPORTED = "is in the record but not in what the cloud reports"     # core.inventory's notice for an unread entry


def detection_mode(b):
    """How detection b's search is used: count (the default: matching events counted per window) or rows (one row
    per finding)."""
    return one(b, "ciamDetectionMode") or "count"


def entity_mappings(b):
    """((entity, identifier, result column), ...) of detection b's ciamEntityMapping values, in the record's order."""
    return tuple((head.split(" ", 1)[0], head.split(" ", 1)[1], column)
                 for v in values(b, "ciamEntityMapping") for head, _, column in (v.partition("="),) if " " in head)


def forwardings(m):
    """((cloud log destination, SIEM index destination or None), ...) of environment m: each log destination that
    forwards its logs on (ciamForwardsToRole), with the destination that role binds (None: unbound)."""
    return tuple((b, one_role(m, one(b, "ciamForwardsToRole"))) for b in of_class(m, "ciamLogDestination")
                 if one(b, "ciamForwardsToRole"))


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


def search_language(b, native):
    """The language detection b's search is written in (ciamSearchLanguage), else native: the language of the SIEM
    keeping the index it searches."""
    return one(b, "ciamSearchLanguage") or native


def _others(d, spec, keeps):
    if get(d, env_dn(spec)) is None:
        return frozenset()
    m = env_model(d, spec)
    mine = {e.dn for e in of_class(m, "ciamLogDestination") if keeps(m, e)} | \
           {e.dn for e in of_class(m, "ciamAlarmBinding") if (x := detection_index(m, e)) is not None and keeps(m, x)}
    return frozenset(rdn_value(e) for c in ("ciamLogDestination", "ciamAlarmBinding") for e in of_class(m, c)
                     if e.dn not in mine)


def own_notices(d, imported, keeps):
    """A SIEM importer's Imported without the placement's notices about entries that aren't its SIEM's: the log
    destinations of each environment it read that keeps(m, b) (its adapter's siem_indexes) says aren't its indexes,
    and the alarms that aren't detections searching one (a cloud's, another SIEM's): a SIEM's answers say nothing
    about them."""
    def kept(n):
        spec, _, rest = n.partition(": ")
        return not (n.endswith(UNREPORTED) and any(rest.startswith(f"{x} (") for x in _others(d, spec, keeps)))
    return imported._replace(notices=tuple(n for n in imported.notices if kept(n)))


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


def _mapped(ctx):
    """Blockers for entity mappings a SIEM can't honour: on a count detection (its results are counts, not rows naming
    anything), or naming an identifier its entity type doesn't have."""
    envs = {m.dn.lower(): m for m in (ctx.src, ctx.dst)}.values()
    return [("Monitoring", f"{m.label}'s detection `{rdn_value(b)}` {why}.", responsible(ctx.d, b, m.env))
            for m in envs for b in detections(m) for why in (
                *(["maps entities but counts events (ciamDetectionMode count): its results hold no rows to name them; "
                   "make it a rows detection (a search returning one row per finding) or drop the mappings"]
                  if entity_mappings(b) and detection_mode(b) == "count" else []),
                *(f"maps {entity} by `{identifier}`, an identifier {entity} doesn't have "
                  f"({', '.join(ENTITY_IDENTIFIERS[entity])})"
                  for entity, identifier, _ in entity_mappings(b) if identifier not in ENTITY_IDENTIFIERS[entity]))]


def _forwarded(ctx):
    """Actions for forwarding that reaches no SIEM index: the role unbound, or bound to another kind."""
    envs = {m.dn.lower(): m for m in (ctx.src, ctx.dst)}.values()
    return [("Logs", f"{m.label}'s log destination `{rdn_value(b)}` forwards its logs to "
             f"`{one(b, 'ciamForwardsToRole')}`, which {m.label} " + (
                 "doesn't bind" if to is None else f"binds to `{rdn_value(to)}`, not a SIEM index") +
             ": nothing is forwarded. Bind the role to the SIEM's index (a log destination of kind siem-index).",
             responsible(ctx.d, b, m.env), None)
            for m in envs for b, to in forwardings(m) if to is None or not is_siem(to)]


def check_siem(ctx):
    """Detections the source's SIEM runs that the target records none of, target detections searching nothing or
    recording no search, logs under legal hold a SIEM keeps in the target, and log destinations forwarding to a role
    that isn't a SIEM index are actions; entity mappings on a count
    detection, or by an identifier the entity type doesn't have, are blockers."""
    rules = {rdn_value(r): r for r in alert_rules(ctx.d)}
    actions = [*_lost(ctx, rules), *_broken(ctx, rules), *_held(ctx), *_forwarded(ctx)]
    blockers = _mapped(ctx)
    return findings(actions=actions, blockers=blockers) if actions or blockers else findings()

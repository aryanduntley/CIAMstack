"""What evaluates each alert rule in the target: the metric its cloud runs for it (an alarm binding's ciamMetric), else
the Prometheus signal the target's product adapters declare (domains/observability/signals); and where each log
route's logs come from, given the log sources they declare (domains/observability/sources). A connector: the signals
and log sources come from the adapters rendering the environment. Pure.

A rule the target delivers (its alert role is bound there) that nothing there evaluates is an action: the renderers
can't write it, so after the move it watches nothing. A rule delivered nowhere is already the observability domain's
blocker, so it isn't repeated here. Likewise a log route the target keeps whose files sit on servers recording no
install root is an action (nothing can locate them), as is one collecting from a server role whose logs there hold
none of its kinds: either way nothing ships them.

A SIEM index the target keeps logs in (a log destination of kind siem-index) that no adapter rendering it keeps
(Adapter.siem_indexes: its retention, detections and forwarding) is an action: what it holds is kept by hand.

Which synthetic checks each environment renders (the canary-coverage report): every canary it could run, rendered
(and, for a service a private CA certified, the CA certificates it is given to trust: CanarySpec.trust), inherited or
kept by someone else, or not rendered with the render note that says why (connectors.render environment_notes: the
adapters' and the core's own).
"""
from ..core.contract import directory_report
from ..core.directory import one, rdn_value, values
from ..core.environment import one_role
from ..core.findings import findings, responsible
from ..domains.observability.alerts import alert_rules
from ..domains.observability.canaries import canary_specs
from ..domains.observability.logs import log_routes
from ..domains.observability.signals import evaluation
from ..domains.observability.siem import siem_destinations
from ..domains.observability.sources import COLLECTION_HEADERS, collection_rows, collections, uncollected
from ..domains.pki.pem import certificate_pem
from .registry import ADAPTERS, environment, environment_specs, services
from .render import environment_notes

COVERAGE_HEADERS = ("environment", "canary", "flow", "owner", "rendered")


def signal_check(dst_adapters):
    """The planner check for alert rules the target delivers but nothing there evaluates, given its adapters."""
    signals = tuple(s for a in dst_adapters for s in a.signals)

    def check_signals(ctx):
        rules = tuple(r for r in alert_rules(ctx.d) if one_role(ctx.dst, one(r, "ciamAlertRole")) is not None)
        missing = tuple(e for e in (evaluation(ctx.dst, signals, r) for r in rules) if e.missing)
        return findings(actions=[
            ("Alert", f"Alert rule `{rdn_value(e.rule)}` can't be evaluated in {ctx.dst.label}: {e.missing}. Record "
             "the metric the alarm realizing it evaluates there (ciamMetric), or install a product adapter that "
             "declares the signal.", responsible(ctx.d, e.rule, ctx.dst.env), None) for e in missing])
    return check_signals


def siem_check(dst_adapters):
    """The planner check for the target's SIEM indexes no adapter rendering it keeps (Adapter.siem_indexes), or more
    than one does (the index's reference reads as each one's: only the first renders it), given its adapters: an
    action per index."""
    def keepers(ctx, b):
        return tuple(a.name for a in dst_adapters if a.siem_indexes is not None and a.siem_indexes(ctx.dst, b))

    def check_siem_kept(ctx):
        kept = tuple((b, keepers(ctx, b)) for b in siem_destinations(ctx.dst))
        return findings(actions=[
            *(("Logs", f"{ctx.dst.label}'s `{one(b, 'ciamBindingRole')}` is a SIEM index ({one(b, 'ciamProviderRef')}) "
               f"that nothing rendering {ctx.dst.label} keeps: its retention, the detections searching it and the "
               "forwarding of logs to it are left to whoever runs the SIEM. Declare the SIEM's adapter in the "
               "environment's stack (stack role siem), or confirm the SIEM team keeps them.",
               responsible(ctx.d, b, ctx.dst.env), None) for b, names in kept if not names),
            *(("Logs", f"{ctx.dst.label}'s `{one(b, 'ciamBindingRole')}` is a SIEM index ({one(b, 'ciamProviderRef')}) "
               f"that {' and '.join(names)} each read as theirs: only {names[0]} renders it (the first declared), so "
               f"what {', '.join(names[1:])} would keep there isn't rendered. Declare one SIEM adapter for the "
               "environment, or name the index in the form only its SIEM's adapter reads.",
               responsible(ctx.d, b, ctx.dst.env), None) for b, names in kept if len(names) > 1)])
    return check_siem_kept


def _sources(adapters):
    return tuple(s for a in adapters for s in a.logs)


def log_collection_check(dst_adapters):
    """The planner check for what log routes the target keeps can't collect there, given its adapters: an action per
    server role whose servers record no install root (naming them and the routes), and one per route collecting from
    roles whose logs there hold none of its kinds."""
    sources = _sources(dst_adapters)

    def check_log_collection(ctx):
        kept = tuple(r for r in log_routes(ctx.d) if one_role(ctx.dst, one(r, "ciamLogDestinationRole")) is not None)
        every = collections(ctx.dst, kept, sources)
        found = tuple(c for c in every if c.unrooted)
        roles = {c.role: (c.unrooted, tuple(dict.fromkeys(rdn_value(x.route) for x in found if x.role == c.role)),
                          c.route) for c in found}
        missing = tuple(c for c in every if c.source is None)
        routes = {c.route.dn: (c.route, tuple(x for x in missing if x.route.dn == c.route.dn)) for c in missing}
        return findings(actions=[
            ("Logs", f"Servers of role `{role}` in {ctx.dst.label} record no install root ({', '.join(servers)}): the "
             f"files log route{'s' if len(names) > 1 else ''} {', '.join(f'`{n}`' for n in names)} "
             f"collect{'' if len(names) > 1 else 's'} from them can't be located, so nothing ships them. Record where "
             "the product is installed on each server (ciamInstallRoot).", responsible(ctx.d, route, ctx.dst.env),
             None)
            for role, (servers, names, route) in roles.items()] + [
            ("Logs", f"Log route `{rdn_value(route)}` collects {', '.join(values(route, 'ciamLogKind'))} logs, but in "
             f"{ctx.dst.label} nothing declares such a log for "
             f"{', '.join(f'`{c.role}` on {c.on} ({uncollected(c)})' for c in cs)}: nothing ships them from there.",
             responsible(ctx.d, route, ctx.dst.env), None)
            for route, cs in routes.values()])
    return check_log_collection


def log_collection_report(installed=ADAPTERS):
    """The `log-collection` report (an environment's DN): where each log route's logs come from there, with the log
    sources the adapters rendering it declare."""
    def rows(d, dn):
        m, adapters = environment(d, dn, installed)
        return collection_rows(m, log_routes(d), _sources(adapters))
    return directory_report(COLLECTION_HEADERS, rows, needs_dn=True)


def _covered(m, spec, notes):
    n = notes.get(f"canary {rdn_value(spec.canary)}")
    if n is not None:
        return ", ".join(n.owners) or "**NO OWNER**", f"NO ({n.severity}): {n.text.removeprefix('not rendered: ')}"
    return (responsible(m.d, spec.binding, spec.canary, m.env),
            f"inherited or kept: {spec.keeper}" if spec.keeper else "yes" + _trusting(spec.trust))


def _trusting(trust):
    """What a rendered check is given to trust besides its runtime's store, in words ('' when nothing)."""
    if trust is None or not trust.pem:
        return ""
    given = tuple(rdn_value(c) for c in trust.chain if certificate_pem(c))
    return f", trusting {', '.join(given)}" + (" (an intermediate CA as the anchor)" if trust.partial else "")


def coverage_rows(d, spec, installed=ADAPTERS):
    """(environment, canary, flow, owner, rendered) of each canary environment spec could run: yes; inherited or kept
    (by whom); or NO (severity: why, from its render note)."""
    m, notes = environment_notes(d, spec, installed)
    by_subject = {n.subject: n for n in notes}
    return tuple((m.label, rdn_value(s.canary), s.flow, *_covered(m, s, by_subject))
                 for s in canary_specs(m, services(installed).endpoints))


def coverage_report(installed=ADAPTERS):
    """The `canary-coverage` report (an environment's DN, else every environment): which synthetic checks each
    renders."""
    def rows(d, dn):
        return tuple(r for spec in ((dn,) if dn else environment_specs(d)) for r in coverage_rows(d, spec, installed))
    return directory_report(COVERAGE_HEADERS, rows)

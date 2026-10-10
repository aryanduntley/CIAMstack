"""What evaluates each alert rule in the target: the metric its cloud runs for it (an alarm binding's ciamMetric), else
the Prometheus signal the target's product adapters declare (domains/observability/signals); and where each log
route's logs come from, given the log sources they declare (domains/observability/sources). A connector: the signals
and log sources come from the adapters rendering the environment. Pure.

A rule the target delivers (its alert role is bound there) that nothing there evaluates is an action: the renderers
can't write it, so after the move it watches nothing. A rule delivered nowhere is already the observability domain's
blocker, so it isn't repeated here. Likewise a log route the target keeps whose files sit on servers recording no
install root is an action (nothing can locate them), as is one collecting from a server role whose logs there hold
none of its kinds: either way nothing ships them.
"""
from ..core.contract import directory_report
from ..core.directory import one, rdn_value, values
from ..core.environment import one_role
from ..core.findings import findings, responsible
from ..domains.observability.alerts import alert_rules
from ..domains.observability.logs import log_routes
from ..domains.observability.signals import evaluation
from ..domains.observability.sources import COLLECTION_HEADERS, collection_rows, collections, uncollected
from .registry import ADAPTERS, environment


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

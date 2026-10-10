"""What evaluates each alert rule in the target: the metric its cloud runs for it (an alarm binding's ciamMetric), else
the Prometheus signal the target's product adapters declare (domains/observability/signals). A connector: the signals
come from the adapters rendering the target, which the planner gives it. Pure.

A rule the target delivers (its alert role is bound there) that nothing there evaluates is an action: the renderers
can't write it, so after the move it watches nothing. A rule delivered nowhere is already the observability domain's
blocker, so it isn't repeated here.
"""
from ..core.directory import one, rdn_value
from ..core.environment import one_role
from ..core.findings import findings, responsible
from ..domains.observability.alerts import alert_rules
from ..domains.observability.signals import evaluation


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

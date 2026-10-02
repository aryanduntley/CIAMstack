"""Alert rules and synthetic checks: the reports and the planner's check. Pure.

An alert rule is intent: a neutral signal on a server role, the condition that fires it, how severe, the runbook that
says what to do, and the role of the channel that delivers it (ciamAlertRole), which each environment binds (a
topic, an action group, a paging service). A canary signs in as a user would against the service name a role
publishes (ciamCheckedService), with test credentials from a secret role (ciamUsesRole), and fires an alert rule when
it fails (ciamFeedsAlert). Roles neither environment binds are blockers (the core role check covers one only the
source binds): alerts that go nowhere and checks that check nothing are what a move breaks silently.
"""
from ...core.directory import children, follow, get, one, rdn_value, values
from ...core.environment import bound_nowhere
from ...core.findings import findings, merge_findings, responsible
from .naming import ALERT_RULES, CANARIES

ALERT_HEADERS = ("alert rule", "signal", "on", "fires when", "severity", "delivered by", "runbooks", "owner")
CANARY_HEADERS = ("canary", "flow", "checks", "every", "credentials", "fires")


def alert_rules(d):
    return children(d, ALERT_RULES, "ciamAlertRule")


def canaries(d):
    return children(d, CANARIES, "ciamCanary")


def _condition(r):
    parts = (one(r, "ciamComparison"), one(r, "ciamThreshold"))
    period = one(r, "ciamEvaluationPeriod")
    return " ".join(p for p in parts if p) + (f" for {period}" if period else "")


def _names(d, e, attr):
    return ", ".join(rdn_value(t) for t in (get(d, v) for v in values(e, attr)) if t is not None)


def alert_rows(d, dn=None):
    """One row per alert rule."""
    return [(rdn_value(r), one(r, "ciamSignal"), one(r, "ciamTargetRole") or "", _condition(r),
             one(r, "ciamSeverity") or "", one(r, "ciamAlertRole"), _names(d, r, "ciamRunbookRef"),
             _names(d, r, "ciamOwner"))
            for r in alert_rules(d)]


def canary_rows(d, dn=None):
    """One row per synthetic check."""
    return [(rdn_value(c), one(c, "ciamCanaryFlow"), one(c, "ciamCheckedService"), one(c, "ciamInterval") or "",
             ", ".join(values(c, "ciamUsesRole")),
             rdn_value(follow(d, c, "ciamFeedsAlert")) if one(c, "ciamFeedsAlert") else "")
            for c in canaries(d)]


def _rule(ctx, r):
    name, owner, role = rdn_value(r), responsible(ctx.d, r, ctx.dst.env), one(r, "ciamAlertRole")
    return findings(
        blockers=[("Alert", f"Alert rule `{name}` is delivered by role `{role}`, which neither {ctx.src.label} nor "
                   f"{ctx.dst.label} binds: its alerts go nowhere. Record each environment's channel.", owner)
                  for role in bound_nowhere((role,), ctx.src, ctx.dst)],
        actions=[*((("Alert", f"Alert rule `{name}` names no runbook: whoever it pages doesn't know what to do. Link "
                     "one (ciamRunbookRef).", owner, None),) if not values(r, "ciamRunbookRef") else ()),
                 *((("Alert", f"Alert rule `{name}` has no owner: nobody answers for it after a move. Name who owns "
                     "it.", owner, None),) if not values(r, "ciamOwner") else ())])


def _canary(ctx, c):
    name, owner = rdn_value(c), responsible(ctx.d, c, ctx.dst.env)
    nowhere = bound_nowhere((one(c, "ciamCheckedService"), *values(c, "ciamUsesRole")), ctx.src, ctx.dst)
    return findings(
        blockers=[("Canary", f"Canary `{name}` needs role `{r}`, which neither {ctx.src.label} nor {ctx.dst.label} "
                   "binds: it checks nothing. Record each environment's.", owner) for r in nowhere],
        actions=[("Canary", f"Canary `{name}` fires no alert rule: when it fails, nobody hears. Name the rule it "
                  "feeds (ciamFeedsAlert).", owner, None)] if not one(c, "ciamFeedsAlert") else [])


def check_alerts(ctx):
    """Alert rules and canaries whose roles neither environment binds are blockers; rules without a runbook or an
    owner, and canaries that fire nothing, are actions."""
    rules, checks = alert_rules(ctx.d), canaries(ctx.d)
    if not rules and not checks:
        return findings()
    parts = merge_findings([*(_rule(ctx, r) for r in rules), *(_canary(ctx, c) for c in checks)])
    if parts.blockers or parts.actions:
        return parts
    return parts._replace(ok=(*parts.ok, f"Alert rules ({len(rules)}) and canaries ({len(checks)}) are delivered and "
                                         f"exercised in {ctx.dst.label}."))

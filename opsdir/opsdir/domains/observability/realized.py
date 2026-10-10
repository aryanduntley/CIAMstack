"""What each cloud runs of the platform's monitoring: the alarms and synthetic checks cloud importers read into an
environment (ciamAlarmBinding, ciamCanaryBinding), each naming the alert rule or canary it realizes (ciamRealizes).
The report and the planner's check. Pure.

An alarm the source runs that realizes no recorded alert rule is monitoring nobody described: after a move it is lost,
or copied without anyone knowing why. A rule the source doesn't realize while it records what it runs is intent
nothing runs today. Both are actions; rendering what the target runs is the renderers' (path 6).
"""
from ...core.directory import is_a, one, rdn_value, sorted_by_dn, subtree, values
from ...core.environment import environment_of, inherited_from, of_class
from ...core.findings import findings, responsible
from ...core.naming import branch, env_label
from ..network.stack import kept_by
from .alerts import alert_rules, canaries

MONITOR_HEADERS = ("environment", "monitor", "kind", "realizes", "evaluates", "notifies", "every", "provider ref")
# (binding class, what the cloud runs, what it realizes, the record's entries of that)
KINDS = (("ciamAlarmBinding", "alarm", "alert rule", alert_rules), ("ciamCanaryBinding", "check", "canary", canaries))


def keeper_of(m, b):
    """Who keeps a monitoring binding's resource when environment m's root doesn't render it: the party it names
    (ciamManagedBy: network.stack.kept_by), or the base environment overlay m inherits it from; None when it is m's
    to render (or b is None)."""
    if b is None:
        return None
    if one(b, "ciamManagedBy"):
        return kept_by(m, b)
    base = inherited_from(m, b)
    return f"{base} (this environment inherits it)" if base else None


def monitors(m):
    """Environment m's alarms and synthetic checks, as its cloud runs them."""
    return tuple(b for oc, _, _, _ in KINDS for b in of_class(m, oc))


def monitor_rows(d, dn=None):
    """One row per alarm and synthetic check a cloud runs, in every environment."""
    held = sorted_by_dn(e for oc, _, _, _ in KINDS for e in subtree(d, branch("environments"), oc))
    return [(env_label(environment_of(e)), rdn_value(e), "alarm" if is_a(e, "ciamAlarmBinding") else "check",
             one(e, "ciamRealizes") or "", one(e, "ciamMetric") or "", ", ".join(values(e, "ciamNotifies")),
             one(e, "ciamInterval") or "", one(e, "ciamProviderRef"))
            for e in held]


def _unrecorded(src, b, run, intent):
    named = one(b, "ciamRealizes")
    said = f" (it names `{named}`, which the record doesn't have)" if named else ""
    return (f"{src.label} runs {run} `{rdn_value(b)}` ({one(b, 'ciamProviderRef')}), which realizes no recorded "
            f"{intent}{said}: record what it watches, or retire it.")


def _kind(ctx, oc, run, intent, recorded, owner):
    running = of_class(ctx.src, oc)
    names = {rdn_value(r) for r in recorded(ctx.d)}
    realized = {one(b, "ciamRealizes") for b in running}
    return [*(("Monitoring", _unrecorded(ctx.src, b, run, intent), owner, None)
              for b in running if one(b, "ciamRealizes") not in names),
            *(("Monitoring", f"{intent.capitalize()} `{n}` isn't realized in {ctx.src.label}: nothing there runs it "
               "today.", owner, None) for n in sorted(names - realized) if running)]


def check_realized(ctx):
    """The source's alarms and checks that realize no recorded rule or canary, and (once the source records what it
    runs of a kind) the rules or canaries nothing there runs, are actions."""
    owner = responsible(ctx.d, ctx.src.env)
    actions = [a for oc, run, intent, recorded in KINDS for a in _kind(ctx, oc, run, intent, recorded, owner)]
    return findings(actions=actions) if actions else findings()

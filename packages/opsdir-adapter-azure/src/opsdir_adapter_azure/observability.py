"""Alerting and log retention on Azure (core observability) as Azure Monitor metric alerts and Log Analytics
workspaces. Pure.

Alerts (domains/observability/alarms): each alert rule the environment delivers, realized by an alarm binding that
records its metric ("<metric namespace> <metric name>"), as an azurerm_monitor_metric_alert named as the binding, on
the virtual machines of the rule's target role (its scopes; with more than one, their resource type and location),
notifying the action group of the rule's channel (its ciamProviderRef, when it is an action group ID), tagged
Realizes and BindingRole so the inventory reads it back as the same binding. The condition: the rule's comparison (ne
isn't a metric alert's: named), its threshold in the unit it is written in where it is a duration in ms, else in
seconds, bytes or percent (a metric alert has no unit: a comment says which the metric must report); a rate as the
Total over the window; the evaluation period as the window, raised to a size Azure allows (PT1M ... P1D), evaluated
every minute (every five past five minutes); ciamSeverity sev0..sev4 as its severity. A rule realized by a log query
alarm (ciamMetric "log query"), with no target role, or whose role has no virtual machine here, is named; an alarm
someone else keeps, or an overlay inherits from its base (rendered there), is named with its keeper.

Workspaces: each log destination of kind workspace the platform keeps (not inherited) whose ciamProviderRef is a
workspace ID, as an azurerm_log_analytics_workspace of that name (PerGB2018) keeping logs as many days as recorded
within what a workspace's retention allows (30 to 730: fewer raised to 30, more, or indefinitely, kept 730 with a
comment: a table's total retention keeps them longer, up to 4383 days).
"""
from decimal import Decimal

from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import of_class, servers_with_role
from opsdir.domains.observability.alarms import alarm_specs, condition, in_unit
from opsdir.domains.observability.realized import keeper_of
from opsdir.domains.observability.signals import number_text, parse_threshold
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .account import tagged
from .identities import LOC, RG

ALERT = "azurerm_monitor_metric_alert"
WORKSPACE = "azurerm_log_analytics_workspace"
OPERATORS = {"gt": "GreaterThan", "ge": "GreaterThanOrEqual", "lt": "LessThan", "le": "LessThanOrEqual",
             "eq": "Equals"}
AGGREGATIONS = {"average": "Average", "sum": "Total"}
WINDOWS = (60, 300, 900, 1800, 3600, 21600, 43200, 86400)          # PT1M ... P1D
MIN_DAYS, MAX_DAYS = 30, 730
VM_TYPE = "Microsoft.Compute/virtualMachines"


def iso_duration(seconds):
    """Seconds as an ISO 8601 duration (PT5M, PT6H, P1D)."""
    if seconds % 86400 == 0:
        return f"P{seconds // 86400}D"
    return f"PT{seconds // 3600}H" if seconds % 3600 == 0 else f"PT{seconds // 60}M"


def _number(text):
    value = Decimal(text)
    return int(value) if value == value.to_integral_value() else float(text)


def _must_report(unit):
    return f"compared in {unit}: the metric must report {unit}"


def _threshold(rule, c, window):
    """(threshold text, a comment on what it is compared in, or None) of a rule's Condition over a window."""
    value, unit = parse_threshold(one(rule, "ciamThreshold"))
    if c.kind is None:
        return c.threshold, None
    if c.kind == "count":
        return (number_text(Decimal(c.threshold) * window / c.window),
                f"{one(rule, 'ciamThreshold')} as the total over the window")
    if unit == "ms":
        return number_text(value), _must_report("milliseconds")
    return {"time": (c.threshold, _must_report("seconds")), "size": (c.threshold, _must_report("bytes")),
            "share": (in_unit(c, "%"), _must_report("percent"))}[c.kind]


def _severity(rule):
    sev = one(rule, "ciamSeverity") or ""
    return int(sev[3:]) if sev.startswith("sev") and sev[3:].isdigit() and int(sev[3:]) <= 4 else None


def _action_group(channel):
    ref_ = one(channel, "ciamProviderRef") or ""
    return ref_ if "/providers/microsoft.insights/actiongroups/" in ref_.lower() else None


def _why(m, s, operator, c, metric):
    role = one(s.rule, "ciamTargetRole")
    if one(s.alarm, "ciamMetric") == "log query":
        return "its alarm is a log query alert and the record holds no query"
    if operator is None:
        return f"a metric alert has no comparison {one(s.rule, 'ciamComparison')!r}"
    if c is None:
        return f"its threshold {one(s.rule, 'ciamThreshold')!r} isn't a number with a known unit"
    if not metric or " " in metric:
        return f"its alarm's metric {one(s.alarm, 'ciamMetric')!r} isn't '<metric namespace> <metric name>'"
    if not role:
        return "it names no target role (ciamTargetRole) whose virtual machines it watches"
    if not servers_with_role(m, role):
        return f"role {role} has no virtual machine in {m.label} to watch"
    return None


def _alert(m, s):
    rule = rdn_value(s.rule)
    if s.why:
        return (f"# NOTE: alert rule {rule}: not rendered: {s.why}",)
    name = rdn_value(s.alarm)
    if s.keeper is not None:
        return (f"# Alarm {name} (alert rule {rule}): kept by {s.keeper}, not rendered here",)
    operator, c = OPERATORS.get(one(s.rule, "ciamComparison") or ""), condition(s.rule)
    namespace, _, metric = (one(s.alarm, "ciamMetric") or "").partition(" ")
    why = _why(m, s, operator, c, metric)
    if why:
        return (f"# NOTE: alert rule {rule}: not rendered: {why}",)
    window = next((w for w in WINDOWS if w >= c.window * c.windows), WINDOWS[-1])
    threshold, compared = _threshold(s.rule, c, window)
    vms = [ref(f"azurerm_linux_virtual_machine.{tf_name(rdn_value(v))}.id")
           for v in servers_with_role(m, one(s.rule, "ciamTargetRole"))]
    group, severity = _action_group(s.channel), _severity(s.rule)
    return (block("resource", [ALERT, tf_name(name)], [
        ("name", name), ("resource_group_name", RG), ("scopes", vms),
        *((("target_resource_type", VM_TYPE), ("target_resource_location", LOC)) if len(vms) > 1 else ()),
        ("description", f"Alert rule {rule}: {one(s.rule, 'ciamSignal')} {one(s.rule, 'ciamComparison')} "
                        f"{one(s.rule, 'ciamThreshold')} (opsdir)"),
        *((("severity", severity),) if severity is not None else ()),
        ("frequency", "PT1M" if window <= 300 else "PT5M"), ("window_size", iso_duration(window)),
        ("criteria", Block((
            *((("#", compared),) if compared else ()),
            ("metric_namespace", namespace), ("metric_name", metric),
            ("aggregation", AGGREGATIONS[c.statistic]), ("operator", operator),
            ("threshold", _number(threshold))))),
        *((("action", Block((("action_group_id", group),))),) if group else
          (("#", f"channel {rdn_value(s.channel)} names no action group ID (ciamProviderRef): no action"),)),
        ("tags", tagged(m, {"Realizes": rule, "BindingRole": one(s.alarm, "ciamBindingRole")}))]),)


def render_alerts(m):
    """HCL (and comments) for environment m's Azure Monitor metric alerts."""
    return tuple(x for s in alarm_specs(m) for x in _alert(m, s))


def workspace_retention(days):
    """(retention_in_days a workspace allows for a recorded number of days, why it differs or None); 0 is
    indefinitely."""
    if days == 0 or days > MAX_DAYS:
        return MAX_DAYS, (f"{'indefinitely' if days == 0 else f'{days} days'} is longer than a workspace keeps logs "
                          f"({MAX_DAYS}): kept {MAX_DAYS}; set the tables' total retention (up to 4383 days) to keep "
                          "them longer")
    if days < MIN_DAYS:
        return MIN_DAYS, f"{days} days is less than a workspace keeps logs: raised to {MIN_DAYS}"
    return days, None


def workspace_name(b):
    """The Log Analytics workspace name a log destination's provider ref (a workspace ID) gives, or None."""
    ref_ = one(b, "ciamProviderRef") or ""
    marker = "/providers/microsoft.operationalinsights/workspaces/"
    i = ref_.lower().find(marker)
    return ref_[i + len(marker):].split("/", 1)[0] if i >= 0 else None


def _workspace(m, b):
    cn, name = rdn_value(b), workspace_name(b)
    if one(b, "ciamDestinationKind") != "workspace":
        return ()
    if keeper_of(m, b):
        return (f"# Log Analytics workspace {cn}: kept by {keeper_of(m, b)}, not rendered here",)
    if name is None:
        return (f"# NOTE: log destination {cn}: not rendered: its ciamProviderRef isn't a Log Analytics workspace ID",)
    days, why = workspace_retention(int(one(b, "ciamRetentionDays"))) if one(b, "ciamRetentionDays") is not None \
        else (None, "no retention recorded (ciamRetentionDays): the workspace keeps Azure's default")
    return (block("resource", [WORKSPACE, tf_name(cn)], [
        *((("#", why),) if why else ()), ("name", name), ("location", LOC), ("resource_group_name", RG),
        ("sku", "PerGB2018"), *((("retention_in_days", days),) if days is not None else ()),
        ("tags", tagged(m, {"BindingRole": one(b, "ciamBindingRole")}))]),)


def workspace_id(m, b):
    """The ID Terraform gives a log destination of kind workspace: the workspace rendered here when this root
    renders it, else its recorded ID; None for another kind or no workspace ID."""
    if b is None or one(b, "ciamDestinationKind") != "workspace" or workspace_name(b) is None:
        return None
    return one(b, "ciamProviderRef") if keeper_of(m, b) else ref(f"{WORKSPACE}.{tf_name(rdn_value(b))}.id")


def render_workspaces(m):
    """HCL (and comments) for environment m's Log Analytics workspaces."""
    return tuple(x for b in of_class(m, "ciamLogDestination") for x in _workspace(m, b))

"""Alerting and log retention on AWS (core observability) as CloudWatch alarms and log groups. Pure.

Alarms (domains/observability/alarms): each alert rule the environment delivers, realized by an alarm binding that
records its metric ("<namespace> <metric name>"), as an aws_cloudwatch_metric_alarm named as the binding, notifying
the SNS topic of the rule's channel (its ciamProviderRef, when it is a topic ARN), tagged Realizes (the rule) and
BindingRole (the binding's role) so the inventory reads it back as the same binding. The condition: the rule's
comparison (eq and ne aren't CloudWatch's: named, not rendered), its threshold in the unit it is written in where
CloudWatch has that unit (ms as Milliseconds; other durations in Seconds; sizes in Bytes; % and ratios as Percent),
set as the alarm's unit so it compares only data published in it; a rate (/s, /min, /h) as a Sum of Count over a
window of at least a minute; the evaluation period as that many windows. The metric's dimensions aren't recorded:
the alarm watches the metric as published without them. An alarm someone else keeps, or an overlay inherits from its
base (rendered there), is named with its keeper; a rule without an alarm here, or whose alarm records no metric, is
named (Prometheus may evaluate it).

Log groups: each log destination of kind log-group the platform keeps (not inherited) whose ciamProviderRef is a log
group ARN, as an aws_cloudwatch_log_group of that name keeping logs as many days as recorded, raised to the next value
CloudWatch allows (said in a comment); 0 (never expire) as 0, and more than CloudWatch's longest (3653 days) as 0
with a comment.
"""
from decimal import Decimal

from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import of_class
from opsdir.domains.observability.alarms import alarm_specs, condition, in_unit
from opsdir.domains.observability.realized import keeper_of
from opsdir.domains.observability.signals import number_text, parse_threshold
from opsdir_format_terraform.hcl import block, tf_name

ALARM = "aws_cloudwatch_metric_alarm"
LOG_GROUP = "aws_cloudwatch_log_group"
OPERATORS = {"gt": "GreaterThanThreshold", "ge": "GreaterThanOrEqualToThreshold", "lt": "LessThanThreshold",
             "le": "LessThanOrEqualToThreshold"}
STATISTICS = {"average": "Average", "sum": "Sum"}
RETENTION_DAYS = (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922,
                  3288, 3653)


def _number(text):
    value = Decimal(text)
    return int(value) if value == value.to_integral_value() else float(text)


def _threshold(rule, c):
    """(threshold text, CloudWatch unit or None) of a rule's Condition."""
    value, unit = parse_threshold(one(rule, "ciamThreshold"))
    if c.kind is None:
        return c.threshold, None
    if c.kind == "count":
        return c.threshold, "Count"
    if unit == "ms":
        return number_text(value), "Milliseconds"
    return {"time": (c.threshold, "Seconds"), "size": (c.threshold, "Bytes"),
            "share": (in_unit(c, "%"), "Percent")}[c.kind]


def _topic(channel):
    ref = one(channel, "ciamProviderRef") or ""
    return ref if ref.startswith("arn:") and ":sns:" in ref else None


def _alarm(m, s):
    rule = rdn_value(s.rule)
    if s.why:
        return (f"# NOTE: alert rule {rule}: not rendered: {s.why}",)
    name = rdn_value(s.alarm)
    if s.keeper is not None:
        return (f"# Alarm {name} (alert rule {rule}): kept by {s.keeper}, not rendered here",)
    operator, c = OPERATORS.get(one(s.rule, "ciamComparison") or ""), condition(s.rule)
    namespace, _, metric = (one(s.alarm, "ciamMetric") or "").partition(" ")
    why = (f"CloudWatch has no comparison {one(s.rule, 'ciamComparison')!r}" if operator is None
           else f"its threshold {one(s.rule, 'ciamThreshold')!r} isn't a number with a known unit" if c is None
           else f"its alarm's metric {one(s.alarm, 'ciamMetric')!r} isn't '<namespace> <metric name>'"
           if not metric or " " in metric else None)
    if why:
        return (f"# NOTE: alert rule {rule}: not rendered: {why}",)
    threshold, unit = _threshold(s.rule, c)
    topic = _topic(s.channel)
    return (block("resource", [ALARM, tf_name(name)], [
        ("alarm_name", name),
        ("alarm_description", f"Alert rule {rule}: {one(s.rule, 'ciamSignal')} {one(s.rule, 'ciamComparison')} "
                              f"{one(s.rule, 'ciamThreshold')} (opsdir)"),
        ("namespace", namespace), ("metric_name", metric), ("statistic", STATISTICS[c.statistic]),
        ("period", c.window), ("evaluation_periods", c.windows), ("comparison_operator", operator),
        ("threshold", _number(threshold)), *((("unit", unit),) if unit else ()),
        *((("alarm_actions", [topic]), ("ok_actions", [topic])) if topic else
          (("#", f"channel {rdn_value(s.channel)} names no SNS topic ARN (ciamProviderRef): no actions"),)),
        ("tags", {"Realizes": rule, "BindingRole": one(s.alarm, "ciamBindingRole")})]),)


def render_alarms(m):
    """HCL (and comments) for environment m's CloudWatch alarms."""
    return tuple(x for s in alarm_specs(m) for x in _alarm(m, s))


def retention(days):
    """(retention_in_days CloudWatch allows for a recorded number of days, why it differs or None)."""
    if days == 0:
        return 0, None
    allowed = next((d for d in RETENTION_DAYS if d >= days), None)
    if allowed is None:
        return 0, f"{days} days is longer than CloudWatch keeps logs (3653): kept indefinitely"
    return allowed, (None if allowed == days else f"{days} days isn't a CloudWatch retention: raised to {allowed}")


def _group_name(b):
    ref = one(b, "ciamProviderRef") or ""
    return ref.split(":log-group:", 1)[1].removesuffix(":*") if ref.startswith("arn:") and ":log-group:" in ref \
        else None


def _log_group(m, b):
    cn, name, keeper = rdn_value(b), _group_name(b), keeper_of(m, b)
    if one(b, "ciamDestinationKind") != "log-group":
        return ()
    if keeper:
        return (f"# Log group {cn}: kept by {keeper}, not rendered here",)
    if name is None:
        return (f"# NOTE: log destination {cn}: not rendered: its ciamProviderRef isn't a log group ARN",)
    days, why = retention(int(one(b, "ciamRetentionDays") or 0)) if one(b, "ciamRetentionDays") is not None \
        else (None, "no retention recorded (ciamRetentionDays): CloudWatch keeps its logs indefinitely")
    return (block("resource", [LOG_GROUP, tf_name(cn)], [
        *((("#", why),) if why else ()), ("name", name),
        *((("retention_in_days", days),) if days is not None else ()),
        ("tags", {"BindingRole": one(b, "ciamBindingRole")})]),)


def render_log_groups(m):
    """HCL (and comments) for environment m's CloudWatch log groups."""
    return tuple(x for b in of_class(m, "ciamLogDestination") for x in _log_group(m, b))

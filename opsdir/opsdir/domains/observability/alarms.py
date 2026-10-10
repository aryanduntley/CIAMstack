"""What a cloud renders of an environment's alerting, cloud-neutral (each cloud adapter maps it to its own alarms).
Pure.

An alert rule the environment delivers (its ciamAlertRole is bound here: the channel) is rendered as the cloud's
alarm when the environment records the alarm realizing it (a ciamAlarmBinding naming the rule in ciamRealizes) with
the metric it evaluates (ciamMetric): the binding is the alarm's name, role and metric, the rule its condition and
period. A rule without such an alarm here is named, not rendered (a product's Prometheus signal is evaluated by the
Prometheus add-on instead); an alarm someone else keeps (ciamManagedBy), or an overlay inherits from its base
(rendered there), is named with its keeper. A rule the environment doesn't deliver is the planner's blocker, not a
renderer's concern.

The condition in a cloud's own terms: thresholds are compared in the unit they are written in where the cloud's
alarms can say it (cloud_threshold); rates (/s, /min, /h) become counts over a window a cloud evaluates.
"""
from collections import namedtuple
from decimal import Decimal

from ...core.directory import one, rdn_value
from ...core.environment import one_role
from ...core.inventory import duration_seconds
from .alerts import alert_rules
from .realized import keeper_of
from .signals import UNITS, alarm_for, number_text, parse_threshold

# A rule as one environment renders it: the rule, its alarm binding (or None), the channel delivering it, who keeps
# the alarm when this environment doesn't (realized.keeper_of: a party, or the base an overlay inherits it from; or
# None), and why it isn't rendered (None when it is).
AlarmSpec = namedtuple("AlarmSpec", ("rule", "alarm", "channel", "keeper", "why"))

# A condition as a cloud evaluates it: the threshold as number text, its unit kind and base unit (time: s, size:
# bytes, share: ratio, count: a count per window of window seconds), the statistic (average, or sum for counts), the
# window in seconds, and how many windows must breach (the rule's evaluation period).
Condition = namedtuple("Condition", ("threshold", "kind", "unit", "statistic", "window", "windows"))

RATE_WINDOWS = {"/s": 1, "/min": 60, "/h": 3600}
MINIMUM_WINDOW = 60


def _why_not(m, rule, alarm):
    if alarm is None:
        return (f"no alarm in {m.label} realizes it (a ciamAlarmBinding with ciamRealizes {rdn_value(rule)}): "
                "record the one the cloud runs, or let Prometheus evaluate it")
    if not one(alarm, "ciamMetric"):
        return f"its alarm {rdn_value(alarm)} records no metric (ciamMetric)"
    return None


def alarm_specs(m):
    """Environment m's alert rules it delivers, as AlarmSpecs, in the record's order."""
    def spec(rule):
        alarm = alarm_for(m, rule)
        return AlarmSpec(rule, alarm, one_role(m, one(rule, "ciamAlertRole")), keeper_of(m, alarm),
                         _why_not(m, rule, alarm))
    return tuple(spec(r) for r in alert_rules(m.d) if one_role(m, one(r, "ciamAlertRole")) is not None)


def _windows(rule, window):
    seconds = duration_seconds(one(rule, "ciamEvaluationPeriod"))
    return max(1, -(-seconds // window)) if seconds else 1


def condition(rule):
    """The rule's Condition, or None when its threshold isn't a number or its unit is unknown. A threshold without a
    unit is compared as written (kind None)."""
    parsed = parse_threshold(one(rule, "ciamThreshold"))
    if parsed is None:
        return None
    value, unit = parsed
    if unit is None:
        return Condition(number_text(value), None, None, "average", MINIMUM_WINDOW, _windows(rule, MINIMUM_WINDOW))
    if unit in RATE_WINDOWS:
        window = max(MINIMUM_WINDOW, RATE_WINDOWS[unit])
        count = value * window / RATE_WINDOWS[unit]
        return Condition(number_text(count), "count", "count", "sum", window, _windows(rule, window))
    if unit not in UNITS:
        return None
    kind, factor = UNITS[unit]
    base = {"time": "s", "size": "bytes", "share": "ratio"}[kind]
    return Condition(number_text(value * factor), kind, base, "average", MINIMUM_WINDOW,
                     _windows(rule, MINIMUM_WINDOW))


def in_unit(c, unit):
    """A Condition's threshold in another unit of its kind (ms, %, ...), as number text."""
    return number_text(Decimal(c.threshold) / UNITS[unit][1] * UNITS[c.unit][1]) if c.unit in UNITS else c.threshold

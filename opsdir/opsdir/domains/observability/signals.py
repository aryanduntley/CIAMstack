"""What an alert rule evaluates in an environment, and its condition in the signal's own unit. Pure.

A rule names a neutral signal on a server role (ciamSignal, ciamTargetRole). In an environment it is evaluated on,
first, the metric the environment's cloud runs for it (the alarm binding realizing the rule: its ciamMetric), else the
Prometheus expression the product serving the role declares for the signal (core.contract.Signal, from the adapters
rendering the environment), else nothing: renderers then say what to record, and the planner asks for it.

A threshold is a number with its unit (5000 ms, 90 %, 50 /min, 10 GB); it is converted to the unit of what evaluates
it (a Signal's unit) when both are of one kind: time (ms, s, m, h, d), size (B, KB, MB, GB, TB decimal; KiB, MiB,
GiB, TiB binary), rate (/s, /min, /h) or share (%, ratio). A threshold without a unit is taken as it is.
"""
from collections import namedtuple
from decimal import Decimal, InvalidOperation

from ...core.directory import one, rdn_value
from ...core.environment import of_class

# The PromQL operator of each comparison (naming.COMPARISONS).
PROMQL_OPERATORS = {"gt": ">", "ge": ">=", "lt": "<", "le": "<=", "eq": "==", "ne": "!="}

# unit -> (kind, factor to the kind's base unit: seconds, bytes, per second, ratio)
UNITS = {"ms": ("time", Decimal("0.001")), "s": ("time", Decimal(1)), "m": ("time", Decimal(60)),
         "min": ("time", Decimal(60)), "h": ("time", Decimal(3600)), "d": ("time", Decimal(86400)),
         "B": ("size", Decimal(1)), "bytes": ("size", Decimal(1)),
         "KB": ("size", Decimal(10) ** 3), "MB": ("size", Decimal(10) ** 6), "GB": ("size", Decimal(10) ** 9),
         "TB": ("size", Decimal(10) ** 12), "KiB": ("size", Decimal(2) ** 10), "MiB": ("size", Decimal(2) ** 20),
         "GiB": ("size", Decimal(2) ** 30), "TiB": ("size", Decimal(2) ** 40),
         "/s": ("rate", Decimal(1)), "/min": ("rate", Decimal(1) / 60), "/h": ("rate", Decimal(1) / 3600),
         "%": ("share", Decimal("0.01")), "ratio": ("share", Decimal(1))}

# A rule as evaluated in one environment: the rule, the alarm binding realizing it there (or None), the product
# Signal for its signal and role (or None), and why neither evaluates it (None when one does).
Evaluation = namedtuple("Evaluation", ("rule", "alarm", "signal", "missing"))


def parse_threshold(text):
    """(value as Decimal, unit or None) of a threshold (5000 ms, 50 /min, 0.5), or None when it isn't a number."""
    parts = (text or "").strip().split(None, 1)
    if not parts:
        return None
    head = parts[0]
    number, unit = (head, parts[1].strip() if len(parts) > 1 else None)
    if len(parts) == 1:            # 90% or 5000ms written without a space
        cut = next((i for i, ch in enumerate(head) if not (ch.isdigit() or ch in ".-")), len(head))
        number, unit = head[:cut], head[cut:] or None
    try:
        return Decimal(number), unit
    except InvalidOperation:
        return None


def convert(value, unit, to_unit):
    """value in unit as a value in to_unit (Decimal), or None when the two aren't of one kind; a value without a unit
    is taken as it is."""
    if unit is None or unit == to_unit:
        return value
    have, want = UNITS.get(unit), UNITS.get(to_unit)
    if have is None or want is None or have[0] != want[0]:
        return None
    return value * have[1] / want[1]


def number_text(value):
    """A Decimal as the shortest plain number text (5, 0.25, 0.833333: six decimal places at most), never in exponent
    form."""
    text = format(value.quantize(Decimal("0.000001")).normalize(), "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def threshold_in(rule, to_unit):
    """The rule's threshold converted to to_unit, as number text, or None when it can't be (no threshold, not a
    number, or a unit of another kind)."""
    parsed = parse_threshold(one(rule, "ciamThreshold"))
    if parsed is None:
        return None
    value = convert(parsed[0], parsed[1], to_unit)
    return number_text(value) if value is not None else None


def product_signal(signals, rule):
    """The Signal a product declares for the rule's signal on its target role, or None."""
    name, role = one(rule, "ciamSignal"), one(rule, "ciamTargetRole")
    return next((s for s in signals if s.signal == name and s.server_role == role), None)


def alarm_for(m, rule):
    """Environment m's alarm binding realizing the rule (ciamRealizes names it), or None."""
    name = rdn_value(rule)
    return next((b for b in of_class(m, "ciamAlarmBinding") if one(b, "ciamRealizes") == name), None)


def evaluation(m, signals, rule):
    """How the rule is evaluated in environment m, given the Signals of the adapters rendering it."""
    alarm, signal = alarm_for(m, rule), product_signal(signals, rule)
    if (alarm is not None and one(alarm, "ciamMetric")) or signal is not None:
        return Evaluation(rule, alarm, signal, None)
    role = one(rule, "ciamTargetRole")
    return Evaluation(rule, alarm, None,
                      f"no alarm in {m.label} realizes it with a recorded metric (ciamMetric), and no product "
                      f"declares signal `{one(rule, 'ciamSignal')}`" + (f" for role `{role}`" if role else ""))


def promql(rule, signal):
    """(PromQL alert expression for the rule on a product Signal, None) or (None, why it can't be written)."""
    op = PROMQL_OPERATORS.get(one(rule, "ciamComparison") or "")
    if op is None:
        return None, f"alert rule {rdn_value(rule)} records no comparison (ciamComparison)"
    threshold = threshold_in(rule, signal.unit)
    if threshold is None:
        return None, (f"alert rule {rdn_value(rule)}'s threshold {one(rule, 'ciamThreshold')!r} can't be read in "
                      f"{signal.signal}'s unit ({signal.unit})")
    return f"({signal.expr}) {op} {threshold}", None

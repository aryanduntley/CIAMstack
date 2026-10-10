"""Alerting and log retention on Google Cloud (core observability) as Cloud Monitoring alert policies and Cloud
Logging bucket settings. Pure.

Alert policies (domains/observability/alarms): each alert rule the environment delivers, realized by an alarm binding
that records its metric type (ciamMetric: custom.googleapis.com/..., agent.googleapis.com/...), as a
google_monitoring_alert_policy named as the binding with one threshold condition on that metric type: the rule's
comparison, its threshold in the unit it is written in where it is a duration in ms, else in seconds, bytes or
percent (a comment says which the metric must report), each series aligned over a minute (its mean; for a rate, its
delta over the window, compared as a count), held for the rule's evaluation period; notifying the rule's channel
(its ciamProviderRef, when it is a notification channel name); user labels realizes and bindingrole so the inventory
reads it back as the same binding. A rule realized by a log-based alarm (ciamMetric "log query"), or whose metric
isn't a metric type, is named; an alarm someone else keeps, or an overlay inherits from its base (rendered there),
is named with its keeper.

Log buckets: each log destination the platform keeps (not inherited) whose ciamProviderRef is a Cloud Logging bucket
(projects/<p>/locations/<l>/buckets/<b>) as google_logging_project_bucket_config keeping logs as many days as recorded
(1 to 3650: indefinitely or longer kept 3650 with a comment). A bucket a route under legal hold sends logs to is
named for locking, never locked here: a locked bucket's retention can't be lowered nor the bucket deleted, ever.
"""
import re
from decimal import Decimal

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class
from opsdir.domains.observability.alarms import alarm_specs, condition, in_unit
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.realized import keeper_of
from opsdir.domains.observability.signals import number_text, parse_threshold
from opsdir_format_terraform.hcl import Block, block, tf_name
from .names import label, resource_id

POLICY = "google_monitoring_alert_policy"
BUCKET = "google_logging_project_bucket_config"
COMPARISONS = {"gt": "COMPARISON_GT", "ge": "COMPARISON_GE", "lt": "COMPARISON_LT", "le": "COMPARISON_LE",
               "eq": "COMPARISON_EQ", "ne": "COMPARISON_NE"}
ALIGNERS = {"average": "ALIGN_MEAN", "sum": "ALIGN_DELTA"}
MAX_DAYS = 3650
_BUCKET = re.compile(r"^projects/([^/]+)/locations/([^/]+)/buckets/([^/]+)$")


def _number(text):
    value = Decimal(text)
    return int(value) if value == value.to_integral_value() else float(text)


def _must_report(unit):
    return f"compared in {unit}: the metric must report {unit}"


def _threshold(rule, c):
    """(threshold text, a comment on what it is compared in, or None) of a rule's Condition."""
    value, unit = parse_threshold(one(rule, "ciamThreshold"))
    if c.kind is None:
        return c.threshold, None
    if c.kind == "count":
        return c.threshold, f"{one(rule, 'ciamThreshold')} as a count over each {c.window}s"
    if unit == "ms":
        return number_text(value), _must_report("milliseconds")
    return {"time": (c.threshold, _must_report("seconds")), "size": (c.threshold, _must_report("bytes")),
            "share": (in_unit(c, "%"), _must_report("percent"))}[c.kind]


def _channel(channel):
    ref_ = one(channel, "ciamProviderRef") or ""
    return ref_ if "/notificationChannels/" in ref_ else None


def _policy(m, s):
    rule = rdn_value(s.rule)
    if s.why:
        return (f"# NOTE: alert rule {rule}: not rendered: {s.why}",)
    name = rdn_value(s.alarm)
    if s.keeper is not None:
        return (f"# Alert policy {name} (alert rule {rule}): kept by {s.keeper}, not rendered here",)
    comparison, c, metric = COMPARISONS.get(one(s.rule, "ciamComparison") or ""), condition(s.rule), \
        one(s.alarm, "ciamMetric") or ""
    why = ("its alarm is a log-based alert and the record holds no query" if metric == "log query"
           else f"its alarm's metric {metric!r} isn't a metric type (<service>/<path>)" if "/" not in metric
           or " " in metric
           else f"Cloud Monitoring has no comparison {one(s.rule, 'ciamComparison')!r}" if comparison is None
           else f"its threshold {one(s.rule, 'ciamThreshold')!r} isn't a number with a known unit" if c is None
           else None)
    if why:
        return (f"# NOTE: alert rule {rule}: not rendered: {why}",)
    threshold, compared = _threshold(s.rule, c)
    target = _channel(s.channel)
    return (block("resource", [POLICY, tf_name(name)], [
        ("display_name", name), ("combiner", "OR"),
        ("conditions", Block((
            ("display_name", f"{one(s.rule, 'ciamSignal')} {one(s.rule, 'ciamComparison')} "
                             f"{one(s.rule, 'ciamThreshold')}"),
            ("condition_threshold", Block((
                *((("#", compared),) if compared else ()),
                ("filter", f'metric.type = "{metric}"'), ("comparison", comparison),
                ("threshold_value", _number(threshold)), ("duration", f"{c.window * c.windows}s"),
                ("aggregations", Block((("alignment_period", f"{c.window}s"),
                                        ("per_series_aligner", ALIGNERS[c.statistic])))))))))),
        ("documentation", Block((("content", f"Alert rule {rule} (opsdir)"), ("mime_type", "text/markdown")))),
        *((("notification_channels", [target]),) if target else
          (("#", f"channel {rdn_value(s.channel)} names no notification channel (ciamProviderRef): none"),)),
        ("user_labels", {"realizes": label(rule), "bindingrole": label(one(s.alarm, "ciamBindingRole"))})]),)


def render_policies(m):
    """HCL (and comments) for environment m's Cloud Monitoring alert policies."""
    return tuple(x for s in alarm_specs(m) for x in _policy(m, s))


def bucket_retention(days):
    """(retention_days a log bucket allows for a recorded number of days, why it differs or None); 0 is
    indefinitely."""
    if days == 0 or days > MAX_DAYS:
        return MAX_DAYS, (f"{'indefinitely' if days == 0 else f'{days} days'} is longer than a log bucket keeps logs "
                          f"({MAX_DAYS}): kept {MAX_DAYS}")
    return max(days, 1), None


def _held(m, b):
    """Whether a log route under legal hold sends logs to destination b's role."""
    role = one(b, "ciamBindingRole")
    return any(one(r, "ciamLegalHold") == "TRUE" and role in values(r, "ciamLogDestinationRole")
               for r in log_routes(m.d))


def _bucket(m, b):
    cn, found = rdn_value(b), _BUCKET.match(resource_id(one(b, "ciamProviderRef") or "") or "")
    if found is None:
        return ()
    project, location, bucket = found.groups()
    if keeper_of(m, b):
        return (f"# Log bucket {cn}: kept by {keeper_of(m, b)}, not rendered here",)
    days, why = bucket_retention(int(one(b, "ciamRetentionDays"))) if one(b, "ciamRetentionDays") is not None \
        else (None, "no retention recorded (ciamRetentionDays): the bucket keeps Cloud Logging's default")
    hold = ("under legal hold: lock it (locked = true) once its retention is confirmed; a locked bucket's retention "
            "can't be lowered nor the bucket deleted, ever") if _held(m, b) else None
    return (block("resource", [BUCKET, tf_name(cn)], [
        *(("#", w) for w in (why, hold) if w),
        ("project", project), ("location", location), ("bucket_id", bucket),
        *((("retention_days", days),) if days is not None else ())]),)


def render_buckets(m):
    """HCL (and comments) for environment m's Cloud Logging buckets."""
    return tuple(x for b in of_class(m, "ciamLogDestination") for x in _bucket(m, b))

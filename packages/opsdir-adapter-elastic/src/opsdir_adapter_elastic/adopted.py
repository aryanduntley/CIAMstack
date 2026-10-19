"""The alert rules adopting a product's declared detection as Elastic Security ES|QL rules (task 597): per rule the
environment delivers that no alarm binding of its own realizes (observability.detections.native_rules), a detection
rule whose ES|QL is written here from the rule's canonical selector and the declaration's mapping for the product
version the environment runs, over the Elastic data streams the rule's server role's log routes reach (detections.
searched). Pure.

The query: `FROM <stream>[, <stream>...] | WHERE <selector>`, each canonical field as the product's field (in
backticks where ES|QL needs them) and each canonical value as the product's (field == "value", field IN ("a", "b")),
the fields it counts by not null; then, when the rule counts, `STATS events = COUNT(*) BY <group-by fields> | WHERE
events >= <threshold>`, or with a distinct field `STATS value_count = COUNT_DISTINCT(<field>) BY ... | WHERE value_count
>= <threshold>` (approximate past 3,000 distinct values, ES|QL's default precision: far beyond a threshold). Each row is
an alert, its investigation fields the group-by fields. A rule without a threshold alerts per matching event (METADATA
_id, _index, _version, so overlapping runs don't repeat an event's alert), every 5 minutes over the 5 before.

The window (research on task 597: Elastic's ES|QL rule and alert suppression documentation): a rule searches from
now-<lookback> to now every interval.
- fixed: interval and lookback the window, so the runs search back-to-back windows; they start when the rule is
  enabled, not on the clock's boundaries (a note);
- sliding: it runs every step (detections.overlap_step: a fifth of the window, a minute at least, Kibana's minimum
  interval) over the whole window, and its alerts are suppressed per group for a window (alert_suppression: group_by
  the group-by fields, duration, missing_fields_strategy suppress; ES|QL rules since 8.15), since an aggregating query's
  alerts aren't deduplicated across overlapping runs. Every burst within the window less one step is caught; a rule
  grouping by nothing has nothing to suppress by, so it alerts each run while the window holds (a note).

The rule is named opsdir-<rule> (detections.native_name), which the readers leave out: the record holds no search for
it. A rule the render can't write is a blocker (detections.native_notes): its condition isn't a count reached, no
mapping holds for the product version the environment runs, a field the mapping doesn't name, or a sliding window too
short to search again within it.

A product field inside a list (detections.LIST, `entries[].info.nodeId`) is the multi-valued field Elasticsearch
flattens it into (`entries.info.nodeId`); ES|QL compares only single values, so the query expands each such field it
uses first (`| MV_EXPAND entries.info.nodeId`), one row per value. Two expanded fields pair every value of one with
every value of the other, so an event with several list elements could match one element's value with another's, and a
rule without a threshold alerts once per row (not yet checked live).
"""
import re

from opsdir.core.directory import rdn_value, values
from opsdir.core.inventory import duration_text
from opsdir.core.notes import note
from opsdir.domains.observability.detections import (LIST, native_name, native_notes, native_rules, overlap_step,
                                                     product_field, product_values, searched)
from opsdir.domains.observability.siem import described
from .attack import threat
from .detections import ROWS_PERIOD, SEVERITIES, TAG, UNRATED, attack_notes
from .naming import NATIVE, keeps, stream_name

MIN_STEP = 60                       # Kibana's minimum rule interval (minimumScheduleInterval, 1m by default)
_PLAIN = re.compile(r"^[A-Za-z_@][A-Za-z0-9_]*(\.[A-Za-z_@][A-Za-z0-9_]*)*$")
_UNITS = (("h", 3600), ("m", 60), ("s", 1))       # alert suppression's duration units


def esql_field(name):
    """A field name as ES|QL names it: as it is, or in backticks (doubled within) where it must be quoted."""
    return name if _PLAIN.match(name) else "`" + name.replace("`", "``") + "`"


def flat_field(path):
    """A product field path as Elasticsearch flattens it: a list's elements ([]) are the field's values."""
    return path.replace(LIST, "")


def _field(mapping, f):
    return flat_field(product_field(mapping, f))


def esql_string(text):
    """An ES|QL string literal."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _term(field, found):
    return (f"{esql_field(field)} == {esql_string(found[0])}" if len(found) == 1 else
            f"{esql_field(field)} IN ({', '.join(map(esql_string, found))})")


def grouped(det, mapping):
    """The product's fields a declaration as a rule has it (det) groups by, in order."""
    return tuple(_field(mapping, f) for f in det.group_by)


def esql_search(det, mapping, streams):
    """The ES|QL of a declaration as an alert rule has it (det) in the product's fields and values (mapping), over the
    data streams: its matching events with the fields it counts by, counted per group (or their distinct values of its
    distinct field) and kept where they reach its threshold; the events themselves (with their metadata) when it has
    none."""
    counted = (*grouped(det, mapping), *((_field(mapping, det.distinct),) if det.distinct else ())) \
        if det.threshold is not None else ()
    terms = (*(_term(_field(mapping, f), tuple(dict.fromkeys(v for c in vals for v in product_values(mapping, f, c))))
               for f, vals in det.selector),
             *(f"{esql_field(p)} IS NOT NULL" for p in dict.fromkeys(counted)))
    used = (*(f for f, _ in det.selector), *(det.group_by if det.threshold is not None else ()),
            *((det.distinct,) if det.distinct and det.threshold is not None else ()))
    expanded = tuple(dict.fromkeys(_field(mapping, f) for f in used if LIST in (product_field(mapping, f) or "")))
    head = f"FROM {', '.join(streams)}" + (" METADATA _id, _index, _version" if det.threshold is None else "")
    query = "".join((head, *(f" | MV_EXPAND {esql_field(f)}" for f in expanded), f" | WHERE {' AND '.join(terms)}"))
    if det.threshold is None:
        return query
    by = f" BY {', '.join(map(esql_field, grouped(det, mapping)))}" if det.group_by else ""
    if det.distinct:
        return (f"{query} | STATS value_count = COUNT_DISTINCT({esql_field(_field(mapping, det.distinct))})"
                f"{by} | WHERE value_count >= {det.threshold}")
    return f"{query} | STATS events = COUNT(*){by} | WHERE events >= {det.threshold}"


def schedule(det):
    """((interval, lookback, suppression) in seconds (suppression None: none), None) of a declaration's rule (det: as
    the rule has it), or (None, why its window can't be kept)."""
    if det.threshold is None:
        return (ROWS_PERIOD, ROWS_PERIOD, None), None
    window = det.window_seconds
    if det.window_kind == "fixed":
        return (window, window, None), None
    step = overlap_step(window, MIN_STEP)
    if det.window_kind != "sliding" or step is None:
        return None, (f"its window kind {det.window_kind!r} isn't sliding or fixed" if det.window_kind != "sliding"
                      else f"its sliding window ({window}s) is too short to search again within it (a rule runs each "
                           "minute at the most often)")
    return (step, window, window), None


def suppression_duration(seconds):
    """An alert suppression's duration ({value, unit}: the largest of h, m, s dividing seconds)."""
    unit, size = next((u, s) for u, s in _UNITS if seconds % s == 0)
    return {"value": seconds // size, "unit": unit}


def _why(x):
    return x.why or schedule(x.det)[1]


def elastic_rules(m, services):
    """((NativeRule, the Elastic data streams it searches), ...) of environment m's adopting rules whose server role's
    logs reach an Elastic data stream it keeps (the rest are another SIEM's, or none's)."""
    return tuple((x, found) for x in native_rules(m, services.detections(m), lists=True)
                 for found in (searched(m, x.det, keeps),) if found)


def native_body(x, streams):
    """The detection rule of adopting rule x (a NativeRule) over Elastic data streams, as the detection engine API
    takes it, or None when it isn't rendered (_why)."""
    if _why(x):
        return None
    rule, fields = rdn_value(x.rule), grouped(x.det, x.mapping)
    (every, lookback, hold), _ = schedule(x.det)
    severity, risk = SEVERITIES.get(x.det.severity or "", UNRATED)
    mapped = threat(values(x.rule, "ciamAttackTactic"), values(x.rule, "ciamAttackTechnique"))
    return {"rule_id": native_name(rule), "name": rule, "description": described(rule), "type": NATIVE,
            "language": NATIVE, "query": esql_search(x.det, x.mapping, tuple(map(stream_name, streams))),
            "interval": duration_text(every), "from": f"now-{duration_text(lookback)}", "to": "now",
            "severity": severity, "risk_score": risk, "enabled": True, "tags": [TAG],
            **({"threat": mapped} if mapped else {}),
            **({"investigation_fields": {"field_names": list(fields)}} if fields else {}),
            **({"alert_suppression": {"group_by": list(fields), "duration": suppression_duration(hold),
                                      "missing_fields_strategy": "suppress"}} if hold and fields else {})}


def native_bodies(m, services):
    """((the alert rule's name, rule body), ...) of environment m's adopting rules rendered as ES|QL rules."""
    return tuple((native_name(rdn_value(x.rule)), body) for x, found in elastic_rules(m, services)
                 for body in (native_body(x, found),) if body is not None)


def adopted_notes(m, services):
    """The render notes of environment m's adopting rules in Elastic: those not rendered (blockers), those rendered
    from a declaration documented only, the ATT&CK their threat arrays leave out, a fixed window not aligned to the
    clock and a sliding one alerting each run for want of a field to suppress by (notes)."""
    found = tuple(x for x, _ in elastic_rules(m, services))
    done = tuple(x for x in found if not _why(x))
    return (*native_notes(m, done, tuple((x, _why(x)) for x in found if _why(x)), "Elastic"),
            *(n for x in done for n in attack_notes(m, x.rule, x.rule.dn)),
            *(note("Monitoring", "note", f"alert rule {rdn_value(x.rule)}", f"its fixed window "
                   f"({duration_text(x.det.window_seconds)}) is searched back to back from when its Elastic rule is "
                   "enabled, not from the clock's boundaries", (), x.rule.dn, m.label)
              for x in done if x.det.threshold is not None and x.det.window_kind == "fixed"),
            *(note("Monitoring", "note", f"alert rule {rdn_value(x.rule)}", "its sliding window is searched again "
                   "every step, and grouping by nothing it has no field to suppress its repeated alerts by: it alerts "
                   "each run while the window holds", ("Group it by the field its findings are about (ciamGroupBy)",),
                   x.rule.dn, m.label)
              for x in done if x.det.threshold is not None and x.det.window_kind == "sliding" and not x.det.group_by))

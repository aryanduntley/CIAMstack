"""An environment's detections on its Elastic data streams as Elastic Security detection rules (decision on task 552).
Pure.

Each alert rule a detection realizes on an Elastic data stream here (alarms.detection_specs) is an ES|QL rule: the
detection's search (ciamMetric, ES|QL starting FROM the stream it searches) counted per window, each window compared
with the rule's threshold, returning a row (an alert) when every window of the rule's evaluation period breaches
(alarms.detection_condition): `<search> | STATS events = COUNT(*) BY slot = BUCKET(@timestamp, <window> seconds) |
WHERE events > <n> | STATS breaching = COUNT(*) | WHERE breaching >= <windows>`. It runs every period (interval) over
the period (from now-<period> to now: the detection engine limits the search to that range on @timestamp itself). A
threshold rule can't say "every window", so ES|QL is the one language the render writes; a detection recording another
(ciamSearchLanguage kuery, lucene, eql) is read and kept, not rendered. Its rule_id is the detection's provider
reference, its name the alert rule, its description names the rule (siem.described, which the importer reads back),
its severity and risk score from the rule's ciamSeverity (sev0 critical 99, sev1 high 73, sev2 medium 47, sev3 and
sev4 low 21; medium 47 when none), tagged opsdir.

Named instead (detection_notes): a detection recording no search (a note), and as blockers one the condition, its
language or its search's source keeps from rendering.
"""
import re

from opsdir.core.directory import one, rdn_value
from opsdir.core.inventory import duration_text
from opsdir.domains.observability.alarms import alarm_note, detection_condition, detection_specs
from opsdir.domains.observability.siem import described, detection_index, search_language
from .naming import NATIVE, stream_name

SEVERITIES = {"sev0": ("critical", 99), "sev1": ("high", 73), "sev2": ("medium", 47), "sev3": ("low", 21),
              "sev4": ("low", 21)}
UNRATED = ("medium", 47)
OPERATORS = {"gt": ">", "ge": ">="}
TAG = "opsdir"
_FROM = re.compile(r"^\s*FROM\s+\"?([^\s,|\"]+)", re.IGNORECASE)
_WRAPPED = re.compile(r"^(?P<base>.*) \| STATS events = COUNT\(\*\) BY slot = BUCKET\(@timestamp, \d+ seconds\) "
                      r"\| WHERE events >=? \S+ \| STATS breaching = COUNT\(\*\) \| WHERE breaching >= \d+$", re.DOTALL)


def source_of(query):
    """The first source an ES|QL query names (FROM <source>), or None."""
    found = _FROM.match(query or "")
    return found.group(1) if found else None


def esql_query(metric, rule, c):
    """The rule's ES|QL: the detection's search counted per window, each window compared with the rule's threshold, a
    row when every window of the period breaches."""
    return (f"{metric} | STATS events = COUNT(*) BY slot = BUCKET(@timestamp, {c.window} seconds) | WHERE events "
            f"{OPERATORS[one(rule, 'ciamComparison')]} {c.threshold} | STATS breaching = COUNT(*) "
            f"| WHERE breaching >= {c.windows}")


def base_query(query):
    """A rule's own search: the one the render wrapped with an alert rule's condition, else the query as written."""
    found = _WRAPPED.match(query or "")
    return found.group("base") if found else (query or "")


def elastic_detections(m):
    """Environment m's detection AlarmSpecs on an Elastic data stream it renders (not a base environment's)."""
    return tuple(s for s in detection_specs(m)
                 if s.keeper is None and stream_name(detection_index(m, s.alarm)) is not None)


def _why(m, s):
    """Why detection spec s isn't rendered as an ES|QL rule, about what the record holds, or None."""
    _, why = detection_condition(s.rule)
    language, stream = search_language(s.alarm, NATIVE), stream_name(detection_index(m, s.alarm))
    if why:
        return why
    if language != NATIVE:
        return (f"its search is written in {language} (ciamSearchLanguage), and opsdir renders Elastic's detections "
                "as ES|QL rules (a threshold rule can't require every window of the period)")
    if source_of(one(s.alarm, "ciamMetric")) != stream:
        return f"its search (ciamMetric) doesn't start FROM {stream}, the data stream it searches"
    return None


def rule_body(m, s):
    """The detection rule of detection spec s as the detection engine API takes and answers it, or None when it isn't
    rendered (detection_notes)."""
    if s.why or _why(m, s):
        return None
    c, _ = detection_condition(s.rule)
    every, rule = duration_text(c.window * c.windows), rdn_value(s.rule)
    severity, risk = SEVERITIES.get(one(s.rule, "ciamSeverity") or "", UNRATED)
    return {"rule_id": one(s.alarm, "ciamProviderRef"), "name": rule, "description": described(rule),
            "type": NATIVE, "language": NATIVE, "query": esql_query(one(s.alarm, "ciamMetric"), s.rule, c),
            "interval": every, "from": f"now-{every}", "to": "now", "severity": severity, "risk_score": risk,
            "enabled": True, "tags": [TAG]}


def rendered_rules(m):
    """((detection spec, rule body), ...) of environment m's detections rendered as ES|QL rules."""
    return tuple((s, body) for s in elastic_detections(m) for body in (rule_body(m, s),) if body is not None)


def detection_notes(m):
    """The render notes of environment m's Elastic detections not rendered: no search recorded (a note), a condition,
    language or source the render can't write (a blocker)."""
    def of(s):
        why = None if s.why else _why(m, s)
        return alarm_note(m, s) if s.why else alarm_note(m, s, why) if why else None
    return tuple(n for n in map(of, elastic_detections(m)) if n is not None)

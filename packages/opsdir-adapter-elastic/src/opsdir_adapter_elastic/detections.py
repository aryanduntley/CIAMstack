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

A rows detection (core ciamDetectionMode rows, decision 3299) runs its search as written: each row it returns is an
alert, run every evaluation period of its rule (5 minutes when none) over it. The rule's MITRE ATT&CK tactics and
techniques (ciamAttackTactic, ciamAttackTechnique) are its threat array (attack.threat: an entry per tactic with the
techniques serving it). A rows detection's entity mappings (ciamEntityMapping) name the result columns an alert is
about: they are its investigation fields (investigation_fields.field_names, the alert's highlighted fields; an ES|QL
rule's alert holds the row's columns). Elastic has no entity mapping of its own: its entity risk scoring groups alerts
by user.name and host.name, so an account or a host named by another column is a note. Neither severity_mapping nor
risk_score_mapping is rendered: the record holds no per-finding severity.

Named instead (detection_notes): a detection recording no search (a note), and as blockers one the condition, its
language or its search's source keeps from rendering; as notes, techniques the threat array leaves out (not in the
core's ATT&CK version, v20, or serving none of the rule's tactics), tactics that version retired (defense-evasion) and
entity columns Elastic's entity risk scoring doesn't read.
"""
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.inventory import duration_seconds, duration_text
from opsdir.core.notes import note
from opsdir.domains.observability.alarms import alarm_note, detection_condition, detection_specs
from opsdir.domains.observability.attack import VERSION, retired_tactics, unplaced
from opsdir.domains.observability.siem import (described, detection_index, detection_mode, entity_mappings,
                                               search_language)
from .attack import threat
from .naming import NATIVE, stream_name

SEVERITIES = {"sev0": ("critical", 99), "sev1": ("high", 73), "sev2": ("medium", 47), "sev3": ("low", 21),
              "sev4": ("low", 21)}
UNRATED = ("medium", 47)
OPERATORS = {"gt": ">", "ge": ">="}
TAG = "opsdir"
ROWS_PERIOD = 300                   # a rows detection's period when its rule records none (Elastic's default interval)
# the fields Elastic's entity risk scoring groups alerts by, per core entity and identifier (ciamEntityMapping)
ENTITY_FIELDS = {("account", "name"): "user.name", ("host", "hostname"): "host.name"}
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


def rows_period(s):
    """A rows detection spec's period in seconds: its rule's ciamEvaluationPeriod, else ROWS_PERIOD."""
    return duration_seconds(one(s.rule, "ciamEvaluationPeriod")) or ROWS_PERIOD


def _why(m, s):
    """Why detection spec s isn't rendered as an ES|QL rule, about what the record holds, or None."""
    _, why = (None, None) if detection_mode(s.alarm) == "rows" else detection_condition(s.rule)
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
    rows, rule = detection_mode(s.alarm) == "rows", rdn_value(s.rule)
    c = None if rows else detection_condition(s.rule)[0]
    every = duration_text(rows_period(s) if rows else c.window * c.windows)
    query = one(s.alarm, "ciamMetric") if rows else esql_query(one(s.alarm, "ciamMetric"), s.rule, c)
    severity, risk = SEVERITIES.get(one(s.rule, "ciamSeverity") or "", UNRATED)
    mapped = threat(values(s.rule, "ciamAttackTactic"), values(s.rule, "ciamAttackTechnique"))
    fields = list(dict.fromkeys(column for _, _, column in entity_mappings(s.alarm))) if rows else []
    return {"rule_id": one(s.alarm, "ciamProviderRef"), "name": rule, "description": described(rule),
            "type": NATIVE, "language": NATIVE, "query": query,
            "interval": every, "from": f"now-{every}", "to": "now", "severity": severity, "risk_score": risk,
            "enabled": True, "tags": [TAG], **({"threat": mapped} if mapped else {}),
            **({"investigation_fields": {"field_names": fields}} if fields else {})}


def rendered_rules(m):
    """((detection spec, rule body), ...) of environment m's detections rendered as ES|QL rules."""
    return tuple((s, body) for s in elastic_detections(m) for body in (rule_body(m, s),) if body is not None)


def _mapping_notes(m, s):
    """Notes of a rendered rule's ATT&CK techniques and retired tactics its threat array leaves out and of its entity
    columns Elastic's entity risk scoring doesn't read."""
    left = unplaced(values(s.rule, "ciamAttackTactic"), values(s.rule, "ciamAttackTechnique"))
    old = retired_tactics(values(s.rule, "ciamAttackTactic"))
    unread = tuple(f"{e} {i} by column {col}, not {ENTITY_FIELDS[(e, i)]}" for e, i, col in entity_mappings(s.alarm)
                   if (e, i) in ENTITY_FIELDS and col != ENTITY_FIELDS[(e, i)]) \
        if detection_mode(s.alarm) == "rows" else ()
    rule = rdn_value(s.rule)
    return (*((note("Monitoring", "note", f"alert rule {rule}", f"its ATT&CK techniques {', '.join(left)} aren't in "
                    "its Elastic rule's threat mapping: a technique is mapped under a tactic it serves, and these "
                    f"serve none of the rule's tactics (ciamAttackTactic) or aren't in {VERSION}",
                    ("Record the tactics they serve (ciamAttackTactic), or map them in Kibana (the rule's MITRE "
                     "ATT&CK settings)",), s.alarm.dn, m.label),) if left else ()),
            *((note("Monitoring", "note", f"alert rule {rule}", f"its ATT&CK tactics {', '.join(old)} aren't in its "
                    f"Elastic rule's threat mapping: {VERSION} retired them",
                    ("Apply the plan's fix choosing their successor (ciamAttackTactic)",), s.rule.dn, m.label),)
              if old else ()),
            *((note("Monitoring", "note", f"alert rule {rule}", f"its entity mappings name {'; '.join(unread)}: "
                    "Elastic's entity risk scoring groups alerts by user.name and host.name, so its alerts add to no "
                    "entity's risk score (the columns are only its investigation fields)",
                    ("Return the column under that field's name in the search (ES|QL: RENAME <column> AS "
                     "user.name) and record the mapping so",), s.alarm.dn, m.label),) if unread else ()))


def detection_notes(m):
    """The render notes of environment m's Elastic detections: of one not rendered, no search recorded (a note) or a
    condition, language or source the render can't write (a blocker); of one rendered, the ATT&CK techniques and
    entity columns it can't map (notes)."""
    def of(s):
        why = None if s.why else _why(m, s)
        return (alarm_note(m, s),) if s.why else (alarm_note(m, s, why),) if why else _mapping_notes(m, s)
    return tuple(n for s in elastic_detections(m) for n in of(s))

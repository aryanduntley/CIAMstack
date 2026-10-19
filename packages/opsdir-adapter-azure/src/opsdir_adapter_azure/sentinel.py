"""Microsoft Sentinel on Azure (core observability: a SIEM index, decision 3046): a log destination of kind siem-index
whose ciamProviderRef is a Log Analytics workspace ID is a workspace with Sentinel on it. Pure.

The workspace itself is rendered as any other (observability.render_workspaces: its analytics retention), the log
routes ship to it as to any workspace (log_collection, container_logs), and a route's custom table (log_collection) or
the containers' ContainerLogV2 table (container_logs) keeps its logs as long in all as the destination says
(ciamTotalRetentionDays). Here: Sentinel turned on for the workspace
(azurerm_sentinel_log_analytics_workspace_onboarding, where this environment renders the workspace), and each alert
rule a detection realizes on it (alarms.detection_specs) as a scheduled analytics rule
(azurerm_sentinel_alert_rule_scheduled): the detection's KQL (ciamMetric) counted per window, compared with the rule's
threshold, firing when every window of the rule's evaluation period breaches (alarms.detection_condition), run as often
as that period (5 minutes at least), over it; its severity from ciamSeverity (sev0 and sev1 High, sev2 Medium, sev3
Low, sev4 Informational; Medium when none); its description naming the rule (siem.described), which the importers read
back. Microsoft documents the rule fields (query, query_frequency, query_period, severity, trigger_operator,
trigger_threshold) for the alertRules API 2025-09-01 (research on milestone 104).

Named instead, each a render note written as its comment: a detection not rendered (alarms.alarm_note: no search
recorded; a condition Sentinel can't count; a period shorter than 5 minutes), the total retention of the workspace's
other tables (Sentinel's own), which are set by hand, and in Azure Government what Microsoft doesn't
state is available there (the Tables API's total retention, Sentinel's data lake tiers).

The rule's MITRE ATT&CK tactics become Sentinel's (credential-access: CredentialAccess) and its techniques the parent
techniques (a sub-technique, T1078.004, is rendered as T1078 with a note: azurerm has no sub-technique field, and
neither has the alertRules API's stable version, 2025-09-01, whose change log removed the previews' subTechniques:
the Bicep/ARM render, at that version, keeps the note too).
Sentinel follows ATT&CK v18 ("Microsoft Sentinel is currently aligned to The MITRE ATT&CK framework, version 18"):
the alertRules API (2025-09-01) documents its tactics as v18's, and azurerm 5.10.0 refuses any other (terraform
validate rejects Stealth and DefenseImpairment), while the record follows ATT&CK v20 (observability.attack), where
v19 split Defense Evasion into Stealth (TA0005, its ID) and Defense Impairment (TA0112). Both are rendered as
DefenseEvasion, the tactic they were in v18, with a note (research on task 588); a record still holding
defense-evasion renders as it always did. A rows
detection (ciamDetectionMode rows, milestone 109, decision 3299) runs its search as written, one alert per result row
(event_grouping AlertPerResult), as often as the rule's evaluation period (5 minutes at least), with its entity
mappings (core ciamEntityMapping: account, ip, host, url, application as Sentinel's Account, IP, Host, URL,
CloudApplication; at most three identifiers each, Sentinel's limit).

Incidents and custom details (task 592; the record holds no choice of them, so they follow from the detection): a count
detection keeps Sentinel's default, an incident per alert and no grouping (it raises one alert per run). A rows
detection's alerts (up to 150 a run) are grouped into incidents (incident: created, grouping enabled, closed incidents
not reopened) within its evaluation period (5 minutes to 7 days, Sentinel's range: a longer period groups 7 days, with
a note), by the entity types it maps (Selected, the only types Sentinel lets a rule group by), or, mapping none, all
its alerts of the period into one (AnyAlert). Its result columns its entity mappings don't use become custom details,
each keyed by its own name (custom_details), so analysts see them on the alert: the columns are read from the search's
last stage naming them (project, distinct, summarize: a name, a column, bin(Column, ...); where, take, sort, top after
it keep them); a search naming them otherwise is a note. Sentinel takes 20 custom details per rule, keys of 20
characters at most: the rest are a note.

An alert rule adopting a product's declared detection (task 597) that the environment delivers and no alarm binding
of its own realizes (observability.detections.native_rules) is a scheduled analytics rule named opsdir-<rule> in each
Sentinel workspace its server role's log routes reach (adopted_rule), its KQL written here from the rule's canonical
selector and the declaration's mapping (adopted_query): the routes' custom tables holding the role's log files, the
JSON in RawData parsed (a product field's dots as nested keys), the selector in the product's values, the fields it
counts by as columns named after the canonical fields, `summarize events = count()` (or `value_count = dcount(...)`)
by its group-by fields, kept where they reach its threshold; an alert per result, its subject or actor an Account and
its source address an IP, its incidents grouping a window's alerts by them. A fixed window runs back to back (query
frequency = period = the window, from when the rule is enabled: a note); a sliding one looks back over the window every
step (detections.overlap_step, 5 minutes at least: Sentinel's shortest), the incident grouping folding the overlapping
runs' repeats into one incident (Sentinel's suppression would stop the whole rule, every group with it). What can't be
written (a window outside 5 minutes to 14 days, a sliding one with no shorter step, the role's log files in no table of
the workspace: container output isn't searched, a missing mapping or field) is a blocker (detections.native_notes).

Sentinel's own choices for a detection (milestone 129, decision 3538; the adapter's auxiliary class azSentinelRule on
its alarm binding, schema.py: the core's detections stay vendor-neutral): a rows detection may run as a near-real-time
rule (azSentinelRuleKind nrt: azurerm_sentinel_alert_rule_nrt, every minute over what arrived since its last run, so no
query frequency, period or trigger; its evaluation period still sets how long its incidents group alerts, 5 minutes at
least); its alerts' details may come from its results (alert_details_override: the name and description formats with
{{Column}} placeholders, the severity and tactics columns, alert properties set by columns) and Sentinel may stop
running it for a while after an alert (suppression_enabled, suppression_duration: 5 minutes to 24 hours, azurerm
5.10.0's range). What a rule can't do is a blocker (_choice_why): a count detection as an NRT rule (its windows over a
period can't be counted without a lookback) or naming result columns (its results are the breaching count), a column
its search's last stage doesn't return, a suppression outside the range or not in whole minutes. Sentinel takes 50
enabled NRT rules per workspace, 100 in all with disabled ones (its service limits; its NRT overview says 50 per
customer: research m109c), so the planner counts the NRT rules a render puts in each workspace (check_nrt_quota). Both
forms render the choices; NRT rules stay in Terraform beside a Bicep/ARM render (arm_types.KEPT: the Bicep type index's
stable alertRules versions have no NRT kind).

Read back (sentinel_resources, with the inventory): a workspace is a SIEM index when the source holds its Sentinel
onboarding; a scheduled or NRT analytics rule is a detection realizing the rule its description names (role
alarm-<rule>), searching the workspace it runs in, holding its query without the condition the render wrapped around
it, and the choices it holds (rule_choices: its kind, alert details override, suppression), which an import makes
exactly the source's (with_sentinel_choices: a choice the source no longer holds is dropped, the class added where one
is held), so a choice changed in the portal is drift. Its incident configuration and custom details (read by the CLI
and ARM readers in azurerm's shape, as state holds them) follow from the detection, so they read back as nothing the
record holds: a round trip shows no drift. A rule named opsdir-<rule> realizing its rule (detections.is_native) is left
out: the record holds no search for it.
"""
import re
from itertools import accumulate

from opsdir.core.directory import make_entry, one, rdn_value, values
from opsdir.core.findings import findings, responsible
from opsdir.core.inventory import duration_seconds, duration_text, of_types, realization_roles, resource
from opsdir.core.notes import note, note_comment
from opsdir.domains.observability.alarms import alarm_note, detection_condition, detection_specs
from opsdir.domains.observability.detections import (ENTITIES, LIST, is_native, native_name, native_notes,
                                                     native_rules, overlap_step, product_field, product_values,
                                                     searched)
from opsdir.domains.observability.realized import keeper_of
from opsdir.domains.observability.siem import (described, detection_index, detection_mode, entity_mappings, is_siem,
                                               realized_in, siem_destinations)
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import unstated_note
from .kql import literal
from .log_collection import host_shipments, table_name
from .observability import iso_duration, iso_seconds, workspace_id, workspace_name
from .schema import CHOICES, SENTINEL_RULE

ONBOARDING = "azurerm_sentinel_log_analytics_workspace_onboarding"
RULE = "azurerm_sentinel_alert_rule_scheduled"
NRT = "azurerm_sentinel_alert_rule_nrt"
RULES = (RULE, NRT)
MIN_PERIOD = 300                        # Sentinel runs a scheduled rule every 5 minutes at the most often
MAX_PERIOD = 14 * 86400                 # ... and looks back 14 days at the most (query frequency and period)
EVENT = "ciamEvent"                     # the column an adopting rule's query parses a log line's JSON into
SEARCH_LANGUAGE = "kusto"               # ciamSearchLanguage of a detection's KQL (its native language)
SEVERITIES = {"sev0": "High", "sev1": "High", "sev2": "Medium", "sev3": "Low", "sev4": "Informational"}
OPERATORS = {"gt": ">", "ge": ">="}
# ATT&CK v20 tactics (short names) Sentinel has no name for, as the v18 tactic they were split from (task 588)
V18_TACTICS = {"stealth": "DefenseEvasion", "defense-impairment": "DefenseEvasion"}
# the core's entity types and identifiers (ciamEntityMapping) as Sentinel names them (entity reference, research m109c)
ENTITY_TYPES = {"account": "Account", "ip": "IP", "host": "Host", "url": "URL", "application": "CloudApplication"}
IDENTIFIERS = {("account", "name"): "Name", ("account", "upn-suffix"): "UPNSuffix",
               ("account", "nt-domain"): "NTDomain", ("account", "sid"): "Sid", ("account", "object-id"): "AadUserId",
               ("ip", "address"): "Address",
               ("host", "hostname"): "HostName", ("host", "dns-domain"): "DnsDomain", ("url", "url"): "Url",
               ("application", "app-id"): "AppId", ("application", "name"): "Name"}
CORE_ENTITY = {v: k for k, v in ENTITY_TYPES.items()}
CORE_IDENTIFIER = {(k[0], v): k[1] for k, v in IDENTIFIERS.items()}
MAX_IDENTIFIERS = 3                    # identifiers per entity mapping (Sentinel's entity mapping limit)
# Sentinel's limits (service limits; custom details, alert grouping: research on task 592): custom details per rule,
# the characters of a custom detail's key, an incident grouping's lookback at the longest (5 minutes to 7 days)
MAX_CUSTOM_DETAILS, MAX_KEY, MAX_LOOKBACK = 20, 20, 7 * 86400
# A rule's suppression, shortest and longest (azurerm 5.10.0's terraform validate: 5 minutes to 24 hours)
MIN_SUPPRESSION, MAX_SUPPRESSION = 300, 86400
# Near-real-time rules per workspace: enabled ones, and all of them, disabled ones included (Sentinel's service limits,
# research m109c; its NRT overview says 50 NRT rules per customer instead)
MAX_NRT_ENABLED, MAX_NRT_TOTAL = 50, 100
NRT_AREA = "Monitoring"
# The alert details override's fields (azurerm) and the choice each holds
OVERRIDES = (("display_name_format", "azSentinelAlertName"), ("description_format", "azSentinelAlertDescription"),
             ("severity_column_name", "azSentinelSeverityColumn"), ("tactics_column_name", "azSentinelTacticsColumn"))
_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_]\w*)\s*\}\}")
# KQL stages after the one naming a search's result columns that keep them (they filter or order rows)
_KEEPS_COLUMNS = frozenset({"where", "filter", "take", "limit", "sort", "order", "top"})
_NAMED = re.compile(r"^(?P<name>[A-Za-z_]\w*)\s*=(?!=)")
_COLUMN = re.compile(r"^[A-Za-z_]\w*$")
_BINNED = re.compile(r"^bin\(\s*(?P<name>[A-Za-z_]\w*)\s*,")
_TOKENS = r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|[()\[\]{}]"   # KQL strings, brackets
_OPEN, _CLOSE = ("(", "[", "{"), (")", "]", "}")
_WRAPPED = re.compile(r"^(?P<base>.*) \| summarize events = count\(\) by bin\(TimeGenerated, \d+s\) \| where events "
                      r">=? \S+ \| summarize breaching = count\(\) \| where breaching >= \d+$", re.DOTALL)


def is_sentinel(b):
    """Whether log destination b is a SIEM index on a Log Analytics workspace (Sentinel): kind siem-index, its
    ciamProviderRef a workspace ID."""
    return is_siem(b) and workspace_name(b) is not None


def keeps(m, b):
    """Adapter siem_indexes: whether log destination b of environment m is Sentinel on a workspace (is_sentinel)."""
    return is_sentinel(b)


def sentinel_detections(m):
    """Environment m's detection AlarmSpecs on a Sentinel workspace it renders (not a base environment's)."""
    return tuple(s for s in detection_specs(m) if s.keeper is None and is_sentinel(detection_index(m, s.alarm)))


def detection_query(metric, rule, c):
    """The scheduled rule's KQL: the detection's query counted per window, each window compared with the rule's
    threshold, a row when every window of the period breaches."""
    return (f"{metric} | summarize events = count() by bin(TimeGenerated, {c.window}s) | where events "
            f"{OPERATORS[one(rule, 'ciamComparison')]} {c.threshold} | summarize breaching = count() "
            f"| where breaching >= {c.windows}")


def base_query(query):
    """A scheduled rule's own query: the one the render wrapped with a rule's condition, else the query as written."""
    found = _WRAPPED.match(query or "")
    return found.group("base") if found else (query or "")


def _top_level(text, sep):
    """text split at each sep outside its quoted strings and brackets."""
    found = tuple(re.finditer(_TOKENS + "|" + re.escape(sep), text))
    depths = tuple(accumulate((1 if t.group() in _OPEN else -1 if t.group() in _CLOSE else 0 for t in found),
                              initial=0))
    cuts = tuple(t for t, depth in zip(found, depths) if t.group() == sep and depth == 0)
    return tuple(text[a:b] for a, b in zip((0, *(t.end() for t in cuts)), (*(t.start() for t in cuts), len(text))))


def _column(item, grouping):
    """The result column a project, distinct or summarize item makes: its name (Name = ...), a column as it is, the
    column a group binned (bin(Column, ...)); None for one KQL names itself (an unnamed expression)."""
    item = item.strip()
    found = _NAMED.match(item) or (_BINNED.match(item) if grouping else None)
    return found.group("name") if found else item if _COLUMN.match(item) else None


def result_columns(query):
    """The result columns of a KQL search, in order, from its last stage naming them (project, distinct, summarize;
    stages after it that filter or order rows passed over); None when it names them nowhere opsdir reads (another last
    stage, an unnamed expression)."""
    stages = tuple(" ".join(s.split()) for s in _top_level(query or "", "|"))[1:]
    op, _, rest = next((s for s in reversed(stages) if s.split(" ", 1)[0] not in _KEEPS_COLUMNS), "").partition(" ")
    if op in ("project", "distinct"):
        named = tuple(_column(x, False) for x in _top_level(rest, ","))
    elif op == "summarize" and len(_top_level(f" {rest}", " by ")) <= 2:
        aggregates, *groups = _top_level(f" {rest}", " by ")
        named = (*(_column(x, False) for x in _top_level(aggregates, ",") if x.strip()),
                 *(_column(x, True) for g in groups for x in _top_level(g, ",")))
    else:
        return None
    return named if named and None not in named else None


def custom_details(alarm):
    """Rows detection alarm's custom details: the result columns of its search (result_columns) its entity mappings
    don't name, in order; () for a count detection or a search whose columns opsdir can't read."""
    mapped = {column for _, _, column in entity_mappings(alarm)}
    return (tuple(c for c in result_columns(one(alarm, "ciamMetric")) or () if c not in mapped)
            if detection_mode(alarm) == "rows" else ())


def _details(alarm):
    """(the custom details rendered (keys of MAX_KEY characters at most, MAX_CUSTOM_DETAILS at most), those
    left out)."""
    fits = tuple(c for c in custom_details(alarm) if len(c) <= MAX_KEY)
    return fits[:MAX_CUSTOM_DETAILS], tuple(c for c in custom_details(alarm) if c not in fits[:MAX_CUSTOM_DETAILS])


def incident_grouping(s):
    """How detection spec s's alerts become incidents: None for a count detection (Sentinel's default: an incident
    per alert, no grouping), else (lookback seconds, matching method, entity types): a rows detection's alerts
    grouped within its evaluation period (5 minutes at the shortest, for an NRT rule's; MAX_LOOKBACK at the longest)
    by the entities it maps (Selected), or, mapping none, all of them (AnyAlert)."""
    if detection_mode(s.alarm) != "rows":
        return None
    types = tuple(ENTITY_TYPES[e] for e in dict.fromkeys(e for e, _, _ in entity_mappings(s.alarm)))
    return min(max(_period(s), MIN_PERIOD), MAX_LOOKBACK), "Selected" if types else "AnyAlert", types


def _incident(s):
    return _grouping(incident_grouping(s))


def _grouping(found):
    """The incident block of an incident grouping ((lookback seconds, matching method, entity types), or None: none)."""
    if found is None:
        return ()
    lookback, method, types = found
    return (("incident", Block((("create_incident_enabled", True), ("grouping", Block((
        ("enabled", True), ("lookback_duration", iso_duration(lookback)), ("reopen_closed_incidents", False),
        ("entity_matching_method", method), *((("by_entities", list(types)),) if types else ()))))))),)


def sentinel_tactic(tactic):
    """Sentinel's name of an ATT&CK tactic short name: credential-access -> CredentialAccess; a v20 tactic Sentinel
    has no name for as the v18 tactic it was split from (stealth, defense-impairment -> DefenseEvasion)."""
    return V18_TACTICS.get(tactic) or "".join(part.capitalize() for part in tactic.split("-"))


def parent_techniques(rule):
    """The rule's ATT&CK techniques as parent technique IDs (T1078.004 -> T1078), each once, in the record's order."""
    return tuple(dict.fromkeys(t.split(".", 1)[0] for t in values(rule, "ciamAttackTechnique")))


def _period(s):
    """A rows detection's evaluation period in seconds (the rule's ciamEvaluationPeriod; 5 minutes when none)."""
    return duration_seconds(one(s.rule, "ciamEvaluationPeriod")) or MIN_PERIOD


def rule_kind(alarm):
    """How Sentinel runs detection alarm's analytics rule: nrt (near-real-time) when its azSentinelRuleKind says so,
    else scheduled."""
    return one(alarm, "azSentinelRuleKind") or "scheduled"


def alert_properties(alarm):
    """((alert property, result column), ...) detection alarm's results set (azSentinelAlertProperty), in order."""
    return tuple(tuple(v.split("=", 1)) for v in values(alarm, "azSentinelAlertProperty") if "=" in v)


def override_columns(alarm):
    """The result columns detection alarm's alert details name, in order, each once: the {{Column}} placeholders of
    its name and description formats, its severity and tactics columns, the columns setting its alert properties."""
    formats = (one(alarm, "azSentinelAlertName") or "", one(alarm, "azSentinelAlertDescription") or "")
    return tuple(dict.fromkeys((*(c for f in formats for c in _PLACEHOLDER.findall(f)),
                                *(one(alarm, a) for a in ("azSentinelSeverityColumn", "azSentinelTacticsColumn")
                                  if one(alarm, a)),
                                *(c for _, c in alert_properties(alarm)))))


def suppression_seconds(alarm):
    """How long Sentinel stops running detection alarm's analytics rule after an alert (azSentinelSuppression) in
    seconds; None when it isn't suppressed."""
    return duration_seconds(one(alarm, "azSentinelSuppression"))


def _choice_why(s):
    """Why detection spec s's Sentinel choices (azSentinelRule) can't be rendered, or None: an NRT rule of a count
    detection, a suppression outside Sentinel's range or not in whole minutes, alert details naming result columns
    of a count detection or columns a rows detection's search doesn't return."""
    rows = detection_mode(s.alarm) == "rows"
    if rule_kind(s.alarm) == "nrt" and not rows:
        return ("it asks for a near-real-time analytics rule (azSentinelRuleKind nrt), which runs every minute over "
                "what arrived since its last run, with no lookback: a count detection's windows over its evaluation "
                "period can't be counted there (make it a rows detection, its threshold in its search)")
    seconds = suppression_seconds(s.alarm)
    if one(s.alarm, "azSentinelSuppression") and not (
            seconds and MIN_SUPPRESSION <= seconds <= MAX_SUPPRESSION and seconds % 60 == 0):
        return (f"its suppression ({one(s.alarm, 'azSentinelSuppression')}) isn't one Sentinel takes (5 minutes to "
                "24 hours, in whole minutes)")
    named = override_columns(s.alarm)
    if named and not rows:
        return (f"its alert details name result columns ({', '.join(named)}), and a count detection's results are "
                "only its count of breaching windows (make it a rows detection)")
    columns = result_columns(one(s.alarm, "ciamMetric"))
    missing = tuple(c for c in named if columns is not None and c not in columns)
    return (f"its alert details name result columns its search doesn't return ({', '.join(missing)}; it returns "
            f"{', '.join(columns)})") if missing else None


def _why(s):
    if s.why:
        return s.why
    if _choice_why(s):
        return _choice_why(s)
    if detection_mode(s.alarm) == "rows":
        crowded = sorted({e for e, _, _ in entity_mappings(s.alarm)
                          if sum(1 for x, _, _ in entity_mappings(s.alarm) if x == e) > MAX_IDENTIFIERS})
        unknown = [f"{e} {i}" for e, i, _ in entity_mappings(s.alarm) if (e, i) not in IDENTIFIERS]
        return (f"it maps {', '.join(crowded)} by more than {MAX_IDENTIFIERS} identifiers (Sentinel's limit)"
                if crowded else f"Sentinel has no identifier for {', '.join(unknown)}" if unknown else
                f"its evaluation period ({_period(s)}s) is shorter than Sentinel runs a scheduled rule (every 5 "
                "minutes at the most often)" if _period(s) < MIN_PERIOD and rule_kind(s.alarm) == "scheduled"
                else None)
    c, why = detection_condition(s.rule)
    if why:
        return why
    period = c.window * c.windows
    return (f"its evaluation period ({period}s) is shorter than Sentinel runs a scheduled rule (every 5 minutes at the "
            "most often)") if period < MIN_PERIOD else None


def _rule_id(s):
    ref_ = one(s.alarm, "ciamProviderRef") or ""
    return ref_.rsplit("/alertRules/", 1)[-1] if "/alertRules/" in ref_ else ref_


def _workspace_of(m, b):
    """What a rule names its workspace by: the workspace as this render names it (the rule then waits for its
    onboarding), else its recorded ID. Never through the onboarding: an ARM render scopes the rule by the resource it
    names, and the rule is the workspace's extension, not the onboarding's."""
    return workspace_id(m, b) if keeper_of(m, b) is None else one(b, "ciamProviderRef")


def _after(m, b):
    return ((("depends_on", [ref(f"{ONBOARDING}.{tf_name(rdn_value(b))}")]),) if keeper_of(m, b) is None else ())


def _entity_blocks(alarm):
    """entity_mapping blocks of a rows detection: one per entity type, its identifiers in the record's order."""
    return entity_blocks(entity_mappings(alarm))


def entity_blocks(found):
    """entity_mapping blocks of entity mappings found ((entity, identifier, result column), ...): one per entity type,
    its identifiers in order."""
    return tuple(("entity_mapping", Block((("entity_type", ENTITY_TYPES[e]), *(
        ("field_mapping", Block((("identifier", IDENTIFIERS[(e, i)]), ("column_name", col))))
        for x, i, col in found if x == e)))) for e in dict.fromkeys(x for x, _, _ in found))


def _attack(rule):
    tactics = list(dict.fromkeys(sentinel_tactic(t) for t in values(rule, "ciamAttackTactic")))
    techniques = list(parent_techniques(rule))
    return (*((("tactics", tactics),) if tactics else ()), *((("techniques", techniques),) if techniques else ()))


def _suppression(alarm):
    """A rule's suppression attributes: on, for its azSentinelSuppression, when it has one; none (azurerm's default,
    off) otherwise."""
    seconds = suppression_seconds(alarm)
    return (("suppression_enabled", True), ("suppression_duration", iso_duration(seconds))) if seconds else ()


def _override(alarm):
    """A rule's alert_details_override block, from its azSentinelRule choices: none when it has none."""
    fields = tuple((k, one(alarm, a)) for k, a in OVERRIDES if one(alarm, a))
    props = tuple(("dynamic_property", Block((("name", p), ("value", c)))) for p, c in alert_properties(alarm))
    return (("alert_details_override", Block((*fields, *props))),) if fields or props else ()


def _rule(m, s):
    rule = rdn_value(s.rule)
    rows = detection_mode(s.alarm) == "rows"
    if rows:
        period = iso_duration(_period(s))
        query = one(s.alarm, "ciamMetric")
    else:
        c, _ = detection_condition(s.rule)
        period = iso_duration(c.window * c.windows)
        query = detection_query(one(s.alarm, "ciamMetric"), s.rule, c)
    nrt = rule_kind(s.alarm) == "nrt"            # every minute, over what arrived since: no schedule, no trigger
    timing = () if nrt else (("query_frequency", period), ("query_period", period),
                             ("trigger_operator", "GreaterThan"), ("trigger_threshold", 0))
    return tf_block("resource", [NRT if nrt else RULE, tf_name(rdn_value(s.alarm))], [
        ("name", _rule_id(s)), ("log_analytics_workspace_id", _workspace_of(m, detection_index(m, s.alarm))),
        ("display_name", rule), ("description", described(rule)),
        ("severity", SEVERITIES.get(one(s.rule, "ciamSeverity") or "", "Medium")),
        ("query", query), *timing, ("enabled", True), *_suppression(s.alarm), *_attack(s.rule),
        *((("event_grouping", Block((("aggregation_method", "AlertPerResult"),))), *_entity_blocks(s.alarm))
          if rows else ()),
        *((("custom_details", {c: c for c in _details(s.alarm)[0]}),) if _details(s.alarm)[0] else ()),
        *_override(s.alarm), *_incident(s), *_after(m, detection_index(m, s.alarm))])


def render_sentinel(m, services=None):
    """HCL (and comments) for environment m's Sentinel: each Sentinel workspace it renders onboarded, each detection
    on one as a scheduled analytics rule, and with services (contract.Services) each adopting rule as one written from
    its declaration (adopted_rule); the notes of the detections not rendered as comments."""
    onboard = tuple(from_entry(b.dn, (tf_block("resource", [ONBOARDING, tf_name(rdn_value(b))], [
        ("workspace_id", workspace_id(m, b))]),))
        for b in siem_destinations(m) if is_sentinel(b) and keeper_of(m, b) is None)
    rules = tuple(from_entry(s.alarm.dn, (_rule(m, s),)) for s in sentinel_detections(m) if _why(s) is None)
    adopted = tuple(from_entry(x.rule.dn, (adopted_rule(m, x, b, tables),))
                    for x, b, tables in (sentinel_rules(m, services) if services else ())
                    if not _adopted_why(x, tables))
    return (*(x for xs in onboard for x in xs), *(x for xs in rules for x in xs), *(x for xs in adopted for x in xs),
            *(comment(note_comment(n)) for n in sentinel_notes(m, services)))


def sentinel_notes(m, services=None):
    """The render notes of environment m's Sentinel: detections not rendered (a note when no search is recorded, else
    a blocker), sub-techniques and ATT&CK v20 tactics rendered as what Sentinel names (notes), a rows detection's
    custom details not rendered and its incident grouping shorter than its period (notes), the total retention of
    tables opsdir doesn't render (a note), in Azure Government what Microsoft doesn't state is available there (an
    action), and with services the adopting rules' (adopted_notes)."""
    kept = tuple(b for b in siem_destinations(m) if is_sentinel(b) and keeper_of(m, b) is None)
    gov = unstated_note(m, "the Log Analytics Tables API's total retention and Microsoft Sentinel's data lake tiers",
                        "are") if kept else None
    subs = [(s, [t for t in values(s.rule, "ciamAttackTechnique") if "." in t]) for s in sentinel_detections(m)
            if _why(s) is None]
    v18 = [(s, [t for t in values(s.rule, "ciamAttackTactic") if t in V18_TACTICS]) for s in sentinel_detections(m)
           if _why(s) is None]
    rows = tuple(s for s in sentinel_detections(m) if _why(s) is None and detection_mode(s.alarm) == "rows")
    return (*(alarm_note(m, s) if s.why else alarm_note(m, s, _why(s))
              for s in sentinel_detections(m) if _why(s) is not None),
            *(_subtechnique_note(m, s.rule, ts, s.alarm.dn) for s, ts in subs if ts),
            *(note("Monitoring", "note", f"alert rule {rdn_value(s.rule)}",
                   "its search's result columns aren't rendered as custom details: it names them in no last project, "
                   "distinct or summarize stage opsdir reads",
                   ("End the search with a project naming its columns, or add the custom details analysts need in "
                    "Sentinel",), s.alarm.dn, m.label)
              for s in rows if result_columns(one(s.alarm, "ciamMetric")) is None),
            *(note("Monitoring", "note", f"alert rule {rdn_value(s.rule)}",
                   f"its result columns {', '.join(_details(s.alarm)[1])} aren't custom details: Sentinel takes "
                   f"{MAX_CUSTOM_DETAILS} per rule, each key {MAX_KEY} characters at most",
                   ("Rename a long column in the search (project Short = LongColumnName), or choose the custom details "
                    "in Sentinel",), s.alarm.dn, m.label) for s in rows if _details(s.alarm)[1]),
            *(note("Monitoring", "note", f"alert rule {rdn_value(s.rule)}",
                   f"its incidents group the alerts of 7 days, not of its whole evaluation period ({_period(s)}s): "
                   "Sentinel groups alerts over 7 days at the longest",
                   ("Keep the rule's evaluation period to 7 days if one incident must hold a whole period's alerts",),
                   s.alarm.dn, m.label)
              for s in rows if _period(s) > MAX_LOOKBACK),
            *(_v18_note(m, s.rule, ts, s.alarm.dn) for s, ts in v18 if ts),
            *(note("Logs", "note", f"log destination {rdn_value(b)}", f"keeps logs {one(b, 'ciamTotalRetentionDays')} "
                   "days in all on the tables opsdir renders for its routes (their Ciam<route>_CL tables, and "
                   "ContainerLogV2 for containers' logs); its other tables (Sentinel's own) keep the workspace's "
                   "retention unless set by hand",
                   ("Set the total retention of the workspace's other tables that must keep logs as long, by hand",),
                   b.dn, m.label)
              for b in kept if one(b, "ciamTotalRetentionDays") is not None),
            *((gov,) if gov is not None else ()), *(adopted_notes(m, services) if services else ()))


def nrt_rules(m):
    """((Sentinel workspace, (detection spec, ...)), ...): the near-real-time analytics rules environment m's render
    puts in each workspace (enabled, all of them), in the order the workspaces first appear."""
    found = tuple((detection_index(m, s.alarm), s) for s in sentinel_detections(m)
                  if _why(s) is None and rule_kind(s.alarm) == "nrt")
    workspaces = {b.dn: b for b, _ in found}
    return tuple((b, tuple(s for w, s in found if w.dn == dn)) for dn, b in workspaces.items())


def check_nrt_quota(ctx):
    """The near-real-time rules the target's render puts in each Sentinel workspace against Sentinel's limits: a
    blocker where they are more than the workspace takes (MAX_NRT_ENABLED enabled, MAX_NRT_TOTAL in all: service
    limits; opsdir's rules are all enabled); an action where the workspaces fit but hold more than MAX_NRT_ENABLED
    together (the NRT overview's 50 per customer); an OK line otherwise. Rules made outside opsdir count too: the
    lines say so."""
    m = ctx.dst
    found = nrt_rules(m)
    if not found:
        return findings()
    owner = responsible(ctx.d, m.env)
    # every rule opsdir renders is enabled: the enabled limit binds before the total one
    over = tuple((b, rules) for b, rules in found if len(rules) > MAX_NRT_ENABLED)
    total = sum(len(rules) for _, rules in found)
    blockers = tuple((NRT_AREA, f"{m.label}'s render puts {len(rules)} near-real-time analytics rules in Sentinel "
                                f"workspace {rdn_value(b)}: Sentinel takes {MAX_NRT_ENABLED} enabled NRT rules per "
                                f"workspace ({MAX_NRT_TOTAL} in all, disabled ones included: its service limits). Run "
                                "the others as scheduled rules (azSentinelRuleKind scheduled) or spread them over "
                                "workspaces.", owner) for b, rules in over)
    actions = () if over or total <= MAX_NRT_ENABLED else (
        (NRT_AREA, f"{m.label}'s render puts {total} near-real-time analytics rules in its Sentinel workspaces "
                   f"together ({', '.join(f'{rdn_value(b)} {len(rules)}' for b, rules in found)}): Sentinel's "
                   f"service limits allow {MAX_NRT_ENABLED} enabled per workspace, but its NRT overview says "
                   f"{MAX_NRT_ENABLED} NRT rules per customer. Confirm the limit with Microsoft before applying.",
         owner, ctx.cutover),)
    ok = () if over or actions else tuple(
        f"{m.label}'s Sentinel workspace {rdn_value(b)} gets {len(rules)} near-real-time analytics rules, within "
        f"Sentinel's {MAX_NRT_ENABLED} enabled per workspace (rules made outside opsdir count too)."
        for b, rules in found)
    return findings(blockers=blockers, actions=actions, ok=ok)


def _subtechnique_note(m, rule, found, dn):
    return note("Monitoring", "note", f"alert rule {rdn_value(rule)}",
                f"its sub-techniques {', '.join(found)} are rendered as their parent techniques: azurerm has no "
                "sub-technique field, nor has the alertRules API's stable version (2025-09-01; only its previews)",
                ("Add the sub-techniques to the analytics rule in Sentinel if needed",), dn, m.label)


def _v18_note(m, rule, found, dn):
    return note("Monitoring", "note", f"alert rule {rdn_value(rule)}",
                f"its ATT&CK tactics {', '.join(found)} are rendered as DefenseEvasion: Sentinel follows ATT&CK v18, "
                "where they were Defense Evasion, and its alertRules API names no Stealth or Defense Impairment "
                "tactic", ("Map the rule to Stealth or Defense Impairment in Sentinel once it offers them",), dn,
                m.label)


def _attack_notes(m, rule):
    """The notes of an alert rule's ATT&CK as Sentinel names it: sub-techniques as their parents, ATT&CK v20 tactics
    as the v18 tactic they were split from."""
    subs = tuple(t for t in values(rule, "ciamAttackTechnique") if "." in t)
    v18 = tuple(t for t in values(rule, "ciamAttackTactic") if t in V18_TACTICS)
    return (*((_subtechnique_note(m, rule, subs, rule.dn),) if subs else ()),
            *((_v18_note(m, rule, v18, rule.dn),) if v18 else ()))


def kql_path(path):
    """A product field's path (dots separating nested keys) as the KQL reading it, as a string, from the event parsed
    from a log line (parse_json(RawData), as EVENT)."""
    return f"tostring({EVENT}" + "".join(f"[{literal(k)}]" for k in path.split(".")) + ")"


def list_prefix(path):
    """The key path of the list a product field sits in (what comes before LIST: 'entries' of
    'entries[].info.nodeId'), or None outside a list."""
    return path.split(LIST, 1)[0] if LIST in path else None


def _item(prefixes, prefix):
    return f"item{prefixes.index(prefix)}"


def kql_field(path, prefixes=()):
    """A product field's path as the KQL reading it, as a string: from the event (kql_path), or for a field inside a
    list from the list's element mv-expand gives (mv_expansions over prefixes), so fields of one list are read from the
    same element."""
    prefix = list_prefix(path)
    if prefix is None:
        return kql_path(path)
    rest = path.split(LIST, 1)[1].strip(".")
    return f"tostring({_item(prefixes, prefix)}" + "".join(f"[{literal(k)}]" for k in rest.split(".") if k) + ")"


def mv_expansions(prefixes):
    """The KQL expanding each list (by its key path) into one row per element, before the fields are read."""
    return "".join(f" | mv-expand {_item(prefixes, x)} = {EVENT}" + "".join(f"[{literal(k)}]" for k in x.split("."))
                   for x in prefixes)


def _paths(det, mapping):
    used = (*(f for f, _ in det.selector), *((*det.group_by, *((det.distinct,) if det.distinct else ()))
                                              if det.threshold is not None else ()))
    return tuple(dict.fromkeys(product_field(mapping, f) for f in used))


def column(field):
    """The result column a canonical field is counted by (source-ip -> source_ip)."""
    return field.replace("-", "_")


def _match(mapping, field, canonical, prefixes=()):
    found = tuple(dict.fromkeys(v for c in canonical for v in product_values(mapping, field, c)))
    path = kql_field(product_field(mapping, field), prefixes)
    return f"{path} == {literal(found[0])}" if len(found) == 1 else f"{path} in ({', '.join(map(literal, found))})"


def adopted_query(det, mapping, tables):
    """The KQL of a declaration as an alert rule has it (det) in the product's fields and values (mapping), over the
    custom tables its routes fill: its matching events, the fields it counts by as columns named after the canonical
    fields, counted per group (or their distinct values of its distinct field, dcount) and kept where they reach its
    threshold; the events themselves when it has none. A field inside a list is read from each element of its list
    (mv_expansions), one row per element."""
    prefixes = tuple(dict.fromkeys(x for x in map(list_prefix, _paths(det, mapping)) if x))
    head = (f"{tables[0] if len(tables) == 1 else 'union ' + ', '.join(tables)} | extend {EVENT} = "
            f"parse_json(RawData){mv_expansions(prefixes)} | where "
            + " and ".join(_match(mapping, f, vals, prefixes) for f, vals in det.selector))
    if det.threshold is None:
        return head
    counted = tuple(dict.fromkeys((*det.group_by, *((det.distinct,) if det.distinct else ()))))
    read = ", ".join(f"{column(f)} = {kql_field(product_field(mapping, f), prefixes)}" for f in counted)
    named = (f" | extend {read} "
             f"| where {' and '.join(f'isnotempty({column(f)})' for f in counted)}") if counted else ""
    by = f" by {', '.join(map(column, det.group_by))}" if det.group_by else ""
    total, value = (("value_count", f"dcount({column(det.distinct)})") if det.distinct else ("events", "count()"))
    return f"{head}{named} | summarize {total} = {value}{by} | where {total} >= {det.threshold}"


def adopted_timing(det):
    """((query frequency, query period) in seconds, None) of a declaration's scheduled rule (det: as the rule has it),
    or (None, why its window can't be kept)."""
    if det.threshold is None:
        return (MIN_PERIOD, MIN_PERIOD), None
    window = det.window_seconds
    if not MIN_PERIOD <= window <= MAX_PERIOD:
        return None, (f"its window ({window}s) isn't one a scheduled rule looks back over (5 minutes to 14 days)")
    if det.window_kind == "fixed":
        return (window, window), None
    step = overlap_step(window, MIN_PERIOD)
    if det.window_kind != "sliding" or step is None:
        return None, (f"its window kind {det.window_kind!r} isn't sliding or fixed" if det.window_kind != "sliding"
                      else f"its sliding window ({window}s) is too short to search again within it (a scheduled "
                           "rule runs every 5 minutes at the most often)")
    return (step, window), None


def _adopted_why(x, tables):
    nested = tuple(p for p in _paths(x.det, x.mapping) if p and p.count(LIST) > 1)
    if not x.why and nested:
        return f"the product's fields {', '.join(nested)} sit in a list within a list, which this render doesn't read"
    return x.why or (None if tables else (
        f"no table of the workspace holds role {x.det.server_role}'s log files (the Ciam<route>_CL tables of its "
        "routes); container output (ContainerLogV2) isn't searched")) or adopted_timing(x.det)[1]


def sentinel_rules(m, services):
    """((NativeRule, Sentinel workspace, its tables holding the rule's server role's log files), ...) of environment
    m's adopting rules whose role's logs reach a Sentinel workspace it renders (the rest are another SIEM's, or
    none's)."""
    files = host_shipments(m, services)
    return tuple((x, b, tuple(dict.fromkeys(table_name(s.route) for s in files
                                            if s.role == x.det.server_role and s.destination.dn == b.dn)))
                 for x in native_rules(m, services.detections(m), lists=True) for b in searched(m, x.det, keeps))


def _entities(det):
    """The entity mappings of a declaration's results: each group-by field an entity (detections.ENTITIES) by its
    column, an entity and identifier once."""
    found = tuple((ENTITIES[f], (*ENTITIES[f], column(f))) for f in det.group_by if f in ENTITIES)
    return tuple(v for i, (k, v) in enumerate(found) if k not in tuple(p for p, _ in found[:i]))


def adopted_rule(m, x, b, tables):
    """The scheduled analytics rule of adopting rule x (a NativeRule) in Sentinel workspace b over its tables: an
    alert per result, its group-by fields mapped as entities its incidents group by within its window."""
    rule = rdn_value(x.rule)
    (every, period), _ = adopted_timing(x.det)
    mapped = _entities(x.det)
    types = tuple(ENTITY_TYPES[e] for e in dict.fromkeys(e for e, _, _ in mapped))
    return tf_block("resource", [RULE, tf_name(f"{native_name(rule)}_{rdn_value(b)}")], [
        ("name", native_name(rule)), ("log_analytics_workspace_id", _workspace_of(m, b)), ("display_name", rule),
        ("description", described(rule)), ("severity", SEVERITIES.get(x.det.severity or "", "Medium")),
        ("query", adopted_query(x.det, x.mapping, tables)), ("query_frequency", iso_duration(every)),
        ("query_period", iso_duration(period)), ("trigger_operator", "GreaterThan"), ("trigger_threshold", 0),
        ("enabled", True), *_attack(x.rule), ("event_grouping", Block((("aggregation_method", "AlertPerResult"),))),
        *entity_blocks(mapped), *_grouping((min(period, MAX_LOOKBACK), "Selected" if types else "AnyAlert", types)),
        *_after(m, b)])


def adopted_notes(m, services):
    """The render notes of environment m's adopting rules in Sentinel: those not rendered (blockers), those rendered
    from a declaration documented only, their ATT&CK as Sentinel names it, and a fixed window searched back to back
    from when the rule is enabled (notes)."""
    found = sentinel_rules(m, services)
    done = tuple({x.rule.dn: x for x, _, tables in found if not _adopted_why(x, tables)}.values())
    refused = tuple({x.rule.dn: (x, _adopted_why(x, tables)) for x, _, tables in found
                     if _adopted_why(x, tables)}.values())
    return (*native_notes(m, done, refused, "Sentinel"), *(n for x in done for n in _attack_notes(m, x.rule)),
            *(note("Monitoring", "note", f"alert rule {rdn_value(x.rule)}", f"its fixed window "
                   f"({x.det.window_seconds}s) is searched back to back from when its analytics rule is enabled (and "
                   "Sentinel runs a scheduled rule five minutes after its time), not from the clock's boundaries", (),
                   x.rule.dn, m.label)
              for x in done if x.det.threshold is not None and x.det.window_kind == "fixed"))


def onboarded(found):
    """The workspace IDs (lowercased) a source's Sentinel onboardings name."""
    return frozenset((a.get("workspace_id") or "").lower() for a in of_types(found, ONBOARDING)
                     if a.get("workspace_id"))


def rule_choices(type_, a):
    """The azSentinelRule choices an analytics rule of Terraform type type_ holds, in azurerm's shape (state, or the
    CLI and ARM readers'): {attribute: values} of those it sets: nrt for an NRT rule, its alert details override, its
    suppression when on (as the record writes a duration)."""
    over = (a.get("alert_details_override") or [{}])[0] or {}
    seconds = iso_seconds(a.get("suppression_duration")) if a.get("suppression_enabled") else None
    found = {"azSentinelRuleKind": ("nrt",) if type_ == NRT else (),
             **{attr: (over.get(k),) for k, attr in OVERRIDES},
             "azSentinelAlertProperty": tuple(f"{p.get('name')}={p.get('value')}"
                                              for p in over.get("dynamic_property") or ()
                                              if p.get("name") and p.get("value")),
             "azSentinelSuppression": (duration_text(seconds),)}
    return {k: v for k, v in found.items() if any(v)}


def sentinel_rules_read(found):
    """((Terraform type, attributes), ...) of a source's scheduled and NRT analytics rules opsdir reads (those with an
    ID, not an adopting rule's opsdir-<rule>)."""
    return tuple((t, a) for t, a in found if t in RULES and a.get("id")
                 and not is_native(a.get("name"), a.get("description")))


def sentinel_resources(found):
    """Scheduled and NRT analytics rules as detections (kind alarm): the rule each realizes (its description), its
    query without the render's condition, the workspace it runs in as the log destination it searches, and its
    choices (rule_choices)."""
    def detection(t, a):
        rule = realized_in(a.get("description"))
        role, realizes = realization_roles({"Realizes": rule} if rule else {}, "alarm")
        mapped = tuple(f"{CORE_ENTITY[e.get('entity_type')]} {CORE_IDENTIFIER[key]}={f.get('column_name')}"
                       for e in a.get("entity_mapping") or [] if e.get("entity_type") in CORE_ENTITY
                       for f in e.get("field_mapping") or []
                       for key in ((CORE_ENTITY[e.get("entity_type")], f.get("identifier")),) if key in CORE_IDENTIFIER)
        rows = bool(a.get("query")) and not _WRAPPED.match(a.get("query") or "")
        return resource("alarm", a.get("id"), {"ciamRealizes": realizes,
                                               "ciamMetric": base_query(a.get("query")) or None,
                                               "ciamDetectionMode": "rows" if rows else None,
                                               "ciamEntityMapping": mapped or None, **rule_choices(t, a)},
                        {"ciamLogDestinationRole": a.get("log_analytics_workspace_id")}, name=a.get("name"),
                        role=role)
    return tuple(detection(t, a) for t, a in sentinel_rules_read(found))


def _with_choices(e, held):
    """Entry e (a detection an import placed) with its choices exactly those held (rule_choices), none it doesn't hold,
    and the auxiliary class azSentinelRule when it holds one."""
    attrs = {**{k: v for k, v in e.attrs.items() if k not in CHOICES}, **held}
    classes = (*e.classes, SENTINEL_RULE) if held and SENTINEL_RULE not in e.classes else e.classes
    return make_entry(e.dn, classes, attrs)


def with_sentinel_choices(imported, files, suffixes, read_pairs):
    """An import (core Imported) with each analytics rule's detection holding exactly the choices its source holds
    (rule_choices: a choice the source no longer sets is dropped, so a change made in the portal is drift; the
    auxiliary class added where one is held): the rules read_pairs({path within the folder: text}) gives of each
    <cloud>/<env>/ folder's files ending in one of suffixes, matched to the detections by ID (case aside)."""
    specs = sorted({"/".join(p.split("/")[:2]) for p in files if p.count("/") >= 2})
    held = {(a.get("id") or "").lower(): rule_choices(t, a) for s in specs
            for t, a in sentinel_rules_read(read_pairs({p[len(s) + 1:]: text for p, text in files.items()
                                                        if p.startswith(f"{s}/") and p.endswith(suffixes)}))}
    if not held:
        return imported

    def chosen(e):
        key = (one(e, "ciamProviderRef") or "").lower()
        return _with_choices(e, held[key]) if key in held else e
    return imported._replace(groups=tuple((dn, (chosen(es[0]), *es[1:])) if es else (dn, es)
                                          for dn, es in imported.groups))

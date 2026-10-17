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
techniques (a sub-technique, T1078.004, is rendered as T1078 with a note: azurerm has no sub-technique field). A rows
detection (ciamDetectionMode rows, milestone 109, decision 3299) runs its search as written, one alert per result row
(event_grouping AlertPerResult), as often as the rule's evaluation period (5 minutes at least), with its entity
mappings (core ciamEntityMapping: account, ip, host, url, application as Sentinel's Account, IP, Host, URL,
CloudApplication; at most three identifiers each, Sentinel's limit).

Read back (sentinel_resources, with the inventory): a workspace is a SIEM index when the source holds its Sentinel
onboarding; a scheduled analytics rule is a detection realizing the rule its description names (role alarm-<rule>),
searching the workspace it runs in, holding its query without the condition the render wrapped around it.
"""
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.inventory import duration_seconds, of_types, realization_roles, resource
from opsdir.core.notes import note, note_comment
from opsdir.domains.observability.alarms import alarm_note, detection_condition, detection_specs
from opsdir.domains.observability.realized import keeper_of
from opsdir.domains.observability.siem import (described, detection_index, detection_mode, entity_mappings, is_siem,
                                               realized_in, siem_destinations)
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import unstated_note
from .observability import iso_duration, workspace_id, workspace_name

ONBOARDING = "azurerm_sentinel_log_analytics_workspace_onboarding"
RULE = "azurerm_sentinel_alert_rule_scheduled"
MIN_PERIOD = 300                        # Sentinel runs a scheduled rule every 5 minutes at the most often
SEARCH_LANGUAGE = "kusto"               # ciamSearchLanguage of a detection's KQL (its native language)
SEVERITIES = {"sev0": "High", "sev1": "High", "sev2": "Medium", "sev3": "Low", "sev4": "Informational"}
OPERATORS = {"gt": ">", "ge": ">="}
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


def sentinel_tactic(tactic):
    """Sentinel's name of an ATT&CK tactic short name: credential-access -> CredentialAccess."""
    return "".join(part.capitalize() for part in tactic.split("-"))


def parent_techniques(rule):
    """The rule's ATT&CK techniques as parent technique IDs (T1078.004 -> T1078), each once, in the record's order."""
    return tuple(dict.fromkeys(t.split(".", 1)[0] for t in values(rule, "ciamAttackTechnique")))


def _period(s):
    """A rows detection's evaluation period in seconds (the rule's ciamEvaluationPeriod; 5 minutes when none)."""
    return duration_seconds(one(s.rule, "ciamEvaluationPeriod")) or MIN_PERIOD


def _why(s):
    if s.why:
        return s.why
    if detection_mode(s.alarm) == "rows":
        crowded = sorted({e for e, _, _ in entity_mappings(s.alarm)
                          if sum(1 for x, _, _ in entity_mappings(s.alarm) if x == e) > MAX_IDENTIFIERS})
        unknown = [f"{e} {i}" for e, i, _ in entity_mappings(s.alarm) if (e, i) not in IDENTIFIERS]
        return (f"it maps {', '.join(crowded)} by more than {MAX_IDENTIFIERS} identifiers (Sentinel's limit)"
                if crowded else f"Sentinel has no identifier for {', '.join(unknown)}" if unknown else
                f"its evaluation period ({_period(s)}s) is shorter than Sentinel runs a scheduled rule (every 5 "
                "minutes at the most often)" if _period(s) < MIN_PERIOD else None)
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
    found = entity_mappings(alarm)
    return tuple(("entity_mapping", Block((("entity_type", ENTITY_TYPES[e]), *(
        ("field_mapping", Block((("identifier", IDENTIFIERS[(e, i)]), ("column_name", col))))
        for x, i, col in found if x == e)))) for e in dict.fromkeys(x for x, _, _ in found))


def _attack(rule):
    tactics = [sentinel_tactic(t) for t in values(rule, "ciamAttackTactic")]
    techniques = list(parent_techniques(rule))
    return (*((("tactics", tactics),) if tactics else ()), *((("techniques", techniques),) if techniques else ()))


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
    return tf_block("resource", [RULE, tf_name(rdn_value(s.alarm))], [
        ("name", _rule_id(s)), ("log_analytics_workspace_id", _workspace_of(m, detection_index(m, s.alarm))),
        ("display_name", rule), ("description", described(rule)),
        ("severity", SEVERITIES.get(one(s.rule, "ciamSeverity") or "", "Medium")),
        ("query", query), ("query_frequency", period), ("query_period", period),
        ("trigger_operator", "GreaterThan"), ("trigger_threshold", 0), ("enabled", True), *_attack(s.rule),
        *((("event_grouping", Block((("aggregation_method", "AlertPerResult"),))), *_entity_blocks(s.alarm))
          if rows else ()),
        *_after(m, detection_index(m, s.alarm))])


def render_sentinel(m):
    """HCL (and comments) for environment m's Sentinel: each Sentinel workspace it renders onboarded, each detection
    on one as a scheduled analytics rule; the notes of the detections not rendered as comments."""
    onboard = tuple(from_entry(b.dn, (tf_block("resource", [ONBOARDING, tf_name(rdn_value(b))], [
        ("workspace_id", workspace_id(m, b))]),))
        for b in siem_destinations(m) if is_sentinel(b) and keeper_of(m, b) is None)
    rules = tuple(from_entry(s.alarm.dn, (_rule(m, s),)) for s in sentinel_detections(m) if _why(s) is None)
    return (*(x for xs in onboard for x in xs), *(x for xs in rules for x in xs),
            *(comment(note_comment(n)) for n in sentinel_notes(m)))


def sentinel_notes(m):
    """The render notes of environment m's Sentinel: detections not rendered (a note when no search is recorded, else
    a blocker), the total retention of tables opsdir doesn't render (a note), and in Azure Government what Microsoft
    doesn't state is available there (an action)."""
    kept = tuple(b for b in siem_destinations(m) if is_sentinel(b) and keeper_of(m, b) is None)
    gov = unstated_note(m, "the Log Analytics Tables API's total retention and Microsoft Sentinel's data lake tiers",
                        "are") if kept else None
    subs = [(s, [t for t in values(s.rule, "ciamAttackTechnique") if "." in t]) for s in sentinel_detections(m)
            if _why(s) is None]
    return (*(alarm_note(m, s) if s.why else alarm_note(m, s, _why(s))
              for s in sentinel_detections(m) if _why(s) is not None),
            *(note("Monitoring", "note", f"alert rule {rdn_value(s.rule)}",
                   f"its sub-techniques {', '.join(ts)} are rendered as their parent techniques: azurerm has no "
                   "sub-technique field", ("Add the sub-techniques to the analytics rule in Sentinel if needed",),
                   s.alarm.dn, m.label) for s, ts in subs if ts),
            *(note("Logs", "note", f"log destination {rdn_value(b)}", f"keeps logs {one(b, 'ciamTotalRetentionDays')} "
                   "days in all on the tables opsdir renders for its routes (their Ciam<route>_CL tables, and "
                   "ContainerLogV2 for containers' logs); its other tables (Sentinel's own) keep the workspace's "
                   "retention unless set by hand",
                   ("Set the total retention of the workspace's other tables that must keep logs as long, by hand",),
                   b.dn, m.label)
              for b in kept if one(b, "ciamTotalRetentionDays") is not None),
            *((gov,) if gov is not None else ()))


def onboarded(found):
    """The workspace IDs (lowercased) a source's Sentinel onboardings name."""
    return frozenset((a.get("workspace_id") or "").lower() for a in of_types(found, ONBOARDING)
                     if a.get("workspace_id"))


def sentinel_resources(found):
    """Scheduled analytics rules as detections (kind alarm): the rule each realizes (its description), its query
    without the render's condition, the workspace it runs in as the log destination it searches."""
    def detection(a):
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
                                               "ciamEntityMapping": mapped or None},
                        {"ciamLogDestinationRole": a.get("log_analytics_workspace_id")}, name=a.get("name"),
                        role=role)
    return tuple(detection(a) for a in of_types(found, RULE) if a.get("id"))

"""What the Azure CLI reports about monitoring and suppressions (and an ARM template's, read the same way), item by item
from the ARM type, normalized to the hashicorp/azurerm (and azapi) attribute names the shared mapping reads
(opsdir_adapter_azure.inventory: alarms, alert channels, log destinations, canaries; suppressions; security's
incident routes). Pure.

  az monitor metrics alert list                 Microsoft.Insights/metricAlerts
  az monitor scheduled-query list               Microsoft.Insights/scheduledQueryRules
  az monitor action-group list                  Microsoft.Insights/actionGroups
  az monitor log-analytics workspace list       Microsoft.OperationalInsights/workspaces
  az monitor app-insights web-test list         Microsoft.Insights/webtests (standard tests)
  az containerapp job list                      Microsoft.App/jobs (the scripted checks' jobs: their schedule)
  az policy exemption list                      Microsoft.Authorization/policyExemptions
  az security alerts-suppression-rule list      Microsoft.Security/alertsSuppressionRules (as the azapi resource the
                                                render writes: azurerm has none)
  az rest .../Microsoft.SecurityInsights/onboardingStates, alertRules (per workspace, API 2025-09-01): Sentinel turned
                                                on for the workspace, and its scheduled analytics rules (other kinds
                                                aren't the render's)
Fields are read in any case: an ARM template says a web test's Frequency, the CLI its frequency.
"""
import json

from .arm_ids import arm_field
from .suppressions import ALERT_RULES

METRIC_ALERTS = "microsoft.insights/metricalerts"
QUERY_ALERTS = "microsoft.insights/scheduledqueryrules"
ACTION_GROUPS = "microsoft.insights/actiongroups"
WORKSPACES = "microsoft.operationalinsights/workspaces"
WEB_TESTS = "microsoft.insights/webtests"
JOBS = "microsoft.app/jobs"
EXEMPTIONS = "microsoft.authorization/policyexemptions"
SUPPRESSION_RULES = ALERT_RULES.lower()
ONBOARDING = "microsoft.securityinsights/onboardingstates"
ANALYTICS_RULES = "microsoft.securityinsights/alertrules"
READ = (METRIC_ALERTS, QUERY_ALERTS, ACTION_GROUPS, WORKSPACES, WEB_TESTS, JOBS, EXEMPTIONS, SUPPRESSION_RULES,
        ONBOARDING, ANALYTICS_RULES)
_SECURITY_INSIGHTS = "/providers/microsoft.securityinsights/"
_RULE_FIELDS = ("alertType", "state", "reason", "comment", "expirationDateUtc", "suppressionAlertsScope")


def _of(items, kind):
    return [i for k, i in items if k == kind]


def _metric_alert(a):
    criteria = (arm_field(a, "criteria") or {}).get("allOf") or []
    static = [c for c in criteria if (c.get("criterionType") or "StaticThresholdCriterion") ==
              "StaticThresholdCriterion"]
    dynamic = [c for c in criteria if c.get("criterionType") == "DynamicThresholdCriterion"]

    def one(c):
        return {"metric_namespace": c.get("metricNamespace"), "metric_name": c.get("metricName"),
                "aggregation": c.get("timeAggregation"), "operator": c.get("operator")}
    return {"id": a.get("id"), "name": a.get("name"), "tags": a.get("tags") or {},
            "description": arm_field(a, "description"), "severity": arm_field(a, "severity"),
            "scopes": list(arm_field(a, "scopes") or ()),
            "criteria": [{**one(c), "threshold": c.get("threshold")} for c in static],
            "dynamic_criteria": [one(c) for c in dynamic],
            "action": [{"action_group_id": x.get("actionGroupId")} for x in arm_field(a, "actions") or ()
                       if isinstance(x, dict)]}


def _query_alert(a):
    actions = arm_field(a, "actions") or {}
    return {"id": a.get("id"), "name": a.get("name"), "tags": a.get("tags") or {},
            "description": arm_field(a, "description"), "severity": arm_field(a, "severity"),
            "scopes": list(arm_field(a, "scopes") or ()),
            "criteria": [{"query": c.get("query"), "time_aggregation_method": c.get("timeAggregation"),
                          "operator": c.get("operator"), "threshold": c.get("threshold")}
                         for c in (arm_field(a, "criteria") or {}).get("allOf") or ()],
            "action": [{"action_groups": list(actions.get("actionGroups") or ())}] if isinstance(actions, dict)
            else []}


def _web_test(t):
    request = arm_field(t, "request") or {}
    return {"id": t.get("id"), "name": t.get("name"), "tags": t.get("tags") or {},
            "frequency": arm_field(t, "frequency"), "timeout": arm_field(t, "timeout"),
            "enabled": arm_field(t, "enabled"),
            "geo_locations": [arm_field(x, "id") for x in arm_field(t, "locations") or () if isinstance(x, dict)],
            "request": [{"url": arm_field(request, "requestUrl")}] if request else []}


def _exemption(e):
    metadata = arm_field(e, "metadata")
    return {"id": e.get("id"), "name": e.get("name"),
            "policy_assignment_id": arm_field(e, "policyAssignmentId"),
            "policy_definition_reference_ids": list(arm_field(e, "policyDefinitionReferenceIds") or ()),
            "exemption_category": arm_field(e, "exemptionCategory"), "expires_on": arm_field(e, "expiresOn"),
            "metadata": json.dumps(metadata) if isinstance(metadata, dict) else metadata}


def _suppression_rule(r):
    props = r.get("properties") if isinstance(r.get("properties"), dict) else r
    return {"id": r.get("id"), "name": r.get("name"), "type": ALERT_RULES,
            "body": {"properties": {k: props[k] for k in _RULE_FIELDS if props.get(k) is not None}}}


def _job(j):
    """A Container Apps job: its cron expression, its container's image and the registries it pulls from (the
    Terraform state's names), flattened by the collector's projection, nested as the CLI and an ARM template hold it
    (properties.configuration.scheduleTriggerConfig / .registries, properties.template.containers), or with its
    properties merged in, as the ARM reader gives a template's resource (configuration, template)."""
    props = arm_field(j, "properties") or {}
    config = arm_field(props, "configuration") or arm_field(j, "configuration") or {}
    trigger = arm_field(config, "scheduleTriggerConfig") or {}
    expression = arm_field(j, "cronExpression") or arm_field(trigger, "cronExpression")
    containers = arm_field(arm_field(props, "template") or arm_field(j, "template") or {}, "containers") or [{}]
    image = arm_field(j, "image") or arm_field(containers[0] or {}, "image")
    servers = arm_field(j, "registries") or [arm_field(r, "server") for r in arm_field(config, "registries") or []]
    return {"id": j.get("id"), "name": j.get("name"), "tags": j.get("tags") or {},
            "schedule_trigger_config": [{"cron_expression": expression}] if expression else [],
            "template": [{"container": [{"image": image}]}] if image else [],
            "registry": [{"server": s} for s in servers if s]}


def _workspace_of(item_id):
    """The workspace ID a Sentinel extension resource's ID is under (its part before the SecurityInsights provider)."""
    i = (item_id or "").lower().find(_SECURITY_INSIGHTS)
    return item_id[:i] if i > 0 else None


def _analytics_rule(r):
    """A scheduled analytics rule as az rest returns it (properties nested) or flattened."""
    props = arm_field(r, "properties") or {}
    field = lambda name: arm_field(props, name) if arm_field(props, name) is not None else arm_field(r, name)  # noqa: E731
    return {"id": r.get("id"), "name": r.get("name"), "description": field("description"),
            "display_name": field("displayName"), "query": field("query"),
            "log_analytics_workspace_id": _workspace_of(r.get("id")),
            "entity_mapping": [{"entity_type": arm_field(e, "entityType"),
                                "field_mapping": [{"identifier": arm_field(f, "identifier"),
                                                   "column_name": arm_field(f, "columnName")}
                                                  for f in arm_field(e, "fieldMappings") or []]}
                               for e in field("entityMappings") or []]}


def monitor_items(items):
    """(azurerm/azapi type, attributes) pairs of the monitoring and suppression items among (kind, item) pairs."""
    return [*(("azurerm_monitor_metric_alert", _metric_alert(a)) for a in _of(items, METRIC_ALERTS)),
            *(("azurerm_monitor_scheduled_query_rules_alert_v2", _query_alert(a)) for a in _of(items, QUERY_ALERTS)),
            *(("azurerm_monitor_action_group", {"id": g.get("id"), "name": g.get("name"), "tags": g.get("tags") or {}})
              for g in _of(items, ACTION_GROUPS)),
            *(("azurerm_log_analytics_workspace", {
                "id": w.get("id"), "name": w.get("name"), "tags": w.get("tags") or {},
                "retention_in_days": arm_field(w, "retentionInDays"), "sku": (arm_field(w, "sku") or {}).get("name")})
              for w in _of(items, WORKSPACES)),
            *(("azurerm_application_insights_standard_web_test", _web_test(t)) for t in _of(items, WEB_TESTS)
              if str(arm_field(t, "kind") or "standard").lower() == "standard"),
            *(("azurerm_container_app_job", _job(j)) for j in _of(items, JOBS)),
            *(("azurerm_subscription_policy_exemption", _exemption(e)) for e in _of(items, EXEMPTIONS)),
            *(("azapi_resource", _suppression_rule(r)) for r in _of(items, SUPPRESSION_RULES)),
            *(("azurerm_sentinel_log_analytics_workspace_onboarding", {"id": o.get("id"),
                                                                       "workspace_id": _workspace_of(o.get("id"))})
              for o in _of(items, ONBOARDING) if _workspace_of(o.get("id"))),
            *(("azurerm_sentinel_alert_rule_scheduled", _analytics_rule(r)) for r in _of(items, ANALYTICS_RULES)
              if str(r.get("kind") or "").lower() == "scheduled")]

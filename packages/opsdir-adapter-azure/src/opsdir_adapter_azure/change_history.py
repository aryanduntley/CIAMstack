"""Azure's resource change history kept longer than Resource Graph keeps it (milestone 5.7b, decision 2777 Q3). Pure.

Resource Graph keeps who changed what in a subscription's resources (its resourcechanges table) for 14 days ("Changes
are queryable for 14 days"); Microsoft's documented way to keep them longer is a scheduled Logic App querying Resource
Graph and writing the results to Log Analytics, through the Logs Ingestion API for new work (research 2792). For a
config-recording security service whose ciamRetentionDays is longer than that, with a Log Analytics workspace as its
ciamFindingsRole, this renders:

  azurerm_log_analytics_workspace_table_custom_log  CiamResourceChanges_CL: TimeGenerated, ChangeId, ChangeType,
                                                    TargetResourceId, TargetResourceType, Changes, ChangeAttributes,
                                                    kept ciamRetentionDays (interactive up to Log Analytics' 730 days,
                                                    the rest as long-term retention, up to 4383)
  azurerm_monitor_data_collection_endpoint          where the Logs Ingestion API is called
  azurerm_monitor_data_collection_rule              its stream Custom-ResourceChanges into the table
  azurerm_logic_app_workflow (+ recurrence trigger, every hour: Resource Graph's resourcechanges of the subscription
  and two custom HTTP actions)                      for the last hour (POST .../Microsoft.ResourceGraph/resources), the
                                                    rows posted to the rule's ingestion endpoint; both calls with its
                                                    system-assigned identity (Azure Government's endpoints there); no
                                                    azapi add-on needed
  azurerm_role_assignment                           Reader on the subscription (Resource Graph), Monitoring Metrics
                                                    Publisher on the rule (ingestion)

A run reads at most 1000 changes (Resource Graph's page): more in an hour need the query's skipToken paging (a comment).
Without a workspace to keep them in, not rendered: a blocker (history_note, flow 43), written as its comment.
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.estate.security import findings_destination
from opsdir.domains.observability.audit import INDEFINITE
from opsdir_format_terraform.hcl import Block, comment, jsonencoded, ref, tf_block, tf_name
from .account import government, tagged
from .identities import LOC, RG
from .observability import workspace_id

NATIVE_DAYS = 14                  # Resource Graph's own change history
INTERACTIVE_DAYS, TOTAL_DAYS = 730, 4383   # Log Analytics' longest interactive and total retention
# the total retentions Log Analytics takes beyond its interactive 730 days: whole years (azurerm 5.9's validation)
TOTAL_STEPS = (1095, 1460, 1826, 2191, 2556, 2922, 3288, 3653, 4018, 4383)
TABLE = "CiamResourceChanges_CL"
STREAM = "Custom-ResourceChanges"
TABLE_TYPE, ENDPOINT, RULE = ("azurerm_log_analytics_workspace_table_custom_log",
                              "azurerm_monitor_data_collection_endpoint", "azurerm_monitor_data_collection_rule")
WORKFLOW, TRIGGER, ACTION = ("azurerm_logic_app_workflow", "azurerm_logic_app_trigger_recurrence",
                             "azurerm_logic_app_action_custom")
GRAPH_API = "2022-10-01"          # Resource Graph's resources API (research 2792)
INGESTION_API = "2023-01-01"      # the Logs Ingestion API
COLUMNS = (("TimeGenerated", "datetime"), ("ChangeId", "string"), ("ChangeType", "string"),
           ("TargetResourceId", "string"), ("TargetResourceType", "string"), ("Changes", "dynamic"),
           ("ChangeAttributes", "dynamic"))
QUERY = ("resourcechanges | extend t = todatetime(properties.changeAttributes.timestamp) | where t > ago(1h) | "
         "project TimeGenerated = t, ChangeId = tostring(properties.changeAttributes.changeId), "
         "ChangeType = tostring(properties.changeType), TargetResourceId = tostring(properties.targetResourceId), "
         "TargetResourceType = tostring(properties.targetResourceType), Changes = properties.changes, "
         "ChangeAttributes = properties.changeAttributes")
SUBSCRIPTION = "data.azurerm_subscription.current"


def needs_export(m, s):
    """Whether a config-recording service of environment m asks to keep resource changes longer than Resource Graph
    does (its ciamRetentionDays: more than 14, or kept indefinitely)."""
    days = one(s, "ciamRetentionDays")
    return one(s, "ciamSecurityKind") == "config-recording" and days is not None and \
        (int(days) == INDEFINITE or int(days) > NATIVE_DAYS)


def _endpoints(m):
    """(Azure Resource Manager's endpoint, the Logs Ingestion API's token audience) in environment m's cloud."""
    gov = government(m) or one(m.cloud, "ciamCloudEnvironment") == "usgovernment"
    return (("https://management.usgovcloudapi.net", "https://monitor.azure.us") if gov else
            ("https://management.azure.com", "https://monitor.azure.com"))


def _retention(days):
    """(the table's arguments keeping its rows at least days, a comment or None): interactive retention up to 730
    days, beyond that a total retention of the next whole year Log Analytics takes (never less than asked), the
    longest (4383) for more or indefinite."""
    if days != INDEFINITE and days <= INTERACTIVE_DAYS:
        return (("retention_in_days", days),), None
    total = next((step for step in TOTAL_STEPS if days != INDEFINITE and step >= days), TOTAL_DAYS)
    asked = "indefinite" if days == INDEFINITE else f"{days} days"
    why = (f"Log Analytics keeps rows beyond {INTERACTIVE_DAYS} days in whole years, at most {TOTAL_DAYS}: "
           f"{asked} kept {total}") if total != days else None
    return (("retention_in_days", INTERACTIVE_DAYS), ("total_retention_in_days", total)), why


def _actions(m, n):
    """The Logic App's two HTTP actions (workflow definition language): the Resource Graph query, then the post of
    its rows to the rule's ingestion endpoint, both with the workflow's system-assigned identity."""
    arm, monitor = _endpoints(m)
    identity = {"type": "ManagedServiceIdentity"}
    return (("Query_changes", {"type": "Http", "inputs": {
                "method": "POST", "uri": f"{arm}/providers/Microsoft.ResourceGraph/resources?api-version={GRAPH_API}",
                "body": {"subscriptions": [f"${{{SUBSCRIPTION}.subscription_id}}"], "query": QUERY,
                         "options": {"$top": 1000, "resultFormat": "objectArray"}},
                "authentication": {**identity, "audience": f"{arm}/"}}}),
            ("Keep_changes", {"type": "Http", "runAfter": {"Query_changes": ["Succeeded"]}, "inputs": {
                "method": "POST",
                "uri": f"${{{ENDPOINT}.{n}.logs_ingestion_endpoint}}/dataCollectionRules/"
                       f"${{{RULE}.{n}.immutable_id}}/streams/{STREAM}?api-version={INGESTION_API}",
                "headers": {"Content-Type": "application/json"},
                "body": "@body('Query_changes')?['data']",
                "authentication": {**identity, "audience": monitor}}}))


def _export(m, s, dest):
    cn, n = rdn_value(s), tf_name(f"{rdn_value(s)}_changes")
    retention, why = _retention(int(one(s, "ciamRetentionDays")))
    workflow = f"{WORKFLOW}.{n}"
    return (comment(f"{cn}: Resource Graph keeps resource changes {NATIVE_DAYS} days: every hour a Logic App copies "
                    f"them into {TABLE} in {rdn_value(dest)} (Microsoft's documented way to keep them longer; a run "
                    "reads at most 1000 changes, more need the query's skipToken paging)"),
            tf_block("resource", [TABLE_TYPE, n], [
                *((("#", why),) if why else ()), ("name", TABLE), ("workspace_id", workspace_id(m, dest)),
                ("plan", "Analytics"), *retention,
                *(("column", Block((("name", c), ("type", "dateTime" if t == "datetime" else t))))
                  for c, t in COLUMNS)]),
            tf_block("resource", [ENDPOINT, n], [
                ("name", f"dce-ciam-{rdn_value(m.env)}-changes"), ("location", LOC), ("resource_group_name", RG),
                ("description", f"{cn}: resource changes kept beyond Resource Graph's {NATIVE_DAYS} days (opsdir)"),
                ("tags", tagged(m, {"Realizes": cn, "ManagedBy": "opsdir"}))]),
            tf_block("resource", [RULE, n], [
                ("name", f"dcr-ciam-{rdn_value(m.env)}-changes"), ("location", LOC), ("resource_group_name", RG),
                ("data_collection_endpoint_id", ref(f"{ENDPOINT}.{n}.id")),
                ("destinations", Block((("log_analytics", Block((
                    ("name", "workspace"), ("workspace_resource_id", workspace_id(m, dest))))),))),
                ("stream_declaration", Block((("stream_name", STREAM),
                                              *(("column", Block((("name", c), ("type", t)))) for c, t in COLUMNS)))),
                ("data_flow", Block((("streams", [STREAM]), ("destinations", ["workspace"]),
                                     ("transform_kql", "source"), ("output_stream", f"Custom-{TABLE}")))),
                ("depends_on", [ref(f"{TABLE_TYPE}.{n}")]),
                ("tags", tagged(m, {"Realizes": cn, "ManagedBy": "opsdir"}))]),
            tf_block("resource", [WORKFLOW, n], [
                ("name", f"la-ciam-{rdn_value(m.env)}-changes"), ("location", LOC), ("resource_group_name", RG),
                ("identity", Block((("type", "SystemAssigned"),))),
                ("tags", tagged(m, {"Realizes": cn, "ManagedBy": "opsdir"}))]),
            tf_block("resource", [TRIGGER, n], [
                ("name", "Hourly"), ("logic_app_id", ref(f"{workflow}.id")), ("frequency", "Hour"), ("interval", 1)]),
            *(tf_block("resource", [ACTION, f"{n}_{tf_name(name.lower())}"], [
                ("name", name), ("logic_app_id", ref(f"{workflow}.id")), ("body", jsonencoded(action))])
              for name, action in _actions(m, n)),
            tf_block("resource", ["azurerm_role_assignment", f"{n}_reader"], [
                ("#", "Resource Graph answers with what its caller may read"),
                ("scope", ref(f"{SUBSCRIPTION}.id")), ("role_definition_name", "Reader"),
                ("principal_id", ref(f"{workflow}.identity[0].principal_id"))]),
            tf_block("resource", ["azurerm_role_assignment", f"{n}_publisher"], [
                ("scope", ref(f"{RULE}.{n}.id")), ("role_definition_name", "Monitoring Metrics Publisher"),
                ("principal_id", ref(f"{workflow}.identity[0].principal_id"))]))


def history_note(m, s):
    """The render note of a config-recording service keeping resource changes longer than Resource Graph's 14 days
    with no Log Analytics workspace to copy them to (a blocker), or None."""
    if not needs_export(m, s) or workspace_id(m, findings_destination(m, s)) is not None:
        return None
    return note("Security", "blocker", rdn_value(s), f"keeping resource changes {one(s, 'ciamRetentionDays')} days, "
                f"longer than Resource Graph's {NATIVE_DAYS}, needs a Log Analytics workspace to copy them to (its "
                "ciamFindingsRole): not rendered",
                (f"Bind the service's ciamFindingsRole to a Log Analytics workspace, or record ciamRetentionDays "
                 f"{NATIVE_DAYS} or less, {RECORD}",), s.dn, m.label)


def render_change_history(m, s):
    """HCL for a config-recording service of environment m keeping resource changes longer than Resource Graph's 14
    days (needs_export): the table, endpoint, rule, Logic App and role assignments, or its note's comment
    (history_note) without a workspace; () when it doesn't ask for more."""
    if not needs_export(m, s):
        return ()
    found = history_note(m, s)
    if found is not None:
        return (comment(note_comment(found)),)
    return _export(m, s, findings_destination(m, s))

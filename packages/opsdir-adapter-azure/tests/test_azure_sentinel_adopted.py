"""Alert rules adopting a product's declared detection as Sentinel scheduled analytics rules: the KQL written from the
rule's canonical selector over the custom tables its role's routes fill (the product's JSON parsed from RawData), its
group-by fields as columns and entities its incidents group by, counted (or dcount) to its threshold; a fixed window
searched back to back (query frequency = query period), a sliding one by overlapping lookbacks (frequency a step,
period the window); the rules it can't write named as blockers; the ARM form at the stable API; and its own rules left
out when state is read back."""
import json

from opsdir.connectors.registry import services
from opsdir.core.contract import DetectionMapping, LogSource, ProductDetection
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.core.notes import note_comment
from opsdir.domains.observability.naming import ALERT_RULES, LOG_ROUTES
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.inventory import state_resources
from opsdir_adapter_azure.sentinel import (adopted_query, adopted_rule, kql_path, render_sentinel, sentinel_notes,
                                           sentinel_rules)
from network_fixtures import ALPHA, entry, model

WS = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/providers/"
      "Microsoft.OperationalInsights/workspaces/law-ciam-sentinel")
OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"
FIELDS = (("subject", "principal"), ("realm", "realm"), ("outcome", "result"), ("action", "eventName"),
          ("source-ip", "client.ip"))
SAID = (("outcome", "failure", ("FAILED",)), ("action", "login", ("LOGIN-COMPLETED", "LOGIN-FAILED")))
DETECTION = ProductDetection(
    id="brute-force", title="Brute force", description="Repeated failed sign-ins for one subject",
    products=(("idp", ">=8"),), server_role="ds", log_source="authentication",
    mappings=(DetectionMapping("idp", ">=8", FIELDS, SAID),),
    selector=(("action", ("login",)), ("outcome", ("failure",))), group_by=("subject", "realm"), distinct=None,
    threshold=10, window_seconds=900, window_kind="sliding", tactics=("credential-access",),
    techniques=("T1110", "T1110.001"), severity="sev2", prerequisites=(), evidence=("https://docs.example.test/a",),
    validation="documented")
SPRAY = DETECTION._replace(id="password-spray", title="Password spray", group_by=("source-ip",), distinct="subject",
                           threshold=20, window_seconds=3600, window_kind="fixed", techniques=("T1110.003",),
                           severity="sev1", validation="lab-verified")
PAIRS = (("fake-cloud", DETECTION), ("fake-cloud", SPRAY))
SOURCES = (LogSource("ds", "servers", "audit/*.json", "json-lines", "audit"),)


def _adopting(cn, det, **changes):
    attrs = {"ciamSignal": (det.id,), "ciamTargetRole": (det.server_role,),
             "ciamDetectionSelector": tuple(f"{f}={'|'.join(v)}" for f, v in det.selector),
             "ciamGroupBy": det.group_by, "ciamDistinctField": (det.distinct,) if det.distinct else (),
             "ciamComparison": ("ge",), "ciamThreshold": (str(det.threshold),),
             "ciamEvaluationPeriod": (f"{det.window_seconds}s",), "ciamWindowKind": (det.window_kind,),
             "ciamSeverity": (det.severity,), "ciamAttackTactic": det.tactics, "ciamAttackTechnique": det.techniques,
             "ciamDeclaredDetection": (f"fake-cloud:{det.id}",), "ciamAlertRole": ("alerts-page",), **changes}
    return (f"dn: cn={cn},{ALERT_RULES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamAlertRule\n"
            f"cn: {cn}\n" + "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in vs))


TREE = (OU.format(LOG_ROUTES, "log-routes"), OU.format(ALERT_RULES, "alert-rules"),
        f"dn: cn=security,{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
        "cn: security\nciamLogKind: audit\nciamPublishedBy: ds\nciamLogDestinationRole: siem\n")
RULES = {"idp-brute-force": _adopting("idp-brute-force", DETECTION),
         "idp-password-spray": _adopting("idp-password-spray", SPRAY)}
BINDINGS = (entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef=WS, ciamRetentionDays="90"),
            entry(ALPHA, "page", "ciamAlertChannel", ciamBindingRole="alerts-page", ciamChannelKind="action-group",
                  ciamProviderRef="/subscriptions/0/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/ag"))
SERVICES = services()._replace(logs=lambda m: SOURCES, detections=lambda m: PAIRS)


def _alpha(*rules, rooted=True):
    """Environment alpha/prod recording RULES, those given (LDIF) in place of the one of their name."""
    given = {r.split(",", 1)[0][len("dn: cn="):]: r for r in rules}
    roots = tuple(LdifRecord(f"cn={s},{ALPHA}", "modify", {}, (("add", "ciamInstallRoot", (r,)),))
                  for s, r in (("ds-1", "/opt/ds"), ("ds-2", "/opt/ds")) if rooted)
    _, alpha, _ = model(alpha=BINDINGS, tree=(*TREE, *{**RULES, **given}.values()), changes=roots)
    return alpha


def _block(text, name):
    return text.split(f'resource "azurerm_sentinel_alert_rule_scheduled" "{name}" {{', 1)[1].split("\n}", 1)[0]


def test_a_sliding_rule_looks_back_over_its_window_every_step_its_entities_grouping_incidents():
    text = "\n".join(as_text(render_sentinel(_alpha(), SERVICES)))
    brute = _block(text, "opsdir_idp_brute_force_siem")
    query = ('CiamSecurity_CL | extend ciamEvent = parse_json(RawData) | where tostring(ciamEvent["eventName"]) in '
             '("LOGIN-COMPLETED", "LOGIN-FAILED") and tostring(ciamEvent["result"]) == "FAILED" | extend subject = '
             'tostring(ciamEvent["principal"]), realm = tostring(ciamEvent["realm"]) | where isnotempty(subject) and '
             "isnotempty(realm) | summarize events = count() by subject, realm | where events >= 10")
    assert json.dumps(query) in brute
    for line in ('name                       = "opsdir-idp-brute-force"',
                 "log_analytics_workspace_id = azurerm_log_analytics_workspace.siem.id",
                 'description                = "opsdir: realizes alert rule idp-brute-force"',
                 'severity                   = "Medium"', 'query_frequency            = "PT5M"',
                 'query_period               = "PT15M"', 'tactics                    = ["CredentialAccess"]',
                 'techniques                 = ["T1110"]', 'aggregation_method = "AlertPerResult"',
                 'entity_type = "Account"', 'identifier  = "Name"', 'column_name = "subject"',
                 'lookback_duration       = "PT15M"', 'entity_matching_method  = "Selected"',
                 'by_entities             = ["Account"]',
                 "depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.siem]"):
        assert line in brute, line
    assert kql_path("client.ip") == 'tostring(ciamEvent["client"]["ip"])'


def test_a_fixed_rule_counts_distinct_values_back_to_back_and_maps_the_address_as_an_ip():
    m = _alpha()
    spray = _block("\n".join(as_text(render_sentinel(m, SERVICES))), "opsdir_idp_password_spray_siem")
    assert 'query_frequency            = "PT1H"' in spray and 'query_period               = "PT1H"' in spray
    assert ("summarize value_count = dcount(subject) by source_ip | where value_count >= 20" in spray
            and 'severity                   = "High"' in spray)
    assert 'entity_type = "IP"' in spray and 'identifier  = "Address"' in spray
    notes = [note_comment(n) for n in sentinel_notes(m, SERVICES)]
    assert any("idp-password-spray" in c and "searched back to back" in c for c in notes)
    assert any("idp-brute-force" in c and "sub-techniques T1110.001" in c for c in notes)
    assert any("idp-brute-force" in c and "documented only" in c for c in notes)
    (x, _, tables), _ = sentinel_rules(m, SERVICES)
    assert adopted_query(x.det, x.mapping, ("A_CL", "B_CL")).startswith("union A_CL, B_CL | extend ciamEvent")


def test_what_it_cannot_write_is_a_blocker():
    short = _alpha(_adopting("idp-brute-force", DETECTION, ciamEvaluationPeriod=("5m",)),
                   _adopting("idp-password-spray", SPRAY, ciamEvaluationPeriod=("15d",)))
    blockers = [note_comment(n) for n in sentinel_notes(short, SERVICES) if n.severity == "blocker"]
    assert any("idp-brute-force" in c and "sliding window (300s) is too short" in c for c in blockers)
    assert any("idp-password-spray" in c and "isn't one a scheduled rule looks back over" in c for c in blockers)
    assert "opsdir_idp" not in "\n".join(as_text(render_sentinel(short, SERVICES)))
    unrooted = [note_comment(n) for n in sentinel_notes(_alpha(rooted=False), SERVICES) if n.severity == "blocker"]
    assert any("no table of the workspace holds role ds's log files" in c for c in unrooted)
    assert not any("opsdir-idp" in note_comment(n) for n in sentinel_notes(_alpha()))      # without services


def arm_root(m):
    """A Terraform root of the adopting rules' analytics rules on a workspace in a known resource group, as the ARM
    translation takes it."""
    from opsdir_format_terraform.hcl import TfFile, ref, tf_block
    return TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], [("name", "rg-a")]),
        tf_block("resource", ["azurerm_log_analytics_workspace", "siem"], [
            ("name", "law-ciam"), ("location", ref("data.azurerm_resource_group.main.location")),
            ("resource_group_name", ref("data.azurerm_resource_group.main.name")), ("sku", "PerGB2018")]),
        tf_block("resource", ["azurerm_sentinel_log_analytics_workspace_onboarding", "siem"], [
            ("workspace_id", ref("azurerm_log_analytics_workspace.siem.id"))]),
        *(adopted_rule(m, x, b, tables) for x, b, tables in sentinel_rules(m, SERVICES))))


def test_the_arm_form_carries_the_rule_at_the_stable_api():
    from opsdir_adapter_azure.arm_types import arm_translation
    m = _alpha()
    t = arm_translation(m, {"terraform/main.tf": arm_root(m)}, "Azure infrastructure")
    rules = {r.name: r for (_, k), tpl in t.templates.items() for r in tpl.resources
             if r.type == "Microsoft.SecurityInsights/alertRules"}
    brute = rules["opsdir-idp-brute-force"]
    assert brute.api_version == "2025-09-01" and brute.fields["kind"] == "Scheduled"
    assert {k: brute.properties[k] for k in ("queryFrequency", "queryPeriod", "triggerOperator")} == {
        "queryFrequency": "PT5M", "queryPeriod": "PT15M", "triggerOperator": "GreaterThan"}
    assert brute.properties["incidentConfiguration"]["groupingConfiguration"]["groupByEntities"] == ["Account"]
    assert brute.properties["entityMappings"] == [
        {"entityType": "Account", "fieldMappings": [{"identifier": "Name", "columnName": "subject"}]}]


def test_state_leaves_its_own_rules_out():
    state = json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": "azurerm_sentinel_alert_rule_scheduled", "name": n,
         "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]', "instances": [{"attributes": {
             "id": f"{WS}/providers/Microsoft.SecurityInsights/alertRules/{name}", "name": name,
             "log_analytics_workspace_id": WS, "description": "opsdir: realizes alert rule idp-brute-force",
             "query": "CiamSecurity_CL"}}]}
        for n, name in (("native", "opsdir-idp-brute-force"), ("own", "ciam-brute-force"))]})
    found = [r.ref for r in state_resources(state)[0] if r.kind == "alarm"]
    assert found == [f"{WS}/providers/Microsoft.SecurityInsights/alertRules/ciam-brute-force"]

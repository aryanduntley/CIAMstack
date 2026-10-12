"""What the Azure CLI reports about Defender for Cloud (and an ARM template's, read the same way), item by item from
the ARM type, normalized to the hashicorp/azurerm attribute names opsdir_adapter_azure.security reads. Properties may be
nested or flattened, fields in any case. Pure.

  az security pricing list                     Microsoft.Security/pricings: a plan per resource type, its tier,
                                               sub-plan and extensions (the enabled ones)
  az rest GET <subscription>/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/azureServersSetting
                                               the machines' vulnerability assessment setting (no az command reads it)
  az security automation list                  Microsoft.Security/automations: continuous exports, their sources with
                                               rule sets and where they send (a workspace, Event Hub or Logic App by
                                               resource ID; Event Hub connection strings and Logic App URIs aren't read)
"""
from .arm_ids import arm_field, with_properties

PRICINGS = "microsoft.security/pricings"
VA_SETTINGS = "microsoft.security/servervulnerabilityassessmentssettings"
AUTOMATIONS = "microsoft.security/automations"
READ = (PRICINGS, VA_SETTINGS, AUTOMATIONS)
DESTINATIONS = ("workspaceResourceId", "eventHubResourceId", "logicAppResourceId")


def _of(items, kind):
    return [with_properties(i) for k, i in items if k == kind]


def _enabled(x):
    return str(arm_field(x, "isEnabled")).lower() == "true"          # Defender says "True" / "False", or a boolean


def _pricing(p):
    return {"id": p.get("id"), "resource_type": p.get("name"), "tier": arm_field(p, "pricingTier"),
            "subplan": arm_field(p, "subPlan"),
            "extension": [{"name": arm_field(x, "name")} for x in arm_field(p, "extensions") or ()
                          if isinstance(x, dict) and _enabled(x)]}


def _automation(a):
    def rule(r):
        return {"property_path": arm_field(r, "propertyJPath"), "expected_value": arm_field(r, "expectedValue"),
                "operator": arm_field(r, "operator"), "property_type": arm_field(r, "propertyType")}
    return {"id": a.get("id"), "name": a.get("name"), "enabled": arm_field(a, "isEnabled"),
            "source": [{"event_source": arm_field(s, "eventSource"),
                        "rule_set": [{"rule": [rule(r) for r in arm_field(rs, "rules") or () if isinstance(r, dict)]}
                                     for rs in arm_field(s, "ruleSets") or () if isinstance(rs, dict)]}
                       for s in arm_field(a, "sources") or () if isinstance(s, dict)],
            "action": [{"type": arm_field(x, "actionType"),
                        "resource_id": next((arm_field(x, k) for k in DESTINATIONS if arm_field(x, k)), None)}
                       for x in arm_field(a, "actions") or () if isinstance(x, dict)]}


def security_items(items):
    """(azurerm type, attributes) pairs of the Defender plans, the machines' vulnerability assessment setting and the
    continuous exports among (kind, item) pairs."""
    return [*(("azurerm_security_center_subscription_pricing", _pricing(p)) for p in _of(items, PRICINGS)),
            *(("azurerm_security_center_server_vulnerability_assessments_setting", {
                "id": v.get("id"), "vulnerability_assessment_provider": arm_field(v, "selectedProvider")})
              for v in _of(items, VA_SETTINGS)),
            *(("azurerm_security_center_automation", _automation(a)) for a in _of(items, AUTOMATIONS))]

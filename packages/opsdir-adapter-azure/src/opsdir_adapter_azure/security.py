"""Cloud security services on Azure (core estate: ciamSecurityService) as Microsoft Defender for Cloud and Azure
Policy. Pure.

Rendered in the stack's main.tf for the services the platform team keeps (no ciamManagedBy; one someone else keeps is
named in a comment). Defender's plans are one setting per subscription, so the plans every kept service needs are
merged into one azurerm_security_center_subscription_pricing (tier Standard) per plan:

  threat-detection        control-plane Arm; compute VirtualMachines P2 (agentless scanning); network VirtualMachines
                          P2 (Defender for Servers Plan 2 carries DNS threat detection); containers Containers;
                          storage StorageAccounts DefenderForStorageV2 (malware scanning on upload); databases
                          SqlServers, SqlServerVirtualMachines, OpenSourceRelationalDatabases, CosmosDbs; key-vaults
                          KeyVaults PerKeyVault; applications AppServices, Api; identity has no Defender for Cloud plan:
                          Microsoft Entra ID Protection (identity_protection.py: the risk-log export, and the risk-based
                          Conditional Access policies the record states)
  vulnerability-scanning  compute: VirtualMachines P2 and the server vulnerability assessment setting (Microsoft
                          Defender Vulnerability Management, MdeTvm); containers: Containers with registry vulnerability
                          assessment; applications: no Defender scanner (a comment); compute when no area is named
  config-recording        Azure records resource changes itself (Resource Graph change history, 14 days): nothing
                          to enable, a comment; a longer ciamRetentionDays renders an hourly export into its findings
                          workspace (change_history, 5.7b)
  posture                 CloudPosture (Defender CSPM) and a subscription policy assignment of each framework's built-in
                          initiative, found by display name (nist-800-53-r5 NIST SP 800-53 Rev. 5, nist-800-171-r2 NIST
                          SP 800-171 Rev. 2, fedramp-high, fedramp-moderate, cmmc-l2 CMMC 2.0 Level 2, cmmc-l3, dod-il4,
                          dod-il5, cis, pci-dss, iso-27001, soc2); the Microsoft cloud security benchmark is Defender's
                          own default assignment (a comment); other clouds' baselines are named in a comment

In Azure Government (ciamCloudEnvironment usgovernment) every plan is rendered (decision: a government cloud is assumed
to offer what the record asks for), and a plan or feature one of Microsoft's availability pages lists as unavailable
there carries a comment naming the page, to confirm with the account team. Findings go where ciamFindingsRole says
through continuous export (azurerm_security_center_automation: alerts for threat detection, sub-assessments for
vulnerability scanning, assessments and regulatory compliance for posture) to a Log Analytics workspace (a log
destination's ciamProviderRef) or an Event Hub (a stream binding of kind event-hub, milestone 5.7b, its connection
string the Key Vault secret its ciamSendSecretRole names). A connection string never enters Terraform state (U.5,
task 581): azurerm's action has no write-only argument for it, so an Event Hub's export is rendered through Microsoft's
azapi provider when the cloud allows that add-on (ciamProviderAddOn azapi): an azapi_resource of
Microsoft.Security/automations whose body holds everything but the string, and whose write-only sensitive_body (merged
into the request, never stored) holds the action with the string read from Key Vault by an ephemeral
azurerm_key_vault_secret; without a sensitive_body_version azapi resends it on every update. Without the add-on it is
an action for the service's owner (hub_note): create the export by hand. Bicep/ARM take the merged body, the string a
secure parameter filled from the vault (no state).
An email alert channel (its address the ciamProviderRef) the findings or incidents go to is the subscription's one
Defender security contact (alert notifications, the subscription's owners too; the minimum severity only the preview
securityContacts API sets is named in a comment); another binding is a blocker. An
organization-wide service (milestone 5.7b, decision 2777) is enabled on the management group (ciamManagementRef;
var.management_group_id) by Azure Policy, its part kept with the landing zone (organization origin): per Defender plan
it needs, the built-in DeployIfNotExists policy (PLAN_POLICIES, by definition GUID) assigned with a system-assigned
identity, a role assignment for each role the definition lists, and a remediation for the subscriptions already there;
posture's frameworks' initiatives assigned there too; Defender for APIs has no enabling policy (a comment). The
environment's own root keeps the service's continuous export and incident routing and a line naming who enables it.
Defender covers the whole subscription, every region.

Findings at or above a service's ciamIncidentSeverity also go to the incident process (its ciamIncidentRole): to a Log
Analytics workspace by a second continuous export whose sources carry one rule set per Defender severity at or above it
(alerts: "Severity" Equals high, medium or low, as Microsoft's built-in continuous-export policy filters them;
assessments and sub-assessments: properties.metadata.severity Equals High, Medium or Low); to an action group by a log
alert (azurerm_monitor_scheduled_query_rules_alert_v2) on the table the workspace the service's findings are exported
to keeps them in (Azure Monitor's table reference): threat detection's alerts in SecurityAlert (AlertSeverity at or
above it), vulnerability scanning's findings in SecurityNestedRecommendation and posture's recommendations in
SecurityRecommendation (RecommendationSeverity at or above it, RecommendationState not Healthy). Defender has no
critical severity: critical is routed as high (a comment). Anything else is a blocker. In Azure Government, what one of
Microsoft's pages lists as unavailable there is rendered all the same, and an action: confirm with the account team.
Each is a render note (security_notes, flow 43), written as its comment.

Read back from Terraform state (and from the CLI and ARM, normalized to the same names: cli_security.py; a policy
assignment at a subscription's scope as cli_iam reads it too): azurerm_security_center_subscription_pricing (tier
Standard) -> threat detection over the areas its plans watch, vulnerability scanning
(azurerm_security_center_server_vulnerability_assessments_setting, a Containers plan's registry vulnerability
assessment), posture (CloudPosture, azurerm_subscription_policy_assignment of
a known initiative by its display name) -> security services (kind security), each covering every region, with the
workspace or Event Hub a continuous export of its findings goes to as their destination (an azapi export's body read
as the CLI's automation is), and the incident route: the workspace or Event Hub an export filtering them on severity
goes to, or the action group a log alert on the table of their kind notifies, with the least severity it lets through.
"""
import json
import re

from opsdir.core.directory import get, is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.estate.incidents import incident_routes
from opsdir.domains.estate.naming import ALL_USERS, SEVERITIES
from opsdir.domains.estate.security import findings_destination, security_services
from opsdir_format_terraform.hcl import Block, comment, from_entry, mentions, ref, tf_block, tf_name
from opsdir.domains.governance.keepers import organization_line, organization_origin
from .account import azapi_allowed, management_group, management_group_variable
from .change_history import history_note, render_change_history
from .cli_security import AUTOMATIONS, security_items
from .cmk import role_uri, vault_object
from .identities import GROUP, LOC, RG
from .identity_protection import identity_notes, identity_read, render_identity_protection

PRICING = "azurerm_security_center_subscription_pricing"
VA_SETTING = "azurerm_security_center_server_vulnerability_assessments_setting"
ASSIGNMENT = "azurerm_subscription_policy_assignment"
AUTOMATION = "azurerm_security_center_automation"
AZAPI = "azapi_resource"
# An Event Hub's continuous export through azapi: Microsoft.Security/automations' newest API version (Microsoft's
# template reference lists 2019-01-01-preview and 2023-12-01-preview; research 581)
AZAPI_AUTOMATION = "Microsoft.Security/automations@2023-12-01-preview"
SUBSCRIPTION = "data.azurerm_subscription.current"
CSPM = "CloudPosture"
# area -> Defender plans (resource type, subplan, extensions) watching it
AREA_PLANS = {"control-plane": (("Arm", "PerSubscription", ()),),
              "network": (("VirtualMachines", "P2", ()),),
              "compute": (("VirtualMachines", "P2", ("AgentlessVmScanning",)),),
              "containers": (("Containers", None, ()),),
              "storage": (("StorageAccounts", "DefenderForStorageV2", ("OnUploadMalwareScanning",)),),
              "databases": (("SqlServers", None, ()), ("SqlServerVirtualMachines", None, ()),
                            ("OpenSourceRelationalDatabases", None, ()), ("CosmosDbs", None, ())),
              "key-vaults": (("KeyVaults", "PerKeyVault", ()),),
              "applications": (("AppServices", None, ()), ("Api", "P1", ()))}
SCAN_PLANS = {"compute": (("VirtualMachines", "P2", ("AgentlessVmScanning",)),),
              "containers": (("Containers", None, ("ContainerRegistriesVulnerabilityAssessments",)),)}
# plan -> the area it watches (read back); VirtualMachines P2 also network
PLAN_AREAS = {"Arm": "control-plane", "Dns": "network", "VirtualMachines": "compute", "Containers": "containers",
              "KubernetesService": "containers", "ContainerRegistry": "containers", "StorageAccounts": "storage",
              "SqlServers": "databases", "SqlServerVirtualMachines": "databases",
              "OpenSourceRelationalDatabases": "databases", "CosmosDbs": "databases", "KeyVaults": "key-vaults",
              "AppServices": "applications", "Api": "applications"}
AREAS = ("control-plane", "identity", "network", "compute", "containers", "storage", "databases", "key-vaults",
         "applications")
# framework -> its built-in initiative's display name (Microsoft: "List of built-in policy initiatives")
INITIATIVES = {"nist-800-53-r5": "NIST SP 800-53 Rev. 5", "nist-800-171-r2": "NIST SP 800-171 Rev. 2",
               "fedramp-high": "FedRAMP High", "fedramp-moderate": "FedRAMP Moderate",
               "cmmc-l2": "CMMC 2.0 Level 2", "cmmc-l3": "CMMC Level 3", "dod-il4": "DoD Impact Level 4",
               "dod-il5": "DoD Impact Level 5", "cis": "CIS Microsoft Azure Foundations Benchmark v2.0.0",
               "pci-dss": "PCI DSS v4.0.1", "iso-27001": "ISO 27001:2013", "soc2": "SOC 2 Type 2"}
# plan -> the built-in DeployIfNotExists policy definition enabling it for every subscription under a management group
# (Azure/azure-policy built-in JSON, research 2792); Defender for APIs has none (an audit policy only)
PLAN_POLICIES = {"VirtualMachines": "5eb6d64a-4086-4d7a-92da-ec51aed0332d",
                 "Containers": "efd4031d-b232-4595-babf-ae817348e91b",
                 "StorageAccounts": "cfdc5972-75b3-4418-8ae1-7f5c36839390",
                 "SqlServers": "b99b73e7-074b-4089-9395-b7236f094491",
                 "SqlServerVirtualMachines": "50ea7265-7d8c-429e-9a7d-ca1f410191c3",
                 "OpenSourceRelationalDatabases": "44433aa3-7ec2-4002-93ea-65c65ff0310a",
                 "CosmosDbs": "82bf5b87-728b-4a74-ba4d-6123845cf542",
                 "AppServices": "b40e7bcd-a1e5-47fe-b9cf-2f534d0bfb7d",
                 "KeyVaults": "1f725891-01c0-420a-9059-4fa46cb770b7",
                 "Arm": "b7021b2b-08fd-4dc0-9de7-3c6ece09faf9",
                 "CloudPosture": "72f8cee7-2937-403d-84a1-a4e3e57f3c21"}
MG_ASSIGNMENT = "azurerm_management_group_policy_assignment"
MG_REMEDIATION = "azurerm_management_group_policy_remediation"
MG = ref("var.management_group_id")
BASELINE = "microsoft-cloud-security-benchmark"
BASELINE_NAME = "Microsoft cloud security benchmark"
_REGIONAL = "Microsoft's \"Microsoft Defender for Cloud regional availability\" (2026-10)"
_GOV_PAGE = "Microsoft's \"Cloud feature availability for US Government customers\" (2026-10)"
_MATRIX = "Defender for Cloud's support matrix for cloud environments (2026-10)"
# Azure Government: plans and features one of Microsoft's pages lists as unavailable there (rendered all the same)
GOV_NOTES = {
    "Containers": f"{_REGIONAL} lists the US Gov regions as unsupported for Defender for Containers; {_GOV_PAGE} and "
                  f"{_MATRIX} list it GA",
    "CosmosDbs": f"{_REGIONAL} lists the US Gov regions as unsupported for Defender for Azure Cosmos DB; {_GOV_PAGE} "
                 f"and {_MATRIX} list it GA",
    "Api": f"{_REGIONAL} lists the US Gov regions as unsupported for Defender for APIs, {_MATRIX} lists it not "
           f"available in Azure Government, and {_GOV_PAGE} doesn't list it",
    "AppServices": f"{_REGIONAL}, {_GOV_PAGE} and {_MATRIX} list Defender for App Service as unavailable in Azure "
                   "Government",
    VA_SETTING: f"{_GOV_PAGE} lists integrated vulnerability assessment for machines as not available in Azure "
                "Government; Defender for Servers' support matrix (2026-10) lists VM vulnerability scanning (agentless "
                "and with the Defender for Endpoint sensor) GA there",
    "cmmc-l2": "Azure Government's built-in initiatives list CMMC Level 3, not CMMC 2.0 Level 2 (NIST SP 800-171 Rev. "
               "2 covers its practices)"}
GOV_ONLY = frozenset(("dod-il4", "dod-il5"))
# continuous export: the sources a service's findings come from
EXPORTS = {"threat-detection": ("Alerts",), "vulnerability-scanning": ("SubAssessments",),
           "posture": ("Assessments", "RegulatoryComplianceAssessment")}
QUERY_ALERT = "azurerm_monitor_scheduled_query_rules_alert_v2"
# the Log Analytics table continuous export keeps a kind's findings in, and its severity column
INCIDENT_TABLES = {"threat-detection": ("SecurityAlert", "AlertSeverity"),
                   "vulnerability-scanning": ("SecurityNestedRecommendation", "RecommendationSeverity"),
                   "posture": ("SecurityRecommendation", "RecommendationSeverity")}
TABLE_KINDS = {table: kind for kind, (table, _) in INCIDENT_TABLES.items()}
DEFENDER_LEVELS = ("low", "medium", "high")      # Defender's alert and recommendation severities (Informational aside)
# where a source's severity is in a continuous export's rules: alerts by Microsoft's built-in policy (values lower
# case), recommendations (assessments) and their findings by their metadata (values capitalized)
SEVERITY_PATHS = {"Alerts": ("Severity", str.lower), "Assessments": ("properties.metadata.severity", str.capitalize),
                  "SubAssessments": ("properties.metadata.severity", str.capitalize)}
# Azure Monitor alert severity (0 severest) of an incident route by its least severity
MONITOR_SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
AREA = "Security"


def _gov(m):
    return one(m.cloud, "ciamCloudEnvironment") == "usgovernment"


def gov_note(m, key):
    """The render note of a plan, feature or initiative a Microsoft page lists as unavailable in Azure Government,
    rendered all the same (an action: confirm with the account team), or None (elsewhere, or not listed)."""
    if not (_gov(m) and key in GOV_NOTES):
        return None
    what = "vulnerability assessment for machines" if key == VA_SETTING else \
        f"initiative {INITIATIVES[key]}" if key in INITIATIVES else f"Defender plan {key}"
    return note(AREA, "action", f"{what} in Azure Government", f"{GOV_NOTES[key]}: rendered, confirm with the "
                "account team",
                (f"Ask Microsoft's account team whether {what} is available in the environment's Azure Government "
                 "region before relying on it",
                 f"If it isn't, remove what needs it from the security services' record, {RECORD}"), None, m.label)


def _confirm(m, key):
    """The comment text of a key's Azure Government note (gov_note), or ()."""
    found = gov_note(m, key)
    return (note_comment(found),) if found is not None else ()


def policy_gov_note(m, plan, guid):
    """The render note of a built-in policy enabling a Defender plan that Microsoft doesn't confirm exists in Azure
    Government (an action: check it there), or None elsewhere."""
    if not _gov(m):
        return None
    return note(AREA, "action", f"policy {guid} in Azure Government", f"{plan}: Microsoft doesn't confirm built-in "
                f"policy {guid} exists in Azure Government: check it there (az policy definition show --name {guid})",
                (f"Run `az policy definition show --name {guid}` against Azure Government (az cloud set --name "
                 "AzureUSGovernment)",
                 f"If it doesn't exist, enable Defender plan {plan} in each subscription instead"), None, m.label)


def _plans(services, extra=()):
    """((plan, subplan, extensions, origin), ...) the services need (and extra plans: data discovery's, each with its
    origin), one per plan, extensions merged; origin: the entry of the first that needs it (its pricing is placed with
    that entry's keeper)."""
    wanted = [*((*p, s.dn) for s in services for p in _service_plans(s)), *extra]
    names = list(dict.fromkeys(p for p, _, _, _ in wanted))
    return tuple((p, next((sub for q, sub, _, _ in wanted if q == p and sub), None),
                  tuple(dict.fromkeys(x for q, _, ext, _ in wanted if q == p for x in ext)),
                  next(o for q, _, _, o in wanted if q == p)) for p in names)


def _service_plans(s):
    kind, areas = one(s, "ciamSecurityKind"), values(s, "ciamSecurityCoverage")
    if kind == "threat-detection":
        return tuple(p for a in areas for p in AREA_PLANS.get(a, ()))
    if kind == "vulnerability-scanning":
        return tuple(p for a in (areas or ("compute",)) for p in SCAN_PLANS.get(a, ()))
    return ((CSPM, None, ()),) if kind == "posture" else ()


def _pricing(m, plan, subplan, extensions):
    return tf_block("resource", [PRICING, tf_name(plan)], [
        *(("#", note) for note in _confirm(m, plan)),
        ("tier", "Standard"), ("resource_type", plan), *((("subplan", subplan),) if subplan else ()),
        *(("extension", Block((("name", x),))) for x in extensions)])


def _scanner(m, s):
    areas = values(s, "ciamSecurityCoverage") or ("compute",)
    return (*((tf_block("resource", [VA_SETTING, tf_name(rdn_value(s))], [
                *(("#", note) for note in _confirm(m, VA_SETTING)),
                ("vulnerability_assessment_provider", "MdeTvm")]),) if "compute" in areas else ()),
            *((comment(f"{rdn_value(s)}: Defender for Cloud has no vulnerability scanner for application code (not "
                       "rendered)"),) if "applications" in areas else ()))


def _posture(m, s):
    cn = rdn_value(s)
    frameworks = values(s, "ciamComplianceStandard")
    known = [k for k in frameworks if k in INITIATIVES and not (k in GOV_ONLY and not _gov(m))]
    return (*(x for k in known for x in (
                tf_block("data", ["azurerm_policy_set_definition", tf_name(k)], [("display_name", INITIATIVES[k])]),
                tf_block("resource", [ASSIGNMENT, tf_name(f"{cn}_{k}")], [
                    *(("#", note) for note in _confirm(m, k)),
                    ("name", f"ciam-{k}"), ("display_name", INITIATIVES[k]),
                    ("policy_definition_id", ref(f"data.azurerm_policy_set_definition.{tf_name(k)}.id")),
                    ("subscription_id", ref(f"{SUBSCRIPTION}.id"))]))),
            *((comment(f"{cn}: Defender for Cloud assigns the {BASELINE_NAME} itself (its default assignment)"),)
              if BASELINE in values(s, "ciamSecurityBaseline") else ()),
            *(comment(note_comment(n)) for n in posture_notes(m, s)))


def posture_notes(m, s):
    """The render notes of a posture service's frameworks Azure has no built-in initiative for here (an action:
    assess them another way) and of its other clouds' baselines (a plain note)."""
    cn, frameworks = rdn_value(s), values(s, "ciamComplianceStandard")
    known = [k for k in frameworks if k in INITIATIVES and not (k in GOV_ONLY and not _gov(m))]
    unknown = [k for k in frameworks if k not in known]
    others = [b for b in values(s, "ciamSecurityBaseline") if b != BASELINE]
    return (*((note(AREA, "action", cn, f"Azure has no built-in initiative here for {', '.join(unknown)} (not "
                    "rendered)", (f"Assess {', '.join(unknown)} another way (a custom Azure Policy initiative, or "
                                  "Defender for Cloud's regulatory compliance standards), by hand",), s.dn, m.label),)
              if unknown else ()),
            *((note(AREA, "note", cn, f"{', '.join(others)}: another cloud's baseline, not Azure's (not rendered)", (),
                    s.dn, m.label),) if others else ()))


def _event_hub(m, binding):
    """The Event Hub a binding is (a stream binding of kind event-hub: its ciamProviderRef the hub's ID), or None."""
    return one(binding, "ciamProviderRef") if binding is not None and is_kind(m.d, binding, "ciamStreamBinding") \
        and one(binding, "ciamStreamKind") == "event-hub" else None


def hub_secret(m, binding):
    """(the Event Hub's ID, (vault, name) of the Key Vault secret holding its connection string (ciamSendSecretRole)
    or None, why it can't be sent to or None) of an Event Hub binding; (None, None, None) for another binding."""
    hub = _event_hub(m, binding)
    if hub is None:
        return None, None, None
    uri, unbound = role_uri(m, one(binding, "ciamSendSecretRole"), "send secret")
    if uri is None:
        return hub, None, (unbound[1] if unbound else f"Event Hub {rdn_value(binding)} names no secret holding its "
                                                      "connection string (ciamSendSecretRole)")
    return hub, vault_object(uri), None


def export_action(m, binding):
    """(the azurerm action block a continuous export to binding takes or None, why it can't be rendered or None): a
    Log Analytics workspace by its ID; an Event Hub with its send secret has none and no why (hub_export renders it:
    azurerm's connection_string would keep the secret in Terraform state, U.5)."""
    workspace = _workspace_of(m, binding)
    if workspace:
        return Block((("type", "Workspace"), ("resource_id", workspace))), None
    hub, _, why = hub_secret(m, binding)
    if hub is None:
        return None, (f"{rdn_value(binding)} is no Log Analytics workspace or Event Hub (ciamProviderRef)"
                      if binding is not None else "nothing is bound to it")
    return None, why


def _hub_sources(kind, severity=None):
    """A continuous export's sources as Microsoft.Security/automations takes them: each of a kind's (with severity:
    those with one, a rule set per Defender severity at or above it, as severity_rule_sets)."""
    def rule_sets(src):
        path, spell = SEVERITY_PATHS[src]
        return [{"rules": [{"propertyJPath": path, "propertyType": "String", "expectedValue": spell(level),
                            "operator": "Equals"}]} for level in reversed(_levels(severity))]
    return [{"eventSource": src, **({"ruleSets": rule_sets(src)} if severity else {})}
            for src in EXPORTS[kind] if severity is None or src in SEVERITY_PATHS]


def hub_export(m, s, binding, kind, severity=None):
    """The continuous export of a service's findings (with severity: those at or above it, to the incident process) to
    an Event Hub binding with its send secret, through azapi (ciamProviderAddOn azapi): the vault, the secret read
    ephemerally and the automation, whose write-only sensitive_body alone holds the connection string (in no Terraform
    state or plan, U.5; resent on every update: no sensitive_body_version); without the add-on, its note's comment
    (hub_note)."""
    if not azapi_allowed(m):
        return (comment(note_comment(hub_note(m, s, binding, kind, severity))),)
    cn, what = rdn_value(s), "incidents" if severity else "export"
    n = tf_name(f"{cn}_{what}")
    hub, (vault, name), _ = hub_secret(m, binding)
    action = {"actionType": "EventHub", "eventHubResourceId": hub}
    about = ({"description": f"{cn}'s {severity} and worse findings to {one(s, 'ciamIncidentRole')} (incident "
                             "process)"} if severity else {})
    return (tf_block("data", ["azurerm_key_vault", n], [("name", vault), ("resource_group_name", RG)]),
            tf_block("ephemeral", ["azurerm_key_vault_secret", n], [
                ("name", name), ("key_vault_id", ref(f"data.azurerm_key_vault.{n}.id"))]),
            tf_block("resource", [AZAPI, n], [
                ("#", "the Event Hub's connection string is write-only (azapi's sensitive_body; a secure parameter in "
                      "Bicep/ARM): in no Terraform state (U.5)"),
                ("type", AZAPI_AUTOMATION), ("name", f"{cn}-{what}"), ("parent_id", GROUP), ("location", LOC),
                ("body", {"properties": {**about, "isEnabled": True,
                                         "scopes": [{"scopePath": ref(f"{SUBSCRIPTION}.id")}],
                                         "sources": _hub_sources(kind, severity), "actions": [action]}}),
                ("sensitive_body", {"properties": {"actions": [{
                    **action, "connectionString": ref(f"ephemeral.azurerm_key_vault_secret.{n}.value")}]}})]))


def _source_text(source):
    """An export source as a person sets it: its event source and, if any, the severities its rule sets keep."""
    levels = " or ".join(r["rules"][0]["expectedValue"] for r in source.get("ruleSets", ()))
    return source["eventSource"] + (f" where {SEVERITY_PATHS[source['eventSource']][0]} is {levels}" if levels else "")


def hub_note(m, s, binding, kind, severity=None):
    """The render note of a continuous export to an Event Hub left to a person when the cloud doesn't allow the azapi
    add-on (an action for the service's owner): azurerm's automation would keep the hub's connection string in
    Terraform state (U.5), so the export to create by hand (its name, the hub, the secret holding the string, the
    sources and their severity rules); None otherwise (the add-on allowed, no Event Hub, no secret: findings_note)."""
    hub, secret, why = hub_secret(m, binding)
    if azapi_allowed(m) or hub is None or why is not None or kind not in EXPORTS:
        return None
    cn, role = rdn_value(s), one(s, "ciamIncidentRole" if severity else "ciamFindingsRole")
    name, what = (f"{cn}-incidents", "incidents") if severity else (f"{cn}-export", "findings")
    sources = "; ".join(_source_text(x) for x in _hub_sources(kind, severity))
    return note(AREA, "action", f"{cn}'s {what} to Event Hub {rdn_value(binding)}",
                "not rendered: azurerm's continuous export keeps the Event Hub's connection string in Terraform state "
                "(U.5: no secret in state), and the cloud doesn't allow the azapi add-on, whose write-only body keeps "
                "it out",
                (f"In Defender for Cloud (continuous export, or the Microsoft.Security/automations API), create "
                 f"automation {name} in the environment's resource group on the subscription, exporting {sources} to "
                 f"Event Hub {hub} ({role}), its connection string the one Key Vault {secret[0]} secret {secret[1]} "
                 "holds (pasted there, never written down elsewhere)",
                 f"Or allow the azapi add-on on {rdn_value(m.cloud)} (ciamProviderAddOn azapi), {RECORD}: the export "
                 "is then rendered, its connection string write-only"), s.dn, m.label)


def _route(m, s):
    """A service's incident route (incidents.incident_routes), or None."""
    return next((r for r in incident_routes(m) if r.service.dn == s.dn), None)


def renders_azapi(m):
    """Whether environment m's security render writes an azapi resource: an Event Hub export (hub_export) with the
    add-on allowed."""
    return azapi_allowed(m) and any(
        hub_secret(m, b)[1] is not None for s in security_services(m) if one(s, "ciamSecurityKind") in EXPORTS
        for b in (findings_destination(m, s), *((_route(m, s).binding,) if _route(m, s) else ())))


def _route_how(role):
    return (f"Bind {role} to a Log Analytics workspace (its resource ID as ciamProviderRef), an Event Hub with the "
            f"secret holding its connection string (ciamSendSecretRole) or an email alert channel, {RECORD}",)


def findings_note(m, s, kind):
    """The render note of a service's findings that continuous export can't send where its ciamFindingsRole says
    (neither a workspace, an Event Hub with its secret, nor an email channel: a blocker), or None."""
    dest = findings_destination(m, s)
    if dest is None or kind not in EXPORTS:
        return None
    _, why = export_action(m, dest)
    if why is None or _email(m, dest):
        return None
    role = one(s, "ciamFindingsRole")
    return note(AREA, "blocker", f"{rdn_value(s)}'s findings to {role}", f"not rendered: {why}", _route_how(role),
                s.dn, m.label)


def _export(m, s, kind):
    """The continuous export of a service's findings to the workspace or Event Hub (hub_export) its ciamFindingsRole
    names, the security contact's comment for an email channel, or its note's comment (findings_note)."""
    cn, dest = rdn_value(s), findings_destination(m, s)
    if dest is None or kind not in EXPORTS:
        return ()
    n = tf_name(f"{cn}_export")
    action, why = export_action(m, dest)
    if why is not None:
        return (*_contact(m, s, dest, "findings"),) or (comment(note_comment(findings_note(m, s, kind))),)
    if action is None:
        return hub_export(m, s, dest, kind)
    return (tf_block("resource", [AUTOMATION, n], [
        ("name", f"{cn}-export"), ("location", LOC), ("resource_group_name", RG),
        ("scopes", [ref(f"{SUBSCRIPTION}.id")]), ("action", action),
        *(("source", Block((("event_source", src),))) for src in EXPORTS[kind])]),)


def _email(m, binding):
    """The address of an email alert channel (ciamChannelKind email; its ciamProviderRef, mailto: or bare), or None."""
    ref_ = one(binding, "ciamProviderRef") if binding is not None and is_kind(m.d, binding, "ciamAlertChannel") \
        and one(binding, "ciamChannelKind") == "email" else None
    address = (ref_ or "").removeprefix("mailto:")
    return address if "@" in address else None


def _contact(m, s, binding, what, severity=None):
    """The comment saying a service's findings or incidents reach an email channel as Defender's security contact
    (contacts: the one contact rendered for the subscription); () when the binding isn't one."""
    address = _email(m, binding)
    if address is None:
        return ()
    return (comment(f"{rdn_value(s)}: its {what} reach {address} as Defender's security contact"
                    + (f"; Defender's own minimum alert severity ({severity}) is set only by the securityContacts "
                       "2023-12-01-preview API: set it there" if severity else "")),)


def contacts(m, services):
    """(the subscription's one Defender security contact for every email channel the services' findings or incidents
    go to (their addresses, ';'-joined), the first service needing it) or None."""
    found = [(s, a) for s in services
             for b in (findings_destination(m, s), *(r.binding for r in incident_routes(m) if r.service.dn == s.dn))
             for a in (_email(m, b),) if a and not _workspace_of(m, b) and not _event_hub(m, b)]
    if not found:
        return None
    return tf_block("resource", ["azurerm_security_center_contact", "default"], [
        ("name", "default1"), ("email", ";".join(dict.fromkeys(a for _, a in found))),
        ("alert_notifications", True), ("alerts_to_admins", True)]), found[0][0]


def _levels(severity):
    """Defender's severities at or above a neutral one (critical: high, Defender's highest)."""
    return DEFENDER_LEVELS[min(SEVERITIES.index(severity), len(DEFENDER_LEVELS) - 1):]


def severity_rule_sets(source, severity):
    """The rule sets (one per severity, OR'd) a continuous export of a source keeps its findings at or above a severity
    by; () for a source with no severity (regulatory compliance: an incident export leaves it out)."""
    if source not in SEVERITY_PATHS:
        return ()
    path, spell = SEVERITY_PATHS[source]
    return tuple(("rule_set", Block((("rule", Block((("property_path", path), ("operator", "Equals"),
                                                     ("expected_value", spell(level)),
                                                     ("property_type", "String")))),)))
                 for level in reversed(_levels(severity)))


def incident_query(kind, severity):
    """The query of a kind's exported findings at or above a severity (recommendations: those not healthy)."""
    table, column = INCIDENT_TABLES[kind]
    levels = ", ".join(f'"{x.capitalize()}"' for x in reversed(_levels(severity)))
    state = ' and RecommendationState != "Healthy"' if column == "RecommendationSeverity" else ""
    return f"{table} | where {column} in ({levels}){state}"


def _workspace_of(m, binding):
    return one(binding, "ciamProviderRef") if binding is not None and is_kind(m.d, binding, "ciamLogDestination") \
        and one(binding, "ciamDestinationKind") == "workspace" else None


def _action_group_of(binding):
    ref_ = one(binding, "ciamProviderRef") if binding is not None else None
    return ref_ if ref_ and "/actiongroups/" in ref_.lower() else None


def incident_note(m, s, kind):
    """The render note of a service's incident route this render can't make (a blocker), or None: its binding is no
    workspace, Event Hub, email channel or action group, or a log alert to its action group has no workspace the
    service's findings are exported to."""
    route = _route(m, s)
    if route is None or route.binding is None or kind not in EXPORTS:
        return None
    group = _action_group_of(route.binding)
    findings_ws = _workspace_of(m, findings_destination(m, s))
    if export_action(m, route.binding)[1] is None or _email(m, route.binding) or \
            (group and kind in INCIDENT_TABLES and findings_ws):
        return None
    alert = group and kind in INCIDENT_TABLES
    why = (f"a log alert on {INCIDENT_TABLES[kind][0]} needs the service's findings exported to a Log Analytics "
           "workspace (its ciamFindingsRole)" if alert else
           f"{rdn_value(route.binding)} is no Log Analytics workspace, Event Hub, email channel or action group "
           "(ciamProviderRef)")
    how = ((f"Export the service's findings to a Log Analytics workspace (bind its ciamFindingsRole to one), "
            f"{RECORD}",) if alert else
           (f"Bind {route.role} to a Log Analytics workspace, an Event Hub, an email alert channel or an action group "
            f"(its resource ID as ciamProviderRef), {RECORD}",))
    return note(AREA, "blocker", f"{rdn_value(s)}'s incidents to {route.role}", f"not rendered: {why}", how, s.dn,
                m.label)


def _incident_routing(m, s, kind):
    """The continuous export (or log alert) sending a service's findings at or above its incident severity to the
    incident process (its ciamIncidentRole), or its note's comment (incident_note)."""
    route = _route(m, s)
    if route is None or route.binding is None or kind not in EXPORTS:
        return ()
    cn, n = rdn_value(s), tf_name(f"{rdn_value(s)}_incidents")
    critical = ((comment(f"{cn}: Defender has no critical severity: its high findings go to {route.role}"),)
                if route.severity == "critical" else ())
    group = _action_group_of(route.binding)
    action, why = export_action(m, route.binding)
    if why is None and action is None:
        return (*critical, *hub_export(m, s, route.binding, kind, route.severity))
    if action is not None:
        return (*critical, tf_block("resource", [AUTOMATION, n], [
            ("name", f"{cn}-incidents"), ("location", LOC), ("resource_group_name", RG),
            ("description", f"{cn}'s {route.severity} and worse findings to {route.role} (incident process)"),
            ("scopes", [ref(f"{SUBSCRIPTION}.id")]), ("action", action),
            *(("source", Block((("event_source", src), *severity_rule_sets(src, route.severity))))
              for src in EXPORTS[kind] if src in SEVERITY_PATHS)]))
    contact = _contact(m, s, route.binding, "incidents", route.severity)
    if contact:
        return (*critical, *contact)
    findings_ws = _workspace_of(m, findings_destination(m, s))
    if group and kind in INCIDENT_TABLES and findings_ws:
        return (*critical, tf_block("resource", [QUERY_ALERT, n], [
            ("name", f"{cn}-incidents"), ("location", LOC), ("resource_group_name", RG),
            ("description", f"{cn}'s {route.severity} and worse findings to {route.role} (incident process)"),
            ("scopes", [findings_ws]), ("severity", MONITOR_SEVERITY[route.severity]),
            ("evaluation_frequency", "PT5M"), ("window_duration", "PT5M"),
            ("criteria", Block((("query", incident_query(kind, route.severity)), ("time_aggregation_method", "Count"),
                                ("operator", "GreaterThan"), ("threshold", 0)))),
            ("action", Block((("action_groups", [group]),)))]))
    return (comment(note_comment(incident_note(m, s, kind))),)


def _enabled_by_policy(m, s, plan):
    """The management group's DeployIfNotExists assignment enabling a Defender plan for every subscription: the
    definition by its GUID, a system-assigned identity, a role assignment for each role the definition lists, and a
    remediation for the subscriptions already there."""
    n, guid = tf_name(f"{rdn_value(s)}_{plan}"), PLAN_POLICIES.get(plan)
    if guid is None:
        return (comment(f"{rdn_value(s)}: no built-in policy enables Defender plan {plan} at scale (an audit policy "
                        "only): enable it in each subscription"),)
    name = f"mdc-{plan.lower()}"[:24]
    gov = (("#", note_comment(policy_gov_note(m, plan, guid))),) if _gov(m) else ()
    return (tf_block("data", ["azurerm_policy_definition", n], [("name", guid)]),
            tf_block("resource", [MG_ASSIGNMENT, n], [
                *gov, *(("#", note) for note in _confirm(m, plan)),
                ("name", name), ("display_name", f"Defender for Cloud plan {plan} in every subscription"),
                ("management_group_id", MG), ("policy_definition_id", ref(f"data.azurerm_policy_definition.{n}.id")),
                ("location", one(m.cloud, "ciamRegion")), ("identity", Block((("type", "SystemAssigned"),)))]),
            tf_block("resource", ["azurerm_role_assignment", n], [
                ("#", "each role the policy's remediation needs, as its definition lists them"),
                ("for_each", ref(f"toset(data.azurerm_policy_definition.{n}.role_definition_ids)")),
                ("scope", MG), ("role_definition_id", ref("each.value")),
                ("principal_id", ref(f"{MG_ASSIGNMENT}.{n}.identity[0].principal_id"))]),
            tf_block("resource", [MG_REMEDIATION, n], [
                ("name", f"{name}-fix"), ("management_group_id", MG),
                ("policy_assignment_id", ref(f"{MG_ASSIGNMENT}.{n}.id")),
                ("depends_on", [ref(f"azurerm_role_assignment.{n}")])]))


def organization_note(m, s):
    """The render note of an organization-wide security service without the management group its part is made on
    (ciamManagementRef: a blocker), or None."""
    if management_group(m) is not None:
        return None
    return note(AREA, "blocker", rdn_value(s), "organization-wide, but not rendered: the record doesn't name the "
                "management group (ciamManagementRef)",
                (f"Record the management group on {rdn_value(m.cloud)} (ciamManagementRef: its name or resource ID), "
                 f"{RECORD}",), s.dn, "the organization")


def organization_part(m, s):
    """(the organization part of an organization-wide security service, its note's comment (organization_note) for
    the environment's own part or None): on the management group (ciamManagementRef), the policies enabling each
    Defender plan it needs for every subscription and, for posture, its frameworks' initiatives."""
    missing = organization_note(m, s)
    if missing is not None:
        return (), comment(note_comment(missing))
    plans = tuple(dict.fromkeys(p for p, _, _ in _service_plans(s)))
    frameworks = [k for k in values(s, "ciamComplianceStandard")
                  if k in INITIATIVES and not (k in GOV_ONLY and not _gov(m))]
    return ((*(x for p in plans for x in _enabled_by_policy(m, s, p)),
             *(x for k in frameworks for x in (
                 tf_block("data", ["azurerm_policy_set_definition", tf_name(k)], [("display_name", INITIATIVES[k])]),
                 tf_block("resource", [MG_ASSIGNMENT, tf_name(f"{rdn_value(s)}_{k}")], [
                     *(("#", note) for note in _confirm(m, k)),
                     ("name", f"ciam-{k}"[:24]), ("display_name", INITIATIVES[k]), ("management_group_id", MG),
                     ("policy_definition_id", ref(f"data.azurerm_policy_set_definition.{tf_name(k)}.id"))])))),
            None)


def _service(m, s):
    """(a service's items in the environment's render, its organization part): an organization-wide one keeps its
    continuous export and incident routing here and a line saying who enables it (decision 2777)."""
    cn, kind = rdn_value(s), one(s, "ciamSecurityKind")
    routing = (*_export(m, s, kind), *_incident_routing(m, s, kind))
    if one(s, "ciamAuditScope") == "organization" and kind != "identity-protection" and kind in _ORGANIZATION_KINDS:
        org, missing = organization_part(m, s)
        return (*routing, missing if missing else comment(organization_line(m, s))), org
    body = (_scanner(m, s) if kind == "vulnerability-scanning" else _posture(m, s) if kind == "posture" else
            (render_change_history(m, s) or
             (comment(f"{cn}: Azure records resource changes itself (Resource Graph change history, 14 days): "
                      "nothing to enable; a longer ciamRetentionDays renders an export keeping them"),))
            if kind == "config-recording" else
            render_identity_protection(m, s))
    return (*body, *routing), ()


_ORGANIZATION_KINDS = ("threat-detection", "vulnerability-scanning", "posture")


def render_security(m, extra=()):
    """HCL (and comments) for environment m's security services: the subscription data source when anything refers
    to it, the merged Defender plans (with extra plans: data discovery's, discovery.discovery_plans), then each
    service's own blocks and comments; each stamped with the entry it is for (a plan's with the first service needing
    it), so the render places it by keeper."""
    services = security_services(m)
    contact = contacts(m, services)
    own = tuple(s for s in services if not _organization_wide(s))
    parts = tuple((s, _service(m, s)) for s in services)
    out = (*(x for p, sub, ext, origin in _plans(own, extra)
             for x in from_entry(origin, (_pricing(m, p, sub, ext),))),
           *(from_entry(contact[1].dn, (contact[0],)) if contact else ()),
           *(x for s, (mine, org) in parts
             for x in (*from_entry(s.dn, mine), *from_entry(organization_origin(s.dn), org))))
    return ((tf_block("data", ["azurerm_subscription", "current"], []),) if mentions(out, SUBSCRIPTION) else ()) + \
        ((management_group_variable(m),) if mentions(out, "var.management_group_id") else ()) + out


def _government_notes(m, extra):
    """The Azure Government notes of what environment m's security render confirms (gov_note, policy_gov_note): its
    own services' Defender plans (and extra plans), vulnerability assessment, posture initiatives; the
    organization-wide services' plans' policies and initiatives on the management group."""
    if not _gov(m):
        return ()
    services = security_services(m)
    own = [s for s in services if not _organization_wide(s)]
    org = [s for s in services if _organization_wide(s) and management_group(m) is not None]
    plans = [p for s in org for p in dict.fromkeys(p for p, _, _ in _service_plans(s)) if PLAN_POLICIES.get(p)]
    keys = (*(p for p, _, _, _ in _plans(own, extra)),
            *(VA_SETTING for s in own if one(s, "ciamSecurityKind") == "vulnerability-scanning"
              and "compute" in (values(s, "ciamSecurityCoverage") or ("compute",))),
            *(k for s in own if one(s, "ciamSecurityKind") == "posture" for k in values(s, "ciamComplianceStandard")
              if k in INITIATIVES),
            *plans, *(k for s in org for k in values(s, "ciamComplianceStandard") if k in INITIATIVES))
    return (*(gov_note(m, k) for k in keys), *(policy_gov_note(m, p, PLAN_POLICIES[p]) for p in plans))


def security_notes(m, extra=()):
    """The render notes of environment m's security services (render_security writes their comments, with the same
    extra plans): each service's findings and incident routes' (an Event Hub export left to a person: hub_note), its
    organization part's, a kept service's change history and identity protection notes; then the Azure Government
    confirmations; each once."""
    def of(s):
        kind, org = one(s, "ciamSecurityKind"), _organization_wide(s)
        body = () if org or kind == "vulnerability-scanning" else posture_notes(m, s) if kind == "posture" else \
            (history_note(m, s),) if kind == "config-recording" else identity_notes(m, s)
        route = _route(m, s)
        return (findings_note(m, s, kind), hub_note(m, s, findings_destination(m, s), kind),
                incident_note(m, s, kind),
                hub_note(m, s, route.binding, kind, route.severity) if route is not None else None,
                organization_note(m, s) if org else None, *body)
    found = (*(n for s in security_services(m) for n in of(s)), *_government_notes(m, extra))
    return tuple(dict.fromkeys(n for n in found if n is not None))


def _organization_wide(s):
    return one(s, "ciamAuditScope") == "organization" and one(s, "ciamSecurityKind") in _ORGANIZATION_KINDS


# ------------------------------------------------------------------ read back
_SUBSCRIPTION_SCOPE = re.compile(r"^/subscriptions/[^/]+/?$", re.IGNORECASE)


def _ext(a):
    return {(e.get("name") or "") for e in a.get("extension") or ()}


def _subscription_ref(a, suffix):
    pid = a.get("id") or ""
    return pid.rsplit("/", 1)[0] + suffix if "/pricings/" in pid else None


def _least(levels):
    """The least neutral severity among Defender severities, or None."""
    known = [x.lower() for x in levels if isinstance(x, str) and x.lower() in DEFENDER_LEVELS]
    return min(known, key=SEVERITIES.index) if known else None


def _export_severity(a):
    """The least severity a continuous export's rule sets filter its sources on, or None when they don't."""
    paths = {path for path, _ in SEVERITY_PATHS.values()}
    return _least([r.get("expected_value") for src in a.get("source") or () for rs in src.get("rule_set") or ()
                   for r in rs.get("rule") or () if r.get("property_path") in paths])


def _exports(pairs):
    """((kind, destination, least severity or None), ...) of the continuous exports."""
    return tuple((kind, dest, _export_severity(a)) for a in of_types(pairs, AUTOMATION)
                 for dest in (next((x.get("resource_id") for x in a.get("action") or () if x.get("resource_id")),
                                   None),) if dest
                 for sources in ({x.get("event_source") for x in a.get("source") or ()},)
                 for kind, wanted in EXPORTS.items() if sources & set(wanted))


def _routes(pairs):
    """{kind: the destination its findings' continuous export (no severity filter) sends to}."""
    exports = [(kind, dest) for kind, dest, least in _exports(pairs) if least is None]
    return {kind: next(d for k, d in exports if k == kind) for kind in dict.fromkeys(k for k, _ in exports)}


def _query_table(a):
    """The table a scheduled query alert's query reads (its first word), or None."""
    found = [re.match(r"\s*(\w+)", c.get("query") or "") for c in a.get("criteria") or ()]
    return next((m.group(1) for m in found if m), None)


def is_incident_alert(a):
    """Whether a scheduled query alert's attributes are an incident route's (a query on a table Defender's findings are
    exported to)."""
    return _query_table(a) in TABLE_KINDS


def _query_severity(a):
    return _least(re.findall(r'"(High|Medium|Low)"', " ".join(c.get("query") or "" for c in a.get("criteria") or ())))


def _incidents(pairs):
    """{kind: (the workspace an export filtering its findings on severity, or the action group a log alert on its table
    notifies, the least severity it lets through)}."""
    exported = [(kind, (dest, least)) for kind, dest, least in _exports(pairs) if least is not None]
    alerted = [(TABLE_KINDS[_query_table(a)], (g, _query_severity(a))) for a in of_types(pairs, QUERY_ALERT)
               if is_incident_alert(a) and _query_severity(a)
               for g in [g for x in a.get("action") or () for g in x.get("action_groups") or ()][:1]]
    found = [*exported, *alerted]
    return {kind: next(v for k, v in found if k == kind) for kind in dict.fromkeys(k for k, _ in found)}


def _incident(incidents, kind):
    """(the incident role link, the incident severity attribute) of a kind's route, or ({}, {})."""
    if kind not in incidents:
        return {}, {}
    dest, least = incidents[kind]
    return {"ciamIncidentRole": dest}, {"ciamIncidentSeverity": least}


def security_notices(pairs):
    """What reading Azure's security services can't place: identity protection it can't express (identity_protection.
    identity_read), and identity protection read with no Defender threat detection to belong to."""
    ident = identity_read(pairs)
    defended = any((a.get("tier") or "").lower() == "standard" and PLAN_AREAS.get(a.get("resource_type"))
                   for a in of_types(pairs, PRICING))
    orphan = ("Entra ID Protection (risk logs or risk policies) read, but no Defender for Cloud threat detection "
              "plan to record it on; not imported")
    return (*ident.notices, *((orphan,) if ident.watched and not defended else ()))


def _body(a):
    """An azapi resource's body: an object, or JSON text (as an older state holds it); {} otherwise."""
    b = a.get("body")
    try:
        b = json.loads(b) if isinstance(b, str) else b
    except ValueError:
        return {}
    return b if isinstance(b, dict) else {}


def azapi_automations(pairs):
    """(azurerm_security_center_automation, attributes) of the continuous exports among (type, attributes) pairs made
    through azapi (hub_export), their body read as the CLI's automations are (cli_security)."""
    return tuple(security_items([(AUTOMATIONS, {"id": a.get("id"), "name": a.get("name"), **_body(a)})
                                 for a in of_types(pairs, AZAPI)
                                 if (a.get("type") or "").lower().startswith(AUTOMATIONS + "@")]))


def security_resources(pairs):
    """Security services of (azurerm type, attributes) pairs (an azapi continuous export as the automation it is)."""
    pairs = (*pairs, *azapi_automations(pairs))
    pricings = [a for a in of_types(pairs, PRICING) if (a.get("tier") or "").lower() == "standard"]
    plans = {a.get("resource_type"): a for a in pricings}
    routes, incidents = _routes(pairs), _incidents(pairs)
    every = {"ciamAuditScope": "account", "ciamAllRegions": "TRUE"}
    watched = {PLAN_AREAS[p] for p in plans if p in PLAN_AREAS} | (
        {"network"} if (plans.get("VirtualMachines") or {}).get("subplan") == "P2" else set())
    ident = identity_read(pairs)
    areas = watched | ({"identity"} if ident.watched else set())
    covers = ({"ciamPolicyCovers": ALL_USERS} if ident.all_users else {})
    threat = tuple(resource("security", _subscription_ref(pricings[0], "/defender"), {
        "ciamSecurityKind": "threat-detection", "ciamSecurityCoverage": tuple(a for a in AREAS if a in areas),
        **every, **_incident(incidents, "threat-detection")[1], "ciamRiskPolicy": ident.policies,
        "ciamPolicyMode": ident.mode, **covers},
        links={"ciamFindingsRole": routes.get("threat-detection"), **_incident(incidents, "threat-detection")[0],
               "ciamPolicyCovers": ident.covers, "ciamPolicyExcludes": ident.excludes},
        name="defender-for-cloud")
        for _ in (1,) if watched and _subscription_ref(pricings[0], "/defender"))
    va = next(iter(of_types(pairs, VA_SETTING)), None)
    registries = "ContainerRegistriesVulnerabilityAssessments" in _ext(plans.get("Containers") or {})
    scanned = (*(("compute",) if va is not None else ()), *(("containers",) if registries else ()))
    ref_of = (va or {}).get("id") or (_subscription_ref(pricings[0], "/vulnerability") if pricings else None)
    scan = tuple(resource("security", ref_of, {
        "ciamSecurityKind": "vulnerability-scanning", "ciamSecurityCoverage": scanned, **every,
        **_incident(incidents, "vulnerability-scanning")[1]},
        links={"ciamFindingsRole": routes.get("vulnerability-scanning"),
               **_incident(incidents, "vulnerability-scanning")[0]}, name="defender-vulnerability")
        for _ in (1,) if scanned and ref_of)
    names = {v: k for k, v in INITIATIVES.items()}
    assignments = [a for a in (*of_types(pairs, ASSIGNMENT), *(a for a in of_types(pairs, "azurerm_policy_assignment")
                                                               if _SUBSCRIPTION_SCOPE.match(a.get("scope") or "")))
                   if a.get("display_name") in (*names, BASELINE_NAME)]
    cspm = plans.get(CSPM)
    posture_ref = (cspm or {}).get("id") or next((a.get("id") for a in assignments if a.get("id")), None)
    posture = tuple(resource("security", posture_ref, {
        "ciamSecurityKind": "posture",
        "ciamComplianceStandard": tuple(sorted({names[a["display_name"]] for a in assignments
                                                if a.get("display_name") in names})),
        "ciamSecurityBaseline": (BASELINE,) if cspm is not None or any(
            a.get("display_name") == BASELINE_NAME for a in assignments) else (), **every,
        **_incident(incidents, "posture")[1]},
        links={"ciamFindingsRole": routes.get("posture"), **_incident(incidents, "posture")[0]},
        name="defender-cspm")
        for _ in (1,) if posture_ref)
    return (*threat, *scan, *posture)

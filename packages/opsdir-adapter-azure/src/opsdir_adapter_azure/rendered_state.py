"""Azure: what applying an environment's rendered Terraform would record, so azure/terraform-state reads the render
back (the round trip, milestone 5.5c). Pure.

Each rendered root (terraform/, terraform/landing-zone/, ...) becomes a Terraform state (opsdir_format_terraform.
state_builder): what its blocks configure, and what Azure would assign, which this module gives from the record the
render was made from:
  - a resource realizing a binding the record holds (REALIZES; opsdir_format_terraform.realized) gets that binding's
    provider reference as its id (Azure's importers read a resource by its id), and what else Azure assigned it that
    the record holds (RECORDED: a managed identity's client id);
  - any other resource the id Azure would give it (resource_id: its resource group, its resource provider and ARM
    type, its name; the importers read ids by their segments), and what Azure assigns its type (ASSIGNS: a managed
    identity's principal and client ids);
  - data sources the same ids, so a lookup by name and resource group finds what the record holds; a resource group
    in the environment's region; the subscription the provider runs in (its subscription_id, a variable's default).
"""
import uuid
from types import MappingProxyType

from opsdir.core.directory import one
from opsdir.core.environment import env_dn, env_model
from opsdir_format_terraform.realized import realized
from opsdir_format_terraform.state_builder import root_states, synthetic
from .resource_providers import namespace_of

# Resource types realizing a binding the record matches by its provider reference -> the binding's object class
REALIZES = MappingProxyType({
    "azurerm_kubernetes_cluster": "ciamCluster", "azurerm_security_center_subscription_pricing": "ciamSecurityService",
    "azurerm_monitor_metric_alert": "ciamAlarmBinding", "azurerm_user_assigned_identity": "ciamIdentityBinding",
    "azurerm_log_analytics_workspace": "ciamLogDestination", "azurerm_private_endpoint": "ciamPrivateEndpoint",
    "azurerm_private_link_service": "ciamEndpointService", "azurerm_subscription_policy_assignment": "ciamGuardrail",
    "azurerm_postgresql_flexible_server": "ciamDatabase", "azurerm_route_table": "ciamRouteTable",
    "azurerm_network_watcher_flow_log": "ciamFlowLog", "azurerm_web_application_firewall_policy": "ciamEdgeService",
    "azurerm_monitor_action_group": "ciamAlertChannel", "azurerm_consumption_budget_subscription": "ciamBudget",
    "azurerm_application_insights_standard_web_test": "ciamCanaryBinding"})
# The ARM resource type of an azurerm type in its resource provider (resource_providers.namespace_of)
ARM_TYPES = MappingProxyType({
    "azurerm_kubernetes_cluster": "managedClusters", "azurerm_key_vault": "vaults",
    "azurerm_log_analytics_workspace": "workspaces", "azurerm_user_assigned_identity": "userAssignedIdentities",
    "azurerm_virtual_network": "virtualNetworks", "azurerm_network_security_group": "networkSecurityGroups",
    "azurerm_route_table": "routeTables", "azurerm_private_dns_zone": "privateDnsZones",
    "azurerm_public_ip": "publicIPAddresses", "azurerm_application_gateway": "applicationGateways",
    "azurerm_lb": "loadBalancers", "azurerm_nat_gateway": "natGateways",
    "azurerm_network_interface": "networkInterfaces", "azurerm_private_endpoint": "privateEndpoints",
    "azurerm_private_link_service": "privateLinkServices",
    "azurerm_web_application_firewall_policy": "ApplicationGatewayWebApplicationFirewallPolicies",
    "azurerm_firewall_policy": "firewallPolicies", "azurerm_postgresql_flexible_server": "flexibleServers",
    "azurerm_storage_account": "storageAccounts", "azurerm_linux_virtual_machine": "virtualMachines",
    "azurerm_managed_disk": "disks", "azurerm_monitor_action_group": "actionGroups",
    "azurerm_monitor_metric_alert": "metricAlerts", "azurerm_monitor_data_collection_rule": "dataCollectionRules",
    "azurerm_monitor_data_collection_endpoint": "dataCollectionEndpoints", "azurerm_application_insights": "components",
    "azurerm_application_insights_standard_web_test": "webTests",
    "azurerm_data_protection_backup_vault": "backupVaults", "azurerm_security_center_automation": "automations"})
# What the record holds of what Azure assigned a realized binding's resource:
# {type: {state attribute: record attribute}}
RECORDED = MappingProxyType({"azurerm_user_assigned_identity": {"client_id": "ciamIdentityClientId"}})
_NAMESPACE = uuid.UUID("6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f")       # synthetic GUIDs: stable per resource


def guid(*parts):
    """A stable synthetic GUID for what Azure would assign (a principal id, a tenant): the same parts, the same GUID."""
    return str(uuid.uuid5(_NAMESPACE, "/".join(str(p) for p in parts)))


# What Azure assigns a resource of a type beyond its id, as the importers read it:
# (block name, configured) -> attributes
ASSIGNS = MappingProxyType({
    "azurerm_user_assigned_identity": lambda name, configured: {
        "principal_id": guid("principal", name), "client_id": guid("client", name), "tenant_id": guid("tenant")}})


def subscription_of(blocks):
    """The subscription a rendered root runs in: its azurerm provider's subscription_id, a literal or the default of the
    variable it names (the zero subscription when it names none)."""
    body = next((b.body for b in blocks if b.kind == "provider" and b.labels == ("azurerm",)), ())
    given = next((v for k, v in body if k == "subscription_id"), "")
    named = given[6:-1] if isinstance(given, str) and given.startswith("${var.") else None
    defaults = {b.labels[0]: v for b in blocks if b.kind == "variable" and b.labels for k, v in b.body
                if k == "default"}
    return (defaults.get(named, "") if named else given) or "00000000-0000-0000-0000-000000000000"


def resource_id(type_, name, index, configured, subscription):
    """The id Azure gives a resource of a type: under its resource group, its resource provider and ARM type
    (ARM_TYPES), its name; a child under its parent (a subnet under its network); subscription-level ones under the
    subscription. A type this module doesn't place gets a synthetic one, unique in the root."""
    named = str(configured.get("name") or name) + (f"-{index}" if index is not None else "")
    sub = f"/subscriptions/{subscription}"
    group = f"{sub}/resourceGroups/{configured.get('resource_group_name') or 'rg-synthetic'}"
    placed = {
        "azurerm_resource_group": lambda: f"{sub}/resourceGroups/{named}",
        "azurerm_subnet": lambda: f"{group}/providers/Microsoft.Network/virtualNetworks/"
                                  f"{configured.get('virtual_network_name')}/subnets/{named}",
        "azurerm_network_watcher_flow_log": lambda: f"{group}/providers/Microsoft.Network/networkWatchers/"
                                                    f"{configured.get('network_watcher_name')}/flowLogs/{named}",
        "azurerm_subscription_policy_assignment": lambda: f"{sub}/providers/Microsoft.Authorization/"
                                                          f"policyAssignments/{named}",
        "azurerm_security_center_subscription_pricing": lambda: f"{sub}/providers/Microsoft.Security/pricings/"
                                                                f"{configured.get('resource_type') or named}",
        "azurerm_security_center_server_vulnerability_assessments_setting": lambda: (
            f"{sub}/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/AzureServersSetting"),
        "azurerm_role_definition": lambda: f"{sub}/providers/Microsoft.Authorization/roleDefinitions/"
                                           f"{guid('role', configured.get('name', name))}",
        "azurerm_role_assignment": lambda: f"{configured.get('scope') or sub}/providers/Microsoft.Authorization/"
                                           f"roleAssignments/{guid('assignment', name, index)}",
        "azurerm_storage_container": lambda: f"{configured.get('storage_account_id')}/blobServices/default/"
                                             f"containers/{named}",
        "azurerm_monitor_aad_diagnostic_setting": lambda: f"/providers/Microsoft.AADIAM/diagnosticSettings/{named}",
        "azuread_conditional_access_policy": lambda: guid("conditional-access", name, index)}
    if type_ in placed:
        return placed[type_]()
    if type_ in ARM_TYPES:
        return f"{group}/providers/{namespace_of(type_)}/{ARM_TYPES[type_]}/{named}"
    return f"{group}/providers/Microsoft.Resources/opsdirSynthetic/{type_[8:]}.{named}"


def azure_assigned(m, blocks):
    """assigned() for one rendered root of environment m (see opsdir_format_terraform.state_builder.tf_state)."""
    subscription = subscription_of(blocks)
    region = one(m.cloud, "ciamRegion") or ""
    answers = {"azurerm_resource_group": lambda configured: {"location": region},
               "azurerm_subscription": lambda configured: {"id": f"/subscriptions/{subscription}",
                                                           "subscription_id": subscription,
                                                           "tenant_id": guid("tenant", subscription)}}

    def assigned(mode, type_, name, index, configured):
        made = {"id": resource_id(type_, name, index, configured, subscription)}
        if mode == "data":
            given = answers[type_](configured) if type_ in answers else {}
            return {**synthetic(mode, type_, name, index, configured), **made, **given}
        binding = realized(m, REALIZES, type_, name)
        ref = one(binding, "ciamProviderRef") if binding is not None else None
        extra = ASSIGNS[type_](name, configured) if type_ in ASSIGNS else {}
        held = {attr: one(binding, held_as) for attr, held_as in RECORDED.get(type_, {}).items()
                if binding is not None and one(binding, held_as)}
        return {**made, **extra, **held, **({"id": ref} if ref else {})}
    return assigned


def rendered_states(files, d, environment):
    """The ReadBack's prepare: the rendered Terraform roots of an environment ({<cloud>/<env>/...tf: text}) as the
    states applying them would record ({<cloud>/<env>/<root>.tfstate: text}), what Azure assigns from record d."""
    m = env_model(d, env_dn(environment))
    return root_states(files, environment, lambda blocks: azure_assigned(m, blocks))

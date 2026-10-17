"""The Azure resource providers an environment's roots need registered in its subscription. azurerm 5.x registers none
by default (resource_provider_registrations = "none"), so the landing zone, applied by the subscription's owner,
registers the namespaces the rendered roots' resources belong to (decision 2383): read from the rendered blocks, each
managed azurerm resource by its type's longest matching prefix below, each azapi resource by its type's namespace.
What to register by hand is a render note (core.notes, flow 43; registration_notes). Pure."""
import re

from opsdir.core.notes import note
from opsdir_format_terraform.hcl import blocks_of

NAMESPACES = (
    ("azurerm_active_directory_domain_service", "Microsoft.AAD"),
    ("azurerm_application_gateway", "Microsoft.Network"),
    ("azurerm_application_insights", "Microsoft.Insights"),
    ("azurerm_bastion_host", "Microsoft.Network"),
    ("azurerm_cdn_frontdoor_", "Microsoft.Cdn"),
    ("azurerm_consumption_budget_", "Microsoft.Consumption"),
    ("azurerm_container_app_", "Microsoft.App"),
    ("azurerm_data_protection_", "Microsoft.DataProtection"),
    ("azurerm_disk_encryption_set", "Microsoft.Compute"),
    ("azurerm_dns_", "Microsoft.Network"),
    ("azurerm_email_communication_service", "Microsoft.Communication"),
    ("azurerm_eventgrid_", "Microsoft.EventGrid"),
    ("azurerm_eventhub", "Microsoft.EventHub"),
    ("azurerm_federated_identity_credential", "Microsoft.ManagedIdentity"),
    ("azurerm_firewall", "Microsoft.Network"),
    ("azurerm_function_app_function", "Microsoft.Web"),
    ("azurerm_key_vault", "Microsoft.KeyVault"),
    ("azurerm_kubernetes_cluster", "Microsoft.ContainerService"),
    ("azurerm_lb", "Microsoft.Network"),
    ("azurerm_linux_function_app", "Microsoft.Web"),
    ("azurerm_linux_virtual_machine", "Microsoft.Compute"),
    ("azurerm_local_network_gateway", "Microsoft.Network"),
    ("azurerm_log_analytics_", "Microsoft.OperationalInsights"),
    ("azurerm_logic_app_", "Microsoft.Logic"),
    ("azurerm_managed_disk", "Microsoft.Compute"),
    ("azurerm_management_group_policy_", "Microsoft.Authorization"),
    ("azurerm_management_lock", "Microsoft.Authorization"),
    ("azurerm_monitor_", "Microsoft.Insights"),
    ("azurerm_mssql_", "Microsoft.Sql"),
    ("azurerm_mysql_flexible_", "Microsoft.DBforMySQL"),
    ("azurerm_nat_gateway", "Microsoft.Network"),
    ("azurerm_network_", "Microsoft.Network"),
    ("azurerm_orchestrated_virtual_machine_scale_set", "Microsoft.Compute"),
    ("azurerm_pim_", "Microsoft.Authorization"),
    ("azurerm_policy_", "Microsoft.Authorization"),
    ("azurerm_postgresql_flexible_", "Microsoft.DBforPostgreSQL"),
    ("azurerm_private_dns_", "Microsoft.Network"),
    ("azurerm_private_endpoint", "Microsoft.Network"),
    ("azurerm_private_link_service", "Microsoft.Network"),
    ("azurerm_public_ip", "Microsoft.Network"),
    ("azurerm_purview_", "Microsoft.Purview"),
    ("azurerm_resource_group", "Microsoft.Resources"),
    ("azurerm_resource_group_policy_", "Microsoft.Authorization"),
    ("azurerm_role_", "Microsoft.Authorization"),
    ("azurerm_route", "Microsoft.Network"),
    ("azurerm_security_center_", "Microsoft.Security"),
    ("azurerm_sentinel_", "Microsoft.SecurityInsights"),
    ("azurerm_servicebus_", "Microsoft.ServiceBus"),
    ("azurerm_storage_", "Microsoft.Storage"),
    ("azurerm_subnet", "Microsoft.Network"),
    ("azurerm_subscription", "Microsoft.Resources"),
    ("azurerm_subscription_policy_", "Microsoft.Authorization"),
    ("azurerm_traffic_manager_", "Microsoft.Network"),
    ("azurerm_user_assigned_identity", "Microsoft.ManagedIdentity"),
    ("azurerm_virtual_hub", "Microsoft.Network"),
    ("azurerm_virtual_machine", "Microsoft.Compute"),
    ("azurerm_virtual_network", "Microsoft.Network"),
    ("azurerm_web_application_firewall_policy", "Microsoft.Network"),
    ("azurerm_windows_function_app", "Microsoft.Web"),
    ("azurerm_windows_virtual_machine", "Microsoft.Compute"),
)
# an azapi_resource's ARM type: '<namespace>/<type>@<api version>'
_ARM_TYPE = re.compile(r"(Microsoft\.[A-Za-z]+)/[^\"]*@")


def namespace_of(type_):
    """The resource provider namespace of an azurerm resource type (its longest matching prefix), or None."""
    found = [(len(p), ns) for p, ns in NAMESPACES if type_.startswith(p)]
    return max(found)[1] if found else None


def _azapi_namespace(b):
    """The namespace of an azapi_resource's ARM type (its first attribute, '<namespace>/<type>@<version>'); None for
    any other first attribute."""
    key, value = b.body[0] if b.body else ("", "")
    found = _ARM_TYPE.match(value) if key == "type" and isinstance(value, str) else None
    return found.group(1) if found else None


def resource_providers(items):
    """(namespaces, unknown types): the sorted namespaces the managed azurerm and azapi resources among rendered
    Terraform items belong to, and the azurerm resource types no namespace is known for. Data-plane resources and data
    sources register nothing."""
    types = {b.labels[0] for b in blocks_of(items, "resource") if b.labels[0].startswith("azurerm_")}
    known = {t: namespace_of(t) for t in types}
    azapi = {ns for b in blocks_of(items, "resource", "azapi_resource") for ns in (_azapi_namespace(b),) if ns}
    return (tuple(sorted({ns for ns in known.values() if ns} | azapi)),
            tuple(sorted(t for t, ns in known.items() if ns is None)))


def registration_notes(m, namespaces, unknown):
    """The render notes (actions) of what to register by hand in environment m's subscription before applying: the
    namespaces given (when no landing-zone root registers them), each azurerm type whose resource provider opsdir
    doesn't know; () when nothing needs registering."""
    return ((note("Subscription", "action", "resource providers", "to register in the subscription before applying "
                  "(azurerm 5.x registers none, and the environment has no landing zone to do it): "
                  f"{', '.join(namespaces)}",
                  ("Before applying, register these resource providers in the subscription (its owner)",), None,
                  m.label),) if namespaces else ()) \
        + tuple(note("Subscription", "action", f"resource type `{t}`", "its resource provider isn't known to opsdir",
                     ("Before applying, register its resource provider in the subscription by hand",), None, m.label)
                for t in unknown)

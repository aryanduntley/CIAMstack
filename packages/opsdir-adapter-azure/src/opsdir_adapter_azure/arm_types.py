"""The Azure render's Terraform types as ARM (5.6, decisions 2592 and 2605): one row per resource type the renderers
write (arm_render translates by it), what the lookups Terraform makes are natively (existing resources, the
deployment's own resource group and subscription, secure parameters), the types ARM has no form for, and the types
kept in Terraform for a stated reason. API versions are the latest stable ones in Microsoft's template reference
(research 2595); bicep build and lint check every rendered template against them. Pure data and small pure
converters.
"""
import re
from types import MappingProxyType

from opsdir_format_arm.template import Call, Interp, Member, ResourceId
from opsdir_format_terraform.native import Computed, Custom, FromBlock, Merge, Native, Nest, obj, one, own
from .arm_render import Arm, Existing, Fixed, Lookup, Parent, Secure, translated, translation

NETWORK, IDENTITY, INSIGHTS, OPINSIGHTS = "2025-09-01", "2023-01-31", "2024-03-11", "2025-07-01"
KEYVAULT, AKS, PIM = "2024-11-01", "2025-05-01", "2024-09-01-preview"
COMPUTE, DISKS, STORAGE, POSTGRES, BACKUP = "2026-04-01", "2025-01-02", "2025-06-01", "2025-08-01", "2025-02-01"
# Front Door, its firewall policies, DNS zones (public, private), MySQL, Traffic Manager, web tests, exemptions
# (research 2595; 2622: the Bicep type index, the newest)
CDN, FD_WAF, DNS, PRIVATE_DNS = "2026-07-01", "2026-04-01", "2018-05-01", "2024-06-01"
MYSQL, TM, WEBTESTS, EXEMPTIONS = "2024-12-30", "2026-09-01", "2022-06-15", "2026-01-01-preview"
# Microsoft Sentinel's onboardingStates and alertRules: the stable version (2025-09-01; Scheduled and NRT rules GA in
# Azure Government: research docs/research m109c, decision 3299)
SENTINEL = "2025-09-01"
AUTOSCALE = "2022-10-01"        # the newest autoscalesettings version the Bicep type index has (probed 2026-10-12)
APP = "2026-07-01"              # Microsoft.App: the newest version the Bicep 0.48.1 type index has (probed 2026-10-14)
# Container registries, Application Insights components: the newest stable versions the Bicep 0.48.1 type index has
# (probed 2026-10-15; components has no other stable one)
REGISTRY, COMPONENTS = "2025-11-01", "2020-02-02"
# Inputs naming a resource by its ID (the root's variables), by name pattern -> (its ARM type, API version): an
# extension resource scoped by one (a check job's grant on the Application Insights resource or a registry) is
# deployed in a module at the group the ID names (arm_render); an input not listed keeps it Terraform (UNPLACED).
INPUT_SCOPES = MappingProxyType({r"application_insights_id": ("Microsoft.Insights/components", COMPONENTS),
                                 r"registry_[a-z0-9_]+_id": ("Microsoft.ContainerRegistry/registries", REGISTRY)})


def input_type(name):
    """The ARM type of the resource an input names by its ID (INPUT_SCOPES), else None."""
    return next((t for pattern, (t, _) in INPUT_SCOPES.items() if re.fullmatch(pattern, name)), None)
# Types ARM has no form for: they stay in the Terraform root beside the templates (research 2595). An external
# tenant's app registrations are Microsoft Graph objects in another tenant (task 547), which no deployment in the
# environment's subscription reaches: Terraform, through the tenant-aliased azuread provider.
NO_NATIVE = frozenset({"azapi_data_plane_resource", "azuread_conditional_access_policy", "azuread_application",
                       "azuread_service_principal", "azuread_service_principal_token_signing_certificate"})
_SUBNET = ("a property of the landing zone's subnet: ARM sets it only by re-declaring the whole subnet, which the "
           "landing zone keeps")
_PARENT_INPUT = ("a child of the {}, which the root takes as an input: ARM deploys a child in its parent's resource "
                 "group, which the record doesn't hold")
_MANAGEMENT_GROUP = ("made on the management group the record names (a management-group scope deployment): its keeper "
                     "applies it with Terraform, with the role assignments and remediation it needs")
# Types kept in Terraform for a stated reason.
_DOMAIN_SERVICES = ("kept with its replica sets: ARM declares them as the managed domain's replicaSets property, which "
                    "azurerm sets as resources of their own")
KEPT = {
    "azurerm_subnet_network_security_group_association": _SUBNET,
    # Entra Domain Services (flow 76): the managed domain and its replica sets together
    "azurerm_active_directory_domain_service": _DOMAIN_SERVICES,
    "azurerm_active_directory_domain_service_replica_set": _DOMAIN_SERVICES,
    "azurerm_subnet_route_table_association": _SUBNET,
    "azurerm_subnet_nat_gateway_association": _SUBNET,
    "azurerm_virtual_hub_connection": _PARENT_INPUT.format("virtual WAN hub"),
    "azurerm_private_dns_resolver_forwarding_rule": _PARENT_INPUT.format("landing zone's DNS forwarding ruleset"),
    # organization-wide Defender (5.7b): the management group's part, in the landing zone keeper's root
    "azurerm_management_group_policy_assignment": _MANAGEMENT_GROUP,
    "azurerm_management_group_policy_remediation": _MANAGEMENT_GROUP,
    "azurerm_storage_object_replication": (
        "ARM sets object replication on the destination account first, in that account's resource group, and the "
        "source's policy takes the id it returns; the destination is an input the record holds no group for"),
}
# Built-in role definitions by name -> their GUIDs: Microsoft's built-in roles page; "built-in roles have the same role
# ID across clouds" (Azure role definitions page). Research 2612.
ROLES = {
    "AcrPull": "7f951dda-4ed3-4680-a7ca-43fe172d538d",     # built-in roles page, Containers (checked 2026-10-15)
    "Azure Event Hubs Data Owner": "f526a384-b230-433a-b45c-95f59c4a2dec",
    "Azure Event Hubs Data Sender": "2b629674-e913-4c01-ae53-ef4638d8f975",
    "Azure Service Bus Data Owner": "090c5cfd-751d-490a-894a-3ce6f1109419",
    "Azure Service Bus Data Sender": "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39",
    "Disk Backup Reader": "3e5e47e6-65f7-47ef-90b5-e5dd4d455f24",
    "Disk Snapshot Contributor": "7efff54f-a5b4-42b5-a1c5-5411624893ce",
    "DNS Zone Contributor": "befefa01-2a29-4197-83a8-272ff33ce314",
    "EventGrid Data Sender": "d5a91429-5739-47e2-a06b-3470a27159e7",
    "Key Vault Administrator": "00482a5a-887f-4fb3-b363-3b7fe8e74483",
    "Key Vault Contributor": "f25e0fa2-a7c8-4377-a976-54943a77a395",
    "Key Vault Crypto Officer": "14b46e9e-c2b7-41b4-b07b-48a6ebf60603",
    "Key Vault Crypto Service Encryption User": "e147488a-f6f5-4113-8e2d-b22465e65bf6",
    "Key Vault Crypto User": "12338af0-0e69-4776-bea7-57ae8d297424",
    "Key Vault Secrets Officer": "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
    "Key Vault Secrets User": "4633458b-17de-408a-b874-0445c86b69e6",
    "Log Analytics Reader": "73c42c96-874c-492b-b04d-ab87d138a893",
    "Monitoring Metrics Publisher": "3913510d-42f4-4e42-8a64-420c390055eb",
    "Monitoring Reader": "43d0d8ad-25c7-4714-9337-8ba259a9fe05",
    "Network Contributor": "4d97b98b-1d4f-4787-a291-c67834d212e7",
    "Private DNS Zone Contributor": "b12aa53e-6015-4669-85d0-8515ebb3ae7f",
    "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",          # Microsoft built-in roles page (checked 2026-10-13)
    "Role Based Access Control Administrator": "f58310d9-a9f6-439a-9e8d-f62e7b41a168",
    "Storage Blob Data Contributor": "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
    "Storage Blob Data Owner": "b7e6dc6d-f1e8-4753-8033-0f276bb0955b",
    "Storage Blob Data Reader": "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
    "User Access Administrator": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    "Virtual Machine Contributor": "9980e02c-c2be-4d73-94e8-173b1dc7cf3c"}
# Built-in policy initiatives by display name -> their policy set definition names: Microsoft's regulatory compliance
# index (Azure Government's use the same ids). Not listed: CMMC 2.0 Level 2, DoD Impact Level 4/5 (no official id
# found), PCI DSS v4.0.1 (only PCI DSS 4.0 has one): an assignment of those stays Terraform (research 2612).
INITIATIVES = {
    "NIST SP 800-53 Rev. 5": "179d1daa-458f-4e47-8086-2a68d0d6c38f",
    "NIST SP 800-171 Rev. 2": "03055927-78bd-4236-86c0-f36125a10dc9",
    "FedRAMP High": "d5264498-16f4-418a-b659-fa7ef418175f",
    "FedRAMP Moderate": "e95f5a9f-57ad-4d03-bb0b-b1d16db93693",
    "CMMC Level 3": "b5629c75-5c77-4422-87b9-2509e680f8de",
    "CIS Microsoft Azure Foundations Benchmark v2.0.0": "06f19060-9e68-4070-92ca-f15cc126059e",
    "ISO 27001:2013": "89c6cddc-1c73-4ac1-b19c-54d1a15a42f2",
    "SOC 2 Type 2": "4054785f-702b-4a98-9215-009cbd58b141"}


def _role_definition(name, where):
    """A built-in role definition's id: subscriptionResourceId of its GUID (refused for a role the table doesn't
    know)."""
    if name not in ROLES:
        raise SystemExit(f"{where}: no built-in role definition id known for {name!r} (add it to ROLES)")
    return Call("subscriptionResourceId", ("Microsoft.Authorization/roleDefinitions", ROLES[name]))


def _initiative(name, where):
    if name not in INITIATIVES:
        raise SystemExit(f"{where}: no built-in policy initiative known as {name!r} (add it to INITIATIVES)")
    return Call("tenantResourceId", ("Microsoft.Authorization/policySetDefinitions", INITIATIVES[name]))


def _unknown_initiative(f, block):
    """Why a policy assignment stays Terraform: the initiative it assigns (a lookup by display name) has no id the
    table knows; else None."""
    ref = f.get("policy_definition_id")
    found = block(ref[2:-1].rsplit(".", 1)[0]) if isinstance(ref, str) and ref.startswith("${data.") else None
    name = dict(found.body).get("display_name") if found is not None else None
    return (f"assigns the built-in initiative {name!r}, whose id Microsoft doesn't publish (Terraform looks it up by "
            "name)") if name is not None and name not in INITIATIVES else None


def _assignment_name(f, cx):
    """A role assignment's (or eligibility request's) name: a GUID from its scope and its Terraform address (stable,
    and known when the deployment starts, as Bicep requires of names)."""
    return Call("guid", (cx.value(f["scope"]), cx.where))


def _lb_address(f):
    """The address of the load balancer a child's loadbalancer_id references."""
    v = f["loadbalancer_id"]
    return v[2:-1].rsplit(".", 1)[0] if isinstance(v, str) and v.startswith("${") else None


def _tags(f, cx):
    return {"tags": cx.value(f["tags"])} if "tags" in f else {}


# ------------------------------------------------------------------ lookups

def _resource_group(f, a):
    """data.azurerm_resource_group: the template's own group by resourceGroup(); another group by its name."""
    name = f.get("name")

    def answer(rg):
        if rg == name:
            return Member(Call("resourceGroup", ()), {"name": "name", "location": "location", "id": "id"}[a])
        if a == "name":
            return name
        if a == "id":
            return Call("subscriptionResourceId", ("Microsoft.Resources/resourceGroups", name))
        raise SystemExit(f"data.azurerm_resource_group {name}: its {a} is read in another group's template, which "
                         "ARM can't")
    return answer if a in ("name", "location", "id") else None


def _in_group(f):
    """The resource group a lookup names: its resource_group_name value as written (arm_render resolves it to a
    group statically), None when it names none."""
    return f.get("resource_group_name")


def _lookup(type_, api, reads):
    """A data source read as an existing resource by name (and resource group): reads {attribute: 'id', 'name' or a
    property path}."""
    return lambda f, a: (Lookup(Existing(type_, api, f["name"], _in_group(f)), reads[a]) if a in reads else None)


def _subnet(f, a):
    vnet = Existing("Microsoft.Network/virtualNetworks", NETWORK, f["virtual_network_name"], _in_group(f))
    return Lookup(Existing("Microsoft.Network/virtualNetworks/subnets", NETWORK, f["name"], None, vnet), "id") \
        if a == "id" else None


def _vault_key(f, a):
    """data.azurerm_key_vault_key: the key under its vault (key_vault_id a vault lookup's id): its id is the versioned
    key URI, versionless_id the key URI, resource_id / resource_versionless_id the ARM id."""
    read = {"id": "keyUriWithVersion", "versionless_id": "keyUri", "resource_versionless_id": "id",
            "resource_id": "id"}.get(a)
    return Lookup(Existing("Microsoft.KeyVault/vaults/keys", KEYVAULT, f["name"], None, f["key_vault_id"]), read) \
        if read else None


DATA = {
    "azurerm_resource_group": _resource_group,
    "azurerm_subscription": lambda f, a: (Member(Call("subscription", ()), "id") if a == "id" else
                                          Member(Call("subscription", ()), "subscriptionId")
                                          if a == "subscription_id" else None),
    "azurerm_virtual_network": _lookup("Microsoft.Network/virtualNetworks", NETWORK, {"id": "id", "name": "name"}),
    "azurerm_subnet": _subnet,
    "azurerm_key_vault": _lookup("Microsoft.KeyVault/vaults", KEYVAULT, {"id": "id", "vault_uri": "vaultUri"}),
    "azurerm_key_vault_key": _vault_key,
    "azurerm_public_ip": _lookup("Microsoft.Network/publicIPAddresses", NETWORK,
                                 {"id": "id", "ip_address": "ipAddress"}),
    "azurerm_private_dns_zone": _lookup("Microsoft.Network/privateDnsZones", PRIVATE_DNS, {"id": "id"}),
    "azurerm_storage_account": _lookup("Microsoft.Storage/storageAccounts", STORAGE, {"id": "id", "name": "name"}),
    "azurerm_log_analytics_workspace": _lookup("Microsoft.OperationalInsights/workspaces", OPINSIGHTS,
                                               {"id": "id", "workspace_id": "customerId", "location": "location"}),
    "azurerm_kubernetes_cluster": _lookup("Microsoft.ContainerService/managedClusters", AKS,
                                          {"id": "id", "oidc_issuer_url": "oidcIssuerProfile.issuerURL"}),
    "azurerm_role_definition": lambda f, a: (Computed(lambda f, value: _role_definition(value(f["name"]),
                                                                                         "data.azurerm_role_definition"))
                                             if a in ("id", "role_definition_id") else None),
    # a built-in policy definition by its GUID name (organization-wide Defender, 5.7b): its id; its roles are read
    # only by the management group's part, which stays Terraform (KEPT)
    "azurerm_policy_definition": lambda f, a: (Computed(lambda f, value: "/providers/Microsoft.Authorization/"
                                                        f"policyDefinitions/{value(f.get('name'))}")
                                               if a == "id" else None),
    "azurerm_policy_set_definition": lambda f, a: (Computed(lambda f, value: _initiative(
        value(f.get("display_name", f.get("name"))), "data.azurerm_policy_set_definition")) if a == "id" else None),
    "azapi_resource": lambda f, a: (Lookup(Existing(f["type"].split("@")[0], f["type"].split("@")[1],
                                                    f["resource_id"].rsplit("/", 1)[1],
                                                    f["resource_id"].split("/resourceGroups/")[1].split("/")[0]),
                                           a[len("output."):]) if a.startswith("output.") else None),
    "azurerm_key_vault_secret": lambda f, a: (
        Secure(f"Key Vault secret {f.get('name')}: the deployment fills it from the vault (parameters file "
               "reference / getSecret)") if a == "value" else None),
}


# ------------------------------------------------------------------ network

NSG_RULE = {"description": "description", "priority": "priority", "direction": "direction", "access": "access",
            "protocol": "protocol", "source_port_range": "sourcePortRange", "source_port_ranges": "sourcePortRanges",
            "destination_port_range": "destinationPortRange", "destination_port_ranges": "destinationPortRanges",
            "source_address_prefix": "sourceAddressPrefix", "source_address_prefixes": "sourceAddressPrefixes",
            "destination_address_prefix": "destinationAddressPrefix",
            "destination_address_prefixes": "destinationAddressPrefixes",
            "name": None, "resource_group_name": None, "network_security_group_name": None}
BASE = {"name": None, "resource_group_name": None, "location": "location"}


def _ip_configuration(v, cx):
    return {"ipConfigurations": [{"name": cx.value(c["name"]), "properties": obj(
        {k: x for k, x in c.items() if k != "name"}, cx, {
            "subnet_id": Custom(lambda x, c: {"subnet": {"id": c.value(x)}}),
            "private_ip_address_allocation": "privateIPAllocationMethod",
            "private_ip_address": "privateIPAddress", "primary": "primary"}, f"{cx.where}.ip_configuration")}
        for c in v]}


def _rule(props, f, cx):
    """An NSG rule, inline in its group's securityRules (a group's PUT replaces the array: rules as child resources
    would be removed by the group's next deployment)."""
    return {**props, "securityRules": [*props.get("securityRules", []), {
        "name": cx.value(f["name"]), "properties": obj(own(f), cx, NSG_RULE)}]}


def _sub_id(path, key="name"):
    """A merged child's id: its parent's id and path/<its name> (FromBlock: the parent's symbol, the child's
    Fields)."""
    return FromBlock(lambda nid, f: Interp((ResourceId(nid), f"/{path}/{f[key]}")))


def _lb(f, cx):
    """A load balancer: its frontend configurations inline (zones beside each one's properties)."""
    rest = {k: v for k, v in own(f).items() if k != "frontend_ip_configuration"}
    frontends = [{"name": cx.value(c["name"]), **({"zones": cx.value(c["zones"])} if "zones" in c else {}),
                  "properties": obj({k: x for k, x in c.items() if k not in ("name", "zones")}, cx, {
                      "subnet_id": Custom(lambda x, c2: {"subnet": {"id": c2.value(x)}}),
                      "private_ip_address_allocation": "privateIPAllocationMethod",
                      "private_ip_address": "privateIPAddress",
                      "public_ip_address_id": Custom(lambda x, c2: {"publicIPAddress": {"id": c2.value(x)}})},
                      f"{cx.where}.frontend_ip_configuration")}
                 for c in f.get("frontend_ip_configuration", ())]
    return {**obj(rest, cx, {**BASE, "sku": Custom(lambda v, c: {"sku": {"name": c.value(v)}})}),
            "frontendIPConfigurations": frontends}


def _lb_child(key, spec):
    """Merge.into: a load balancer child (pool, probe, rule) inline in the balancer's array key (its PUT replaces
    the arrays)."""
    def into(props, f, cx):
        body = obj({k: v for k, v in own(f).items() if k not in ("name", "loadbalancer_id")}, cx, spec)
        return {**props, key: [*props.get(key, []), {"name": cx.value(f["name"]), **({"properties": body}
                                                                                    if body else {})}]}
    return into


def _lb_rule_frontend(v, cx):
    return {"frontendIPConfiguration": {"id": cx.value(v)}}


def _nic_pool(props, f, cx):
    """A NIC's backend pool association: the pool on the named ip configuration."""
    name, pool = cx.value(f["ip_configuration_name"]), cx.value(f["backend_address_pool_id"])
    configs = [{**c, "properties": {**c["properties"], "loadBalancerBackendAddressPools": [
        *c["properties"].get("loadBalancerBackendAddressPools", []), {"id": pool}]}} if c["name"] == name else c
        for c in props["ipConfigurations"]]
    return {**props, "ipConfigurations": configs}


# ------------------------------------------------------------------ compute

def _identity(v, cx):
    """An identity block as ARM's identity: its type, user-assigned identities keyed by id."""
    b = v[0]
    ids = cx.value(b.get("identity_ids", ()))
    return {"identity": {"type": cx.value(b["type"]),
                         **({"userAssignedIdentities": {i: {} for i in ids}} if ids else {})}}


def _managed(disk, cx):
    """A disk block's managedDisk: its type and disk encryption set."""
    return {"storageAccountType": cx.value(disk["storage_account_type"]),
            **({"diskEncryptionSet": {"id": cx.value(disk["disk_encryption_set_id"])}}
               if "disk_encryption_set_id" in disk else {})}


def _os_disk(f, cx):
    """A VM's or scale set's os_disk as ARM's osDisk (from its image)."""
    disk = one(f, "os_disk")
    unknown = sorted(set(disk) - {"caching", "storage_account_type", "disk_encryption_set_id", "disk_size_gb"})
    if unknown:
        raise SystemExit(f"{cx.where}.os_disk: no ARM form for {', '.join(unknown)}")
    return {"createOption": "FromImage", "caching": cx.value(disk["caching"]), "managedDisk": _managed(disk, cx),
            **({"diskSizeGB": cx.value(disk["disk_size_gb"])} if "disk_size_gb" in disk else {})}


def _linux(f, cx, name_key):
    """An osProfile for SSH keys only (password authentication off), its computer name under name_key."""
    user = cx.value(f["admin_username"])
    keys = [{"path": f"/home/{user}/.ssh/authorized_keys", "keyData": cx.value(k["public_key"])}
            for k in f.get("admin_ssh_key", ())]
    return {name_key: cx.value(f.get("computer_name", f["name"])), "adminUsername": user,
            "linuxConfiguration": {"disablePasswordAuthentication": True, "ssh": {"publicKeys": keys}}}


def _vm(f, cx):
    """A Linux virtual machine: hardware, OS profile (SSH keys only), storage (image, OS disk), NICs."""
    rest = {k: v for k, v in own(f).items() if k not in ("admin_ssh_key", "os_disk", "admin_username", "size",
                                                         "computer_name", "network_interface_ids",
                                                         "source_image_id")}
    return {**obj(rest, cx, {**BASE, "zone": Custom(lambda v, c: {"zones": [c.value(v)]}),
                             "identity": Custom(_identity)}),
            "hardwareProfile": {"vmSize": cx.value(f["size"])},
            "osProfile": _linux(f, cx, "computerName"),
            "storageProfile": {"imageReference": {"id": cx.value(f["source_image_id"])}, "osDisk": _os_disk(f, cx)},
            "networkProfile": {"networkInterfaces": [{"id": i} for i in cx.value(f["network_interface_ids"])]}}


SCALE_SET_DATA_DISK = {"lun": "lun", "caching": "caching", "create_option": "createOption",
                       "disk_size_gb": "diskSizeGB", "disk_iops_read_write": "diskIOPSReadWrite",
                       "disk_mbps_read_write": "diskMBpsReadWrite", "storage_account_type": None,
                       "disk_encryption_set_id": None}


def _scale_set_disk(d, cx):
    return {**obj(d, cx, SCALE_SET_DATA_DISK, f"{cx.where}.data_disk"), "managedDisk": _managed(d, cx)}


def _ids(name):
    """A list of IDs as ARM's [{id}, ...] under name."""
    return Custom(lambda v, cx: {name: [{"id": i} for i in cx.value(v)]})


IP_CONFIGURATION = {"name": None, "primary": "primary",
                    "subnet_id": Custom(lambda v, cx: {"subnet": {"id": cx.value(v)}}),
                    "load_balancer_backend_address_pool_ids": _ids("loadBalancerBackendAddressPools"),
                    "application_gateway_backend_address_pool_ids": _ids("applicationGatewayBackendAddressPools")}


def _set_ip_configuration(c, cx):
    return {"name": cx.value(c["name"]),
            "properties": obj(c, cx, IP_CONFIGURATION, f"{cx.where}.ip_configuration")}


def _interface(n, cx):
    return {"name": cx.value(n["name"]), "properties": {
        **obj({k: v for k, v in n.items() if k != "ip_configuration"}, cx, {
            "name": None, "primary": "primary",
            "network_security_group_id": Custom(lambda v, x: {"networkSecurityGroup": {"id": x.value(v)}})},
              f"{cx.where}.network_interface"),
        "ipConfigurations": [_set_ip_configuration(c, cx) for c in n.get("ip_configuration", ())]}}


def _scale_set(f, cx):
    """A Linux virtual machine scale set (Uniform orchestration, manual upgrades: Terraform's defaults): its size and
    instance count as its sku, zones, identity, and the virtual machine profile (OS profile with SSH keys, image, OS
    and data disks, network interfaces with their backend pools)."""
    rest = {k: v for k, v in own(f).items() if k not in ("admin_ssh_key", "os_disk", "data_disk", "admin_username",
                                                         "sku", "instances", "source_image_id", "network_interface",
                                                         "computer_name_prefix")}
    return {**obj(rest, cx, {**BASE, "zones": "zones", "identity": Custom(_identity)}),
            "sku": {"name": cx.value(f["sku"]), "tier": "Standard", "capacity": cx.value(f.get("instances", 0))},
            "orchestrationMode": "Uniform", "upgradePolicy": {"mode": "Manual"},
            "virtualMachineProfile": {
                "osProfile": _linux({**f, "computer_name": f.get("computer_name_prefix", f["name"])}, cx,
                                    "computerNamePrefix"),
                "storageProfile": {"imageReference": {"id": cx.value(f["source_image_id"])},
                                   "osDisk": _os_disk(f, cx),
                                   **({"dataDisks": [_scale_set_disk(d, cx) for d in f["data_disk"]]}
                                      if f.get("data_disk") else {})},
                "networkProfile": {"networkInterfaceConfigurations": [_interface(n, cx)
                                                                      for n in f.get("network_interface", ())]}}}


def _text(v):
    """A number as ARM's string ('2'), an expression as string(...) of it."""
    return str(v) if isinstance(v, (int, str)) else Call("string", (v,))


def _autoscale(f, cx):
    """An autoscale setting: its profiles' capacity (ARM's counts are strings), no rules (the record holds a range,
    not when to move in it), on its target."""
    def profile(p):
        c = one(p, "capacity")
        return {"name": cx.value(p["name"]), "capacity": {k: _text(cx.value(c[k])) for k in ("default", "minimum",
                                                                                           "maximum")},
                "rules": []}
    unknown = sorted(k for p in f.get("profile", ()) for k in p if k not in ("name", "capacity"))
    if unknown:
        raise SystemExit(f"{cx.where}.profile: no ARM form for {', '.join(unknown)}")
    return {**obj({k: v for k, v in own(f).items() if k not in ("profile", "target_resource_id", "enabled")}, cx,
                  BASE),
            "name": cx.value(f["name"]), "enabled": cx.value(f.get("enabled", True)),
            "targetResourceUri": cx.value(f["target_resource_id"]),
            "profiles": [profile(p) for p in f.get("profile", ())]}


def _data_disk(props, f, cx):
    """A data disk attachment: the disk in the VM's storageProfile.dataDisks (attached when the VM deploys)."""
    disk = {"lun": cx.value(f["lun"]), "createOption": "Attach", "caching": cx.value(f.get("caching", "None")),
            "managedDisk": {"id": cx.value(f["managed_disk_id"])}}
    storage = props["storageProfile"]
    return {**props, "storageProfile": {**storage, "dataDisks": [*storage.get("dataDisks", []), disk]}}


def _disk(f, cx):
    return obj(own(f), cx, {
        **BASE, "zone": Custom(lambda v, c: {"zones": [c.value(v)]}),
        "storage_account_type": Custom(lambda v, c: {"sku": {"name": c.value(v)}}),
        "create_option": Custom(lambda v, c: {"creationData": {"createOption": c.value(v)}}),
        "disk_size_gb": "diskSizeGB", "disk_iops_read_write": "diskIOPSReadWrite",
        "disk_mbps_read_write": "diskMBpsReadWrite",
        "disk_encryption_set_id": Custom(lambda v, c: {"encryption": {
            "type": "EncryptionAtRestWithCustomerKey", "diskEncryptionSetId": c.value(v)}})})


# ------------------------------------------------------------------ storage

def _account(f, cx):
    """A storage account: kind StorageV2 (Terraform's default), sku of tier and replication; its blob service's
    settings are the blobServices/default child (expansion)."""
    rest = {k: v for k, v in own(f).items() if k not in ("account_tier", "account_replication_type",
                                                         "blob_properties")}
    return {"kind": "StorageV2", "sku": {"name": f"{cx.value(f['account_tier'])}_"
                                                f"{cx.value(f['account_replication_type'])}"},
            **obj(rest, cx, {**BASE, "account_kind": "kind", "min_tls_version": "minimumTlsVersion",
                             "https_traffic_only_enabled": "supportsHttpsTrafficOnly",
                             "allow_nested_items_to_be_public": "allowBlobPublicAccess",
                             "public_network_access_enabled": Custom(lambda v, c: {
                                 "publicNetworkAccess": "Enabled" if v else "Disabled"}),
                             "identity": Custom(_identity)})}


def _blob_service(lid, f, cx):
    """A storage account's blob service (always: its containers are its children), with the blob settings."""
    settings = obj(one(f, "blob_properties"), cx, {
        "versioning_enabled": "isVersioningEnabled",
        "change_feed_enabled": Custom(lambda v, c: {"changeFeed": {"enabled": c.value(v)}})},
        f"{cx.where}.blob_properties")
    return (("blob", Arm("Microsoft.Storage/storageAccounts/blobServices", STORAGE, Parent("", ""),
                         Fixed("default"), fields=()), {**settings}),)


def _key_reference(cx, key_ref):
    """(vault URI, key name) of a key a reference names (data.azurerm_key_vault_key.<name>.<attr>): the key's vault
    lookup's vaultUri and the key's name."""
    r = key_ref[2:-1].split(".") if isinstance(key_ref, str) and key_ref.startswith("${data.") else None
    block = cx.block(".".join(r[:3])) if r else None
    if block is None:
        raise SystemExit(f"{cx.where}: no ARM form for the key {key_ref!r} (a Key Vault key lookup expected)")
    key = dict(block.body)
    return cx.value(key["key_vault_id"].replace(".id}", ".vault_uri}")), cx.value(key["name"])


def _account_key(props, f, cx):
    """A storage account's customer-managed key: its encryption, by Key Vault and the user-assigned identity."""
    vault, name = _key_reference(cx, f["key_vault_key_id"])
    unknown = sorted(set(own(f)) - {"storage_account_id", "key_vault_key_id", "user_assigned_identity_id"})
    if unknown:
        raise SystemExit(f"{cx.where}: no ARM form for {', '.join(unknown)}")
    return {**props, "encryption": {"keySource": "Microsoft.Keyvault",
                                    "keyvaultproperties": {"keyvaulturi": vault, "keyname": name},
                                    "identity": {"userAssignedIdentity": cx.value(f["user_assigned_identity_id"])},
                                    "services": {"blob": {"enabled": True, "keyType": "Account"},
                                                 "file": {"enabled": True, "keyType": "Account"}}}}


def _management_rules(v, cx):
    def rule(r):
        filters = one(r, "filters")
        actions = one(r, "actions")
        base, version = one(actions, "base_blob"), one(actions, "version")
        days = {"tier_to_cool_after_days_since_modification_greater_than": ("tierToCool",
                                                                            "daysAfterModificationGreaterThan"),
                "tier_to_cold_after_days_since_modification_greater_than": ("tierToCold",
                                                                            "daysAfterModificationGreaterThan"),
                "tier_to_archive_after_days_since_modification_greater_than": ("tierToArchive",
                                                                               "daysAfterModificationGreaterThan"),
                "delete_after_days_since_modification_greater_than": ("delete", "daysAfterModificationGreaterThan"),
                "delete_after_days_since_creation": ("delete", "daysAfterCreationGreaterThan")}
        unknown = sorted((set(base) | set(version)) - set(days))
        if unknown:
            raise SystemExit(f"{cx.where}.rule: no ARM form for {', '.join(unknown)}")
        return {"name": cx.value(r["name"]), "enabled": cx.value(r.get("enabled", True)), "type": "Lifecycle",
                "definition": {"filters": obj(filters, cx, {"blob_types": "blobTypes", "prefix_match": "prefixMatch"},
                                              f"{cx.where}.rule.filters"),
                               "actions": {**({"baseBlob": {days[k][0]: {days[k][1]: cx.value(x)}
                                                            for k, x in base.items()}} if base else {}),
                                           **({"version": {days[k][0]: {days[k][1]: cx.value(x)}
                                                           for k, x in version.items()}} if version else {})}}}
    return {"policy": {"rules": [rule(r) for r in v]}}


# ------------------------------------------------------------------ databases

SKU_TIERS = {"B": "Burstable", "GP": "GeneralPurpose", "MO": "MemoryOptimized"}


def _flexible(dns_key):
    """A flexible server (PostgreSQL's, MySQL's): sku from Terraform's tier-prefixed name, storage in GB (PostgreSQL's
    storage_mb, MySQL's storage block), backups (retention, geo-redundancy), a zone-redundant standby, its network
    (the private DNS zone under dns_key, as each engine names it), the write-only administrator password (an
    ephemeral secret: a secure parameter), its customer-managed key."""
    def props(f, cx):
        tier, _, sku = cx.value(f["sku_name"]).partition("_") if "sku_name" in f else (None, None, None)
        key, ha = one(f, "customer_managed_key"), one(f, "high_availability")
        backup = {**({"backupRetentionDays": cx.value(f["backup_retention_days"])} if "backup_retention_days" in f
                     else {}),
                  **({"geoRedundantBackup": "Enabled" if cx.value(f["geo_redundant_backup_enabled"]) else "Disabled"}
                     if "geo_redundant_backup_enabled" in f else {})}
        network = {**({"delegatedSubnetResourceId": cx.value(f["delegated_subnet_id"])}
                      if "delegated_subnet_id" in f else {}),
                   **({dns_key: cx.value(f["private_dns_zone_id"])} if "private_dns_zone_id" in f else {}),
                   **({"publicNetworkAccess": "Enabled" if f["public_network_access_enabled"] else "Disabled"}
                      if "public_network_access_enabled" in f else {})}
        return {**({"sku": {"name": sku, "tier": SKU_TIERS[tier]}} if sku else {}),
                **obj({k: v for k, v in own(f).items() if k not in (
                    "sku_name", "customer_managed_key", "backup_retention_days", "geo_redundant_backup_enabled",
                    "high_availability", "delegated_subnet_id", "private_dns_zone_id",
                    "public_network_access_enabled")}, cx, {
                    **BASE, "version": "version", "zone": "availabilityZone",
                    "administrator_login": "administratorLogin",
                    "administrator_password_wo": "administratorLoginPassword",
                    "administrator_password_wo_version": None,
                    "storage_mb": Custom(lambda v, c: {"storage": {"storageSizeGB": c.value(v) // 1024}}),
                    "storage": Custom(lambda v, c: {"storage": obj(v[0], c, {"size_gb": "storageSizeGB"},
                                                                   f"{c.where}.storage")}),
                    "identity": Custom(_identity)}),
                **({"backup": backup} if backup else {}),
                **({"highAvailability": obj(ha, cx, {"mode": "mode", "standby_availability_zone":
                                                     "standbyAvailabilityZone"}, f"{cx.where}.high_availability")}
                   if ha else {}),
                "network": network,
                **({"dataEncryption": {"type": "AzureKeyVault", "primaryKeyURI": cx.value(key["key_vault_key_id"]),
                                       "primaryUserAssignedIdentityId": cx.value(
                                           key["primary_user_assigned_identity_id"])}} if key else {})}
    return props


def _configuration(type_, api, server, by="id"):
    """A server parameter, user-set (the configurations child of either engine's flexible server: PostgreSQL's names
    its server by ID, MySQL's by name in its resource group)."""
    parent = Parent("server_id", server) if by == "id" else Parent("server_name", server, "name")
    return Native(Arm(type_, api, parent), {
        "name": None, "server_id": None, "server_name": None, "resource_group_name": None,
        "value": Custom(lambda v, cx: {"value": cx.value(v), "source": "user-override"})},
        {"id": "id"}, "name")


# ------------------------------------------------------------------ monitoring

def _streams(v, cx):
    return {"streamDeclarations": {cx.value(b["stream_name"]): {"columns": [
        {"name": cx.value(c["name"]), "type": cx.value(c["type"])} for c in b.get("column", ())]} for b in v}}


def _dcr(f, cx):
    """A data collection rule: destinations, data sources (log files, extensions), stream declarations, flows."""
    dest = one(f, "destinations")
    sources = one(f, "data_sources")
    return obj(own(f), cx, {
        **BASE, "description": "description", "kind": "kind",
        "data_collection_endpoint_id": "dataCollectionEndpointId",
        "destinations": Custom(lambda v, c: {"destinations": {"logAnalytics": [
            {"name": c.value(x["name"]), "workspaceResourceId": c.value(x["workspace_resource_id"])}
            for x in dest.get("log_analytics", ())]}}),
        "data_sources": Custom(lambda v, c: {"dataSources": {
            **({"logFiles": [{"name": c.value(x["name"]), "filePatterns": c.value(x["file_patterns"]),
                              "format": c.value(x["format"]), "streams": c.value(x["streams"])}
                             for x in sources["log_file"]]} if "log_file" in sources else {}),
            **({"extensions": [{"name": c.value(x["name"]), "extensionName": c.value(x["extension_name"]),
                                "streams": c.value(x["streams"]),
                                **({"extensionSettings": c.value(x["extension_json"])}
                                   if "extension_json" in x else {})}
                               for x in sources["extension"]]} if "extension" in sources else {})}}),
        "stream_declaration": Custom(_streams),
        "data_flow": Nest("dataFlows", {"streams": "streams", "destinations": "destinations",
                                        "transform_kql": "transformKql", "output_stream": "outputStream"}, True)})


def _metric_alert(f, cx):
    """A metric alert (location global): its criteria (named Metric<n>, as azurerm names them) and action groups."""
    scopes = cx.value(f["scopes"])
    kind = "Single" if len(scopes) == 1 else "Multiple"
    criteria = [{"name": f"Metric{i + 1}", "criterionType": "StaticThresholdCriterion", **obj(c, cx, {
        "metric_namespace": "metricNamespace", "metric_name": "metricName", "aggregation": "timeAggregation",
        "operator": "operator", "threshold": "threshold"}, f"{cx.where}.criteria")}
        for i, c in enumerate(f.get("criteria", ()))]
    return {"location": "global", "enabled": True, **obj({k: v for k, v in own(f).items() if k != "criteria"}, cx, {
        "name": None, "resource_group_name": None, "description": "description", "severity": "severity",
        "enabled": "enabled", "scopes": "scopes", "frequency": "evaluationFrequency", "window_size": "windowSize",
        "target_resource_type": "targetResourceType", "target_resource_location": "targetResourceRegion",
        "auto_mitigate": "autoMitigate",
        "action": Custom(lambda v, c: {"actions": [{"actionGroupId": c.value(a["action_group_id"])} for a in v]})}),
        "criteria": {"odata.type": f"Microsoft.Azure.Monitor.{kind}ResourceMultipleMetricCriteria",
                     "allOf": criteria}}


def _query_alert(f, cx):
    return obj(own(f), cx, {
        **BASE, "description": "description", "severity": "severity", "enabled": "enabled", "scopes": "scopes",
        "evaluation_frequency": "evaluationFrequency", "window_duration": "windowSize",
        "criteria": Custom(lambda v, c: {"criteria": {"allOf": [obj(x, c, {
            "query": "query", "time_aggregation_method": "timeAggregation", "operator": "operator",
            "threshold": "threshold"}, f"{c.where}.criteria") for x in v]}}),
        "action": Custom(lambda v, c: {"actions": {"actionGroups": c.value(v[0]["action_groups"])}})})

# ------------------------------------------------------------------ edge and private connectivity

def _self_child(cx, path, name):
    """The id of a named part of the resource being translated (an application gateway's listener, pool, ...)."""
    return {"id": Interp((ResourceId(cx.logical(cx.where)), f"/{path}/{name}"))}


def _named(v, cx, spec, where, extra=lambda b: {}):
    """Named blocks as ARM's [{name, properties}] (spec over each block's other attributes)."""
    return [{"name": cx.value(b["name"]), "properties": {**obj({k: x for k, x in b.items() if k not in
                                                                ("name",) + tuple(extra(b).get("_skip", ()))},
                                                               cx, spec, f"{cx.where}.{where}"),
                                                           **{k: x for k, x in extra(b).items() if k != "_skip"}}}
            for b in v]


def _gateway(f, cx):
    """An application gateway: its parts inline (its PUT replaces them), cross-references between them as ids of the
    gateway's named parts."""
    def ref(path):
        return Custom(lambda v, c: {_REF_KEYS[path]: _self_child(c, path, c.value(v))})
    policy = {"policy_type": "policyType", "policy_name": "policyName", "min_protocol_version": "minProtocolVersion",
              "cipher_suites": "cipherSuites"}
    def ssl_policy(where):
        return Custom(lambda v, c: {"sslPolicy": obj(v[0], c, policy, f"{c.where}.{where}")})
    def client_auth(b):
        """An SSL profile's clientAuthConfiguration from its Terraform attributes."""
        return {"clientAuthConfiguration": {
            "verifyClientAuthMode": cx.value(b.get("client_authentication_mode", "Strict")),
            "verifyClientCertIssuerDN": cx.value(b.get("verify_client_certificate_issuer_dn", False)),
            **({"verifyClientRevocation": cx.value(b["verify_client_certificate_revocation"])}
               if "verify_client_certificate_revocation" in b else {})}}
    header = {"header_name": "headerName", "header_value": "headerValue"}
    rule = {"name": "name", "rule_sequence": "ruleSequence",
            "request_header_configuration": Custom(lambda v, c: {"actionSet": {"requestHeaderConfigurations": [
                obj(h, c, header, f"{c.where}.rewrite_rule") for h in v]}})}
    parts = {
        "gateway_ip_configuration": ("gatewayIPConfigurations", {"subnet_id": Custom(
            lambda v, c: {"subnet": {"id": c.value(v)}})}),
        "frontend_ip_configuration": ("frontendIPConfigurations", {
            "public_ip_address_id": Custom(lambda v, c: {"publicIPAddress": {"id": c.value(v)}}),
            "subnet_id": Custom(lambda v, c: {"subnet": {"id": c.value(v)}}),
            "private_ip_address": "privateIPAddress",
            "private_ip_address_allocation": "privateIPAllocationMethod"}),
        "frontend_port": ("frontendPorts", {"port": "port"}),
        "backend_address_pool": ("backendAddressPools", {"ip_addresses": Custom(lambda v, c: {"backendAddresses": [
            {"ipAddress": x} for x in c.value(v)]}), "fqdns": Custom(lambda v, c: {"backendAddresses": [
                {"fqdn": x} for x in c.value(v)]})}),
        "backend_http_settings": ("backendHttpSettingsCollection", {
            "port": "port", "protocol": "protocol", "cookie_based_affinity": "cookieBasedAffinity",
            "request_timeout": "requestTimeout", "host_name": "hostName", "probe_name": ref("probes"),
            "pick_host_name_from_backend_address": "pickHostNameFromBackendAddress",
            "connection_draining": Custom(lambda v, c: {"connectionDraining": obj(v[0], c, {
                "enabled": "enabled", "drain_timeout_sec": "drainTimeoutInSec"}, f"{c.where}.connection_draining")}),
            "trusted_root_certificate_names": Custom(lambda v, c: {"trustedRootCertificates": [
                _self_child(c, "trustedRootCertificates", x) for x in c.value(v)]})}),
        "probe": ("probes", {"protocol": "protocol", "host": "host", "port": "port", "path": "path",
                             "interval": "interval", "timeout": "timeout", "unhealthy_threshold": "unhealthyThreshold",
                             "pick_host_name_from_backend_http_settings": "pickHostNameFromBackendHttpSettings",
                             "match": Custom(lambda v, c: {"match": {"statusCodes": c.value(v[0]["status_code"])}})}),
        "http_listener": ("httpListeners", {
            "frontend_ip_configuration_name": ref("frontendIPConfigurations"),
            "frontend_port_name": ref("frontendPorts"), "protocol": "protocol", "host_name": "hostName",
            "ssl_certificate_name": ref("sslCertificates"), "ssl_profile_name": ref("sslProfiles")}),
        "request_routing_rule": ("requestRoutingRules", {
            "priority": "priority", "rule_type": "ruleType", "http_listener_name": ref("httpListeners"),
            "backend_address_pool_name": ref("backendAddressPools"),
            "backend_http_settings_name": ref("backendHttpSettingsCollection"),
            "rewrite_rule_set_name": ref("rewriteRuleSets")}),
        "ssl_certificate": ("sslCertificates", {"key_vault_secret_id": "keyVaultSecretId"}),
        "trusted_root_certificate": ("trustedRootCertificates", {"key_vault_secret_id": "keyVaultSecretId"}),
        "trusted_client_certificate": ("trustedClientCertificates", {"data": "data"}),
        "ssl_profile": ("sslProfiles", {
            "trusted_client_certificate_names": Custom(lambda v, c: {"trustedClientCertificates": [
                _self_child(c, "trustedClientCertificates", x) for x in c.value(v)]}),
            "ssl_policy": ssl_policy("ssl_profile.ssl_policy"), "client_authentication_mode": None,
            "verify_client_certificate_issuer_dn": None, "verify_client_certificate_revocation": None}, client_auth),
        "rewrite_rule_set": ("rewriteRuleSets", {"rewrite_rule": Custom(lambda v, c: {"rewriteRules": [
            obj(r, c, rule, f"{c.where}.rewrite_rule_set") for r in v]})})}
    found = {key: _named(f[tf], cx, spec, tf, *extra) for tf, (key, spec, *extra) in parts.items() if tf in f}
    rest = {k: v for k, v in own(f).items() if k not in parts}
    return {**found, **obj(rest, cx, {
        **BASE, "zones": "zones", "identity": Custom(_identity),
        "sku": Custom(lambda v, c: {"sku": obj(v[0], c, {"name": "name", "tier": "tier", "capacity": "capacity"},
                                                f"{c.where}.sku")}),
        "autoscale_configuration": Custom(lambda v, c: {"autoscaleConfiguration": obj(v[0], c, {
            "min_capacity": "minCapacity", "max_capacity": "maxCapacity"}, f"{c.where}.autoscale_configuration")}),
        "ssl_policy": ssl_policy("ssl_policy"),
        "firewall_policy_id": Custom(lambda v, c: {"firewallPolicy": {"id": c.value(v)}}),
        "enable_http2": "enableHttp2"})}


_REF_KEYS = {"probes": "probe", "frontendIPConfigurations": "frontendIPConfiguration",
             "frontendPorts": "frontendPort", "sslCertificates": "sslCertificate", "httpListeners": "httpListener",
             "backendAddressPools": "backendAddressPool", "backendHttpSettingsCollection": "backendHttpSettings",
             "sslProfiles": "sslProfile", "rewriteRuleSets": "rewriteRuleSet"}


def _waf_policy(f, cx):
    """An application gateway WAF policy: settings, custom rules, managed rules (exclusions, rule sets)."""
    settings = one(f, "policy_settings")
    managed = one(f, "managed_rules")

    def condition(c):
        return {"matchVariables": [obj(x, cx, {"variable_name": "variableName", "selector": "selector"},
                                       f"{cx.where}.match_variables") for x in c.get("match_variables", ())],
                **obj({k: v for k, v in c.items() if k != "match_variables"}, cx, {
                    "operator": "operator", "match_values": "matchValues", "negation_condition": "negationConditon",
                    "transforms": "transforms"}, f"{cx.where}.match_conditions")}

    def rule(r):
        rest = {k: v for k, v in r.items() if k not in ("match_conditions", "group_rate_limit_by")}
        return {**obj(rest, cx, {"name": "name", "priority": "priority", "rule_type": "ruleType",
                                 "rate_limit_duration": "rateLimitDuration",
                                 "rate_limit_threshold": "rateLimitThreshold", "action": "action",
                                 "enabled": Custom(lambda v, c: {"state": "Enabled" if v else "Disabled"})},
                    f"{cx.where}.custom_rules"),
                **({"groupByUserSession": [{"groupByVariables": [{"variableName": cx.value(r["group_rate_limit_by"])}
                                                                 ]}]} if "group_rate_limit_by" in r else {}),
                "matchConditions": [condition(c) for c in r.get("match_conditions", ())]}

    def exclusion(e):
        return {**obj({k: v for k, v in e.items() if k != "excluded_rule_set"}, cx, {
            "match_variable": "matchVariable", "selector": "selector",
            "selector_match_operator": "selectorMatchOperator"}, f"{cx.where}.exclusion"),
            **({"exclusionManagedRuleSets": [obj(x, cx, {"type": "ruleSetType", "version": "ruleSetVersion"},
                                                 f"{cx.where}.excluded_rule_set")
                                             for x in e["excluded_rule_set"]]} if "excluded_rule_set" in e else {})}
    return {**obj({k: v for k, v in own(f).items() if k not in ("policy_settings", "custom_rules", "managed_rules")},
                  cx, BASE),
            "policySettings": {**obj({k: v for k, v in settings.items() if k != "enabled"}, cx, {
                "mode": "mode", "request_body_check": "requestBodyCheck",
                "max_request_body_size_in_kb": "maxRequestBodySizeInKb", "file_upload_limit_in_mb":
                "fileUploadLimitInMb"}, f"{cx.where}.policy_settings"),
                "state": "Enabled" if settings.get("enabled", True) else "Disabled"},
            "customRules": [rule(r) for r in f.get("custom_rules", ())],
            "managedRules": {"exclusions": [exclusion(e) for e in managed.get("exclusion", ())],
                             "managedRuleSets": [obj(x, cx, {"type": "ruleSetType", "version": "ruleSetVersion"},
                                                     f"{cx.where}.managed_rule_set")
                                                 for x in managed.get("managed_rule_set", ())]}}


def _private_endpoint(f, cx):
    connections = [{"name": cx.value(c["name"]), "properties": obj(
        {k: v for k, v in c.items() if k not in ("name", "is_manual_connection")}, cx, {
            "private_connection_resource_id": "privateLinkServiceId", "subresource_names": "groupIds",
            "request_message": "requestMessage"}, f"{cx.where}.private_service_connection")}
        for c in f.get("private_service_connection", ())]
    manual = any(c.get("is_manual_connection") for c in f.get("private_service_connection", ()))
    return {**obj({k: v for k, v in own(f).items() if k not in ("private_service_connection",
                                                                "private_dns_zone_group")}, cx, {
        **BASE, "subnet_id": Custom(lambda v, c: {"subnet": {"id": c.value(v)}}),
        "custom_network_interface_name": "customNetworkInterfaceName",
        "ip_configuration": Custom(lambda v, c: {"ipConfigurations": _named(v, c, {
            "private_ip_address": "privateIPAddress", "subresource_name": "groupId", "member_name": "memberName"},
            "ip_configuration")})}),
        ("manualPrivateLinkServiceConnections" if manual else "privateLinkServiceConnections"): connections}


def _dns_zone_group(lid, f, cx):
    """A private endpoint's DNS zone group: its child."""
    return tuple(("zones", Arm("Microsoft.Network/privateEndpoints/privateDnsZoneGroups", NETWORK, Parent("", "")),
                  {"name": cx.value(g["name"]), "privateDnsZoneConfigs": [
                      {"name": z.rsplit("/", 1)[-1].replace(".", "-") if isinstance(z, str) else "zone",
                       "properties": {"privateDnsZoneId": z}} for z in cx.value(g["private_dns_zone_ids"])]})
                 for g in f.get("private_dns_zone_group", ()))


def _link_service(f, cx):
    return obj(own(f), cx, {
        **BASE,
        "load_balancer_frontend_ip_configuration_ids": Custom(lambda v, c: {"loadBalancerFrontendIpConfigurations": [
            {"id": x} for x in c.value(v)]}),
        "nat_ip_configuration": Custom(lambda v, c: {"ipConfigurations": _named(v, c, {
            "primary": "primary", "subnet_id": Custom(lambda x, c2: {"subnet": {"id": c2.value(x)}}),
            "private_ip_address": "privateIPAddress",
            "private_ip_address_version": "privateIPAddressVersion"}, "nat_ip_configuration")}),
        "visibility_subscription_ids": Custom(lambda v, c: {"visibility": {"subscriptions": c.value(v)}}),
        "auto_approval_subscription_ids": Custom(lambda v, c: {"autoApproval": {"subscriptions": c.value(v)}}),
        "enable_proxy_protocol": "enableProxyProtocol"})


_RULES = {   # a collection's rules by their Terraform block: (ARM rule type, spec)
    "application_rule_collection": ("ApplicationRule", {
        "name": "name", "source_addresses": "sourceAddresses", "destination_fqdns": "targetFqdns",
        "destination_fqdn_tags": "fqdnTags", "description": "description",
        "protocols": Custom(lambda v, c: {"protocols": [{"protocolType": c.value(x["type"]),
                                                         "port": c.value(x["port"])} for x in v]})}),
    "network_rule_collection": ("NetworkRule", {
        "name": "name", "protocols": "ipProtocols", "source_addresses": "sourceAddresses",
        "destination_addresses": "destinationAddresses", "destination_fqdns": "destinationFqdns",
        "destination_ports": "destinationPorts", "description": "description"})}


def _rule_collection_group(f, cx):
    """A firewall policy rule collection group: its application and network rule collections (filter collections:
    application rules by host name for web ports, network rules by FQDN for the others)."""
    def collection(c, kind):
        rule_type, spec = _RULES[kind]
        return {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": cx.value(c["name"]),
                "priority": cx.value(c["priority"]), "action": {"type": cx.value(c["action"])},
                "rules": [{"ruleType": rule_type, **obj(r, cx, spec, f"{cx.where}.rule")} for r in c.get("rule", ())]}
    unknown = sorted(set(own(f)) - {"name", "firewall_policy_id", "priority", *_RULES})
    if unknown:
        raise SystemExit(f"{cx.where}: no ARM form for {', '.join(unknown)}")
    return {"priority": cx.value(f["priority"]),
            "ruleCollections": [collection(c, kind) for kind in _RULES for c in f.get(kind, ())]}


def _flow_log(f, cx):
    """A network watcher flow log (in the watcher's group): its target, storage, retention and traffic analytics."""
    analytics = one(f, "traffic_analytics")
    retention = one(f, "retention_policy")
    return {**obj({k: v for k, v in own(f).items() if k not in ("traffic_analytics", "retention_policy")}, cx, {
        "name": None, "network_watcher_name": None, "resource_group_name": None, "location": "location",
        "target_resource_id": "targetResourceId", "storage_account_id": "storageId", "enabled": "enabled",
        "version": Custom(lambda v, c: {"format": {"type": "JSON", "version": c.value(v)}})}),
        **({"retentionPolicy": obj(retention, cx, {"enabled": "enabled", "days": "days"},
                                   f"{cx.where}.retention_policy")} if retention else {}),
        **({"flowAnalyticsConfiguration": {"networkWatcherFlowAnalyticsConfiguration": obj(analytics, cx, {
            "enabled": "enabled", "workspace_id": "workspaceId", "workspace_region": "workspaceRegion",
            "workspace_resource_id": "workspaceResourceId", "interval_in_minutes": "trafficAnalyticsInterval"},
            f"{cx.where}.traffic_analytics")}} if analytics else {})}


# ------------------------------------------------------------------ backup and security automation

def _backup_vault(f, cx):
    return obj(own(f), cx, {
        **BASE, "identity": Custom(_identity),
        "datastore_type": None, "redundancy": None,
        "immutability": Custom(lambda v, c: {"securitySettings": {"immutabilitySettings": {"state": c.value(v)}}}),
        "soft_delete": Custom(lambda v, c: {"softDeleteSettings": {"state": c.value(v)}}),
        "retention_duration_in_days": None}) | {"storageSettings": [{
            "datastoreType": cx.value(f["datastore_type"]), "type": cx.value(f["redundancy"])}]}


def _backup_vault_key(props, f, cx):
    """A backup vault's customer-managed key: its encryption settings (the vault's system-assigned identity)."""
    security = props.get("securitySettings", {})
    return {**props, "securitySettings": {**security, "encryptionSettings": {
        "state": "Enabled", "keyVaultProperties": {"keyUri": cx.value(f["key_vault_key_id"])},
        "kekIdentity": {"identityType": "SystemAssigned"}, "infrastructureEncryption": "Disabled"}}}


def _disk_policy(f, cx):
    """A disk backup policy as azurerm builds it: an operational-store rule on the repeating intervals and a default
    retention rule."""
    store = {"dataStoreType": "OperationalStore", "objectType": "DataStoreInfoBase"}
    unknown = sorted(set(own(f)) - {"name", "vault_id", "backup_repeating_time_intervals",
                                     "default_retention_duration", "time_zone"})
    if unknown:
        raise SystemExit(f"{cx.where}: no ARM form for {', '.join(unknown)}")
    return {"objectType": "BackupPolicy", "datasourceTypes": ["Microsoft.Compute/disks"], "policyRules": [
        {"name": "BackupIntervals", "objectType": "AzureBackupRule",
         "backupParameters": {"objectType": "AzureBackupParams", "backupType": "Incremental"}, "dataStore": store,
         "trigger": {"objectType": "ScheduleBasedTriggerContext",
                     "schedule": {"repeatingTimeIntervals": cx.value(f["backup_repeating_time_intervals"]),
                                  **({"timeZone": cx.value(f["time_zone"])} if "time_zone" in f else {})},
                     "taggingCriteria": [{"isDefault": True, "taggingPriority": 99,
                                          "tagInfo": {"tagName": "Default"}}]}},
        {"name": "Default", "objectType": "AzureRetentionRule", "isDefault": True, "lifecycles": [
            {"deleteAfter": {"objectType": "AbsoluteDeleteOption",
                             "duration": cx.value(f["default_retention_duration"])},
             "sourceDataStore": store, "targetDataStoreCopySettings": []}]}]}


def _disk_instance(f, cx):
    """A disk backup instance: the disk as its data source, the policy with the snapshot resource group."""
    unknown = sorted(set(own(f)) - {"name", "location", "vault_id", "disk_id", "snapshot_resource_group_name",
                                     "backup_policy_id"})
    if unknown:
        raise SystemExit(f"{cx.where}: no ARM form for {', '.join(unknown)}")
    disk = cx.value(f["disk_id"])
    group = Call("subscriptionResourceId", ("Microsoft.Resources/resourceGroups",
                                            cx.value(f["snapshot_resource_group_name"])))
    return {"objectType": "BackupInstance", "dataSourceInfo": {
        "objectType": "Datasource", "datasourceType": "Microsoft.Compute/disks", "resourceID": disk,
        "resourceLocation": cx.value(f["location"]), "resourceType": "Microsoft.Compute/disks",
        "resourceUri": disk}, "policyInfo": {"policyId": cx.value(f["backup_policy_id"]), "policyParameters": {
            "dataStoreParametersList": [{"objectType": "AzureOperationalStoreParameters",
                                         "dataStoreType": "OperationalStore", "resourceGroupId": group}]}}}


# A continuous export's source: its event source and rule sets (an incident export's severity filter), as ARM names
# them (Microsoft.Security/automations' AutomationSource, AutomationRuleSet, AutomationTriggeringRule)
AUTOMATION_SOURCE = {"event_source": "eventSource", "rule_set": Nest("ruleSets", {"rule": Nest("rules", {
    "property_path": "propertyJPath", "property_type": "propertyType", "expected_value": "expectedValue",
    "operator": "operator"}, True)}, True)}


def _automation(f, cx):
    return obj(own(f), cx, {
        **BASE, "description": "description", "enabled": "isEnabled",
        "scopes": Custom(lambda v, c: {"scopes": [{"scopePath": x} for x in c.value(v)]}),
        "source": Custom(lambda v, c: {"sources": [obj(x, c, AUTOMATION_SOURCE, f"{c.where}.source") for x in v]}),
        "action": Custom(lambda v, c: {"actions": [{"actionType": c.value(x["type"]), **(
            {"workspaceResourceId": c.value(x["resource_id"])} if c.value(x["type"]) == "Workspace" else
            {"logicAppResourceId": c.value(x["resource_id"])} if c.value(x["type"]) == "LogicApp" else
            {"eventHubResourceId": c.value(x["resource_id"]),
             **({"connectionString": c.value(x["connection_string"])} if "connection_string" in x else {})})}
            for x in v]})})


def _contact(f, cx):
    """Defender's security contact in the API azurerm writes it with (email, phone, On/Off notifications)."""
    def on(name):
        return Custom(lambda v, c: {name: "On" if c.value(v) else "Off"})
    return obj(own(f), cx, {"name": None, "email": "email", "phone": "phone",
                            "alert_notifications": on("alertNotifications"), "alerts_to_admins": on("alertsToAdmins")})

# ------------------------------------------------------------------ access, subscription and tenant scope

AUTH = "2022-04-01"


def _pim(f, cx):
    """An eligible role assignment: an admin-assigned eligibility schedule request with its expiration."""
    expiration = one(one(f, "schedule"), "expiration")
    days, hours = expiration.get("duration_days"), expiration.get("duration_hours")
    return {"principalId": cx.value(f["principal_id"]), "roleDefinitionId": cx.value(f["role_definition_id"]),
            "requestType": "AdminAssign",
            **({"justification": cx.value(f["justification"])} if "justification" in f else {}),
            "scheduleInfo": {"expiration": {"type": "AfterDuration",
                                            "duration": f"P{days}D" if days else f"PT{hours}H"}
                             if days or hours else {"type": "NoExpiration"}}}


def _pricing(f, cx):
    return obj(own(f), cx, {
        "tier": "pricingTier", "resource_type": None, "subplan": "subPlan",
        "extension": Custom(lambda v, c: {"extensions": [{"name": c.value(x["name"]), "isEnabled": "True",
                                                          **({"additionalExtensionProperties": c.value(
                                                              x["additional_extension_properties"])}
                                                             if "additional_extension_properties" in x else {})}
                                                         for x in v]})})


def _logs(v, cx):
    return [{"category": cx.value(x["category"]), "enabled": True} for x in v]


def _diagnostic(f, cx):
    return obj(own(f), cx, {
        "name": None, "target_resource_id": None, "storage_account_id": "storageAccountId",
        "log_analytics_workspace_id": "workspaceId", "eventhub_authorization_rule_id": "eventHubAuthorizationRuleId",
        "eventhub_name": "eventHubName", "log_analytics_destination_type": "logAnalyticsDestinationType",
        "enabled_log": Custom(lambda v, c: {"logs": _logs(v, c)}),
        "metric": Custom(lambda v, c: {"metrics": [{"category": c.value(x.get("category", "AllMetrics")),
                                                    "enabled": c.value(x.get("enabled", True))} for x in v]})})


def _scheduled_rule(f, cx):
    """A Sentinel scheduled analytics rule: kind Scheduled, what azurerm sets (its custom details and incident
    configuration too: task 592), and the suppression ARM requires (off, the provider's PT5H)."""
    return {"kind": "Scheduled", "suppressionEnabled": False, "suppressionDuration": "PT5H", **obj(own(f), cx, {
        "name": None, "log_analytics_workspace_id": None, "display_name": "displayName", "description": "description",
        "severity": "severity", "query": "query", "query_frequency": "queryFrequency", "query_period": "queryPeriod",
        "trigger_operator": "triggerOperator",
        "trigger_threshold": "triggerThreshold", "enabled": "enabled", "tactics": "tactics", "techniques": "techniques",
        "event_grouping": Custom(lambda v, c: {"eventGroupingSettings": {
            "aggregationKind": c.value(v[0]["aggregation_method"])}}),
        "entity_mapping": Custom(lambda v, c: {"entityMappings": [
            {"entityType": c.value(e["entity_type"]),
             "fieldMappings": [{"identifier": c.value(x["identifier"]), "columnName": c.value(x["column_name"])}
                               for x in e.get("field_mapping", [])]} for e in v]}),
        "custom_details": "customDetails",
        "incident": Nest("incidentConfiguration", {"create_incident_enabled": "createIncident", "grouping": Nest(
            "groupingConfiguration", {
                "enabled": "enabled", "lookback_duration": "lookbackDuration",
                "reopen_closed_incidents": "reopenClosedIncident", "entity_matching_method": "matchingMethod",
                "by_entities": "groupByEntities", "by_alert_details": "groupByAlertDetails",
                "by_custom_details": "groupByCustomDetails"})})})}


def _budget(f, cx):
    """A budget: cost category, its period and notifications (named notification<n>)."""
    period = one(f, "time_period")
    return {"category": "Cost", **obj({k: v for k, v in own(f).items() if k not in ("time_period", "notification")},
                                      cx, {"name": None, "resource_group_id": None, "amount": "amount",
                                           "time_grain": "timeGrain"}),
            "timePeriod": obj(period, cx, {"start_date": "startDate", "end_date": "endDate"},
                              f"{cx.where}.time_period"),
            "notifications": {f"notification{i + 1}": {"enabled": cx.value(n.get("enabled", True)), "contactEmails": [],
                                                       **obj(
                {k: x for k, x in n.items() if k != "enabled"}, cx, {
                    "operator": "operator", "threshold": "threshold", "threshold_type": "thresholdType",
                    "contact_groups": "contactGroups", "contact_emails": "contactEmails",
                    "contact_roles": "contactRoles"}, f"{cx.where}.notification")}
                for i, n in enumerate(f.get("notification", ()))}}


# ------------------------------------------------------------------ Logic Apps (5.7b: change history kept longer)
_WORKFLOW_SCHEMA = ("https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/"
                    "workflowdefinition.json#")


def _workflow(f, cx):
    """A Logic App: enabled, its identity, a definition its trigger and actions are merged into."""
    found = own(f)
    identity = (found.get("identity") or [{}])[0]
    return {**obj({k: v for k, v in found.items() if k != "identity"}, cx, BASE), "state": "Enabled",
            **({"identity": {"type": cx.value(identity["type"])}} if identity else {}),
            "definition": {"$schema": _WORKFLOW_SCHEMA, "contentVersion": "1.0.0.0", "triggers": {}, "actions": {},
                           "outputs": {}}}


def _recurrence(props, f, cx):
    found = own(f)
    trigger = {"type": "Recurrence", "recurrence": {"frequency": cx.value(found["frequency"]),
                                                    "interval": cx.value(found["interval"])}}
    return {**props, "definition": {**props["definition"], "triggers": {
        **props["definition"]["triggers"], cx.value(found["name"]): trigger}}}


def _custom_action(props, f, cx):
    found = own(f)
    return {**props, "definition": {**props["definition"], "actions": {
        **props["definition"]["actions"], cx.value(found["name"]): cx.value(found["body"])}}}


def azapi_merged(body, extra):
    """A body with an azapi sensitive_body merged into it as azapi merges them (v2.13 utils/json.go, research 581):
    objects key by key, lists of the same length item by item, anything else extra's."""
    if isinstance(body, dict) and isinstance(extra, dict):
        return {**body, **{k: azapi_merged(body[k], v) if k in body else v for k, v in extra.items()}}
    if isinstance(body, list) and isinstance(extra, list) and body and len(body) == len(extra):
        return [azapi_merged(b, x) for b, x in zip(body, extra)]
    return extra


def _azapi(f, cx):
    """An azapi resource: its body (with its write-only sensitive_body merged in: a secret there is a secure
    parameter), whose properties are the resource's (the rest top-level fields), and its location, tags (a VPN
    connection's, 586) and managed identity as the resource's (a Logic App's system-assigned identity, 5.7b)."""
    found = own(f)
    body = cx.value(azapi_merged(found.get("body", {}), found.get("sensitive_body", {})))
    rest = sorted(set(found) - {"type", "name", "parent_id", "body", "sensitive_body", "schema_validation_enabled",
                                "location", "identity", "tags"})
    if rest:
        raise SystemExit(f"{cx.where}: no ARM form for {', '.join(rest)}")
    identity = (found.get("identity") or [{}])[0]
    return {**{k: v for k, v in body.items() if k != "properties"}, **body.get("properties", {}),
            **({"location": cx.value(found["location"])} if "location" in found else {}),
            **({"tags": cx.value(found["tags"])} if "tags" in found else {}),
            **({"identity": {"type": cx.value(identity["type"])}} if identity else {})}

# ------------------------------------------------------------------ DNS records, Traffic Manager

def _txt(x):
    """A TXT value as ARM's strings of at most 255 characters (as azurerm splits a longer one); an expression whole."""
    return ([x[i:i + 255] for i in range(0, len(x), 255)] or [""]) if isinstance(x, str) else [x]


def _record_sets(private):
    """{record type: (Terraform attribute, ARM property, (Terraform value, Cx) -> its records)} of a zone's record
    sets, public (dnsZones' casing) or private (privateDnsZones')."""
    def each(spec):
        return lambda v, cx: [obj(r, cx, spec, f"{cx.where}.record") for r in v]
    return {
        "a": ("records", "aRecords" if private else "ARecords", lambda v, cx: [{"ipv4Address": x}
                                                                              for x in cx.value(v)]),
        "aaaa": ("records", "aaaaRecords" if private else "AAAARecords",
                 lambda v, cx: [{"ipv6Address": x} for x in cx.value(v)]),
        "ns": ("records", "NSRecords", lambda v, cx: [{"nsdname": x} for x in cx.value(v)]),
        "cname": ("record", "cnameRecord" if private else "CNAMERecord", lambda v, cx: {"cname": cx.value(v)}),
        "mx": ("record", "mxRecords" if private else "MXRecords", each({"preference": "preference",
                                                                            "exchange": "exchange"})),
        "srv": ("record", "srvRecords" if private else "SRVRecords", each({
            "priority": "priority", "weight": "weight", "port": "port", "target": "target"})),
        "caa": ("record", "caaRecords", each({"flags": "flags", "tag": "tag", "value": "value"})),
        "txt": ("record", "txtRecords" if private else "TXTRecords",
                lambda v, cx: [{"value": _txt(cx.value(r["value"]))} for r in v])}


def _record(kind, private):
    """A DNS record set of a kind: a child of its zone (a public one by name in the record's resource group, a private
    one by id), its TTL, records and tags (as the set's metadata)."""
    attribute, key, records = _record_sets(private)[kind]
    zone = (Parent("private_dns_zone_id", "Microsoft.Network/privateDnsZones") if private else
            Parent("zone_name", "Microsoft.Network/dnsZones", "name"))
    return Native(Arm(f"Microsoft.Network/{'privateDnsZones' if private else 'dnsZones'}/{kind.upper()}",
                      PRIVATE_DNS if private else DNS, zone), {
        "name": None, "zone_name": None, "resource_group_name": None, "private_dns_zone_id": None,
        "ttl": "ttl" if private else "TTL", attribute: Custom(lambda v, cx: {key: records(v, cx)})},
        {"id": "id", "fqdn": "fqdn"}, "name", "map", tags_key="metadata")


RECORDS = {**{f"azurerm_dns_{k}_record": _record(k, False) for k in ("a", "aaaa", "caa", "cname", "mx", "ns", "srv",
                                                                     "txt")},
           **{f"azurerm_private_dns_{k}_record": _record(k, True) for k in ("a", "aaaa", "cname", "mx", "srv", "txt")}}


def _status(key, on="Enabled", off="Disabled"):
    """A Terraform boolean as an ARM state property."""
    return Custom(lambda v, cx: {key: on if cx.value(v) else off})


def _traffic_manager(f, cx):
    """A Traffic Manager profile (location global): its routing, DNS name and endpoint monitoring."""
    return {"location": "global", **obj(own(f), cx, {
        "name": None, "resource_group_name": None, "traffic_routing_method": "trafficRoutingMethod",
        "profile_status": "profileStatus", "max_return": "maxReturn",
        "traffic_view_enabled": _status("trafficViewEnrollmentStatus"),
        "dns_config": Custom(lambda v, c: {"dnsConfig": obj(v[0], c, {"relative_name": "relativeName", "ttl": "ttl"},
                                                            f"{c.where}.dns_config")}),
        "monitor_config": Custom(lambda v, c: {"monitorConfig": obj(v[0], c, {
            "protocol": "protocol", "port": "port", "path": "path", "interval_in_seconds": "intervalInSeconds",
            "timeout_in_seconds": "timeoutInSeconds", "tolerated_number_of_failures": "toleratedNumberOfFailures",
            "expected_status_code_ranges": Custom(lambda x, c2: {"expectedStatusCodeRanges": [
                dict(zip(("min", "max"), map(int, r.split("-")))) for r in c2.value(x)]})},
            f"{c.where}.monitor_config")})})}


# ------------------------------------------------------------------ Front Door

def _profile_child(type_, parent="cdn_frontdoor_profile_id", parent_type="Microsoft.Cdn/profiles"):
    return Arm(f"Microsoft.Cdn/profiles/{type_}", CDN, Parent(parent, parent_type))


def _fd_secret(f, cx):
    """A Front Door secret: a customer certificate from Key Vault (the latest version), named by the Key Vault
    secret's ARM id (Terraform names the certificate by its URI: the vault lookup's vault_uri and the name)."""
    cert = one(one(f, "secret"), "customer_certificate")
    unknown = sorted((set(own(f)) - {"name", "cdn_frontdoor_profile_id", "secret"}) | (set(cert) -
                                                                                       {"key_vault_certificate_id"}))
    uri = cert.get("key_vault_certificate_id")
    uri = uri[3:-2] if isinstance(uri, str) and uri.startswith('${"') and uri.endswith('"}') else uri  # a template
    found = re.match(r"^\$\{(data\.azurerm_key_vault\.[\w-]+)\.vault_uri\}certificates/([^/${}]+)$", uri) \
        if isinstance(uri, str) else None
    if unknown or not found:
        raise SystemExit(f"{cx.where}: no ARM form for {', '.join(unknown) or f'the certificate {uri!r}'}")
    return {"parameters": {"type": "CustomerCertificate", "useLatestVersion": True, "secretSource": {
        "id": cx.value(f"${{{found.group(1)}.id}}/secrets/{found.group(2)}")}}}


def _fd_route_domains(props, f, cx):
    """A custom domain association: the domain among its route's custom domains (once)."""
    domain = {"id": cx.value(f["cdn_frontdoor_custom_domain_id"])}
    found = props.get("customDomains", [])
    return {**props, "customDomains": found if domain in found else [*found, domain]}


def _fd_security(f, cx):
    """A Front Door security policy: its firewall policy and the domains (and paths) it inspects."""
    fw = one(one(f, "security_policies"), "firewall")
    unknown = sorted((set(own(f)) - {"name", "cdn_frontdoor_profile_id", "security_policies"}) |
                     (set(fw) - {"cdn_frontdoor_firewall_policy_id", "association"}))
    if unknown:
        raise SystemExit(f"{cx.where}: no ARM form for {', '.join(unknown)}")
    return {"parameters": {"type": "WebApplicationFirewall",
                           "wafPolicy": {"id": cx.value(fw["cdn_frontdoor_firewall_policy_id"])},
                           "associations": [{"domains": [{"id": cx.value(d["cdn_frontdoor_domain_id"])}
                                                         for d in a.get("domain", ())],
                                             "patternsToMatch": cx.value(a["patterns_to_match"])}
                                            for a in fw.get("association", ())]}}


def _fd_waf(f, cx):
    """A Front Door firewall policy (location Global): its state and mode, custom rules (match conditions, rate
    limits) and managed rule sets (their action, exclusions)."""
    def rule(r):
        return obj(r, cx, {
            "name": "name", "enabled": _status("enabledState"), "priority": "priority", "type": "ruleType",
            "action": "action", "rate_limit_duration_in_minutes": "rateLimitDurationInMinutes",
            "rate_limit_threshold": "rateLimitThreshold",
            "match_condition": Nest("matchConditions", {
                "match_variable": "matchVariable", "operator": "operator", "negation_condition": "negateCondition",
                "match_values": "matchValue", "selector": "selector", "transforms": "transforms"}, True)},
            f"{cx.where}.custom_rule")

    def rule_set(r):
        return obj(r, cx, {"type": "ruleSetType", "version": "ruleSetVersion", "action": "ruleSetAction",
                           "exclusion": Nest("exclusions", {"match_variable": "matchVariable",
                                                            "operator": "selectorMatchOperator",
                                                            "selector": "selector"}, True)},
                   f"{cx.where}.managed_rule")
    rest = {k: v for k, v in own(f).items() if k not in ("custom_rule", "managed_rule", "enabled", "mode",
                                                         "request_body_check_enabled", "redirect_url",
                                                         "custom_block_response_status_code")}
    return {"location": "Global", **obj(rest, cx, {
        "name": None, "resource_group_name": None, "sku_name": Custom(lambda v, c: {"sku": {"name": c.value(v)}})}),
        "policySettings": obj({k: v for k, v in own(f).items() if k in (
            "enabled", "mode", "request_body_check_enabled", "redirect_url", "custom_block_response_status_code")},
            cx, {"enabled": _status("enabledState"), "mode": "mode",
                 "request_body_check_enabled": _status("requestBodyCheck"), "redirect_url": "redirectUrl",
                 "custom_block_response_status_code": "customBlockResponseStatusCode"}),
        "customRules": {"rules": [rule(r) for r in f.get("custom_rule", ())]},
        "managedRules": {"managedRuleSets": [rule_set(r) for r in f.get("managed_rule", ())]}}


# ------------------------------------------------------------------ availability tests

def _web_test(f, cx):
    """A standard web test (kind standard): its request, validation rules and locations, with the hidden-link tag ARM
    requires to tie it to its Application Insights component."""
    app = cx.value(f["application_insights_id"])
    link = f"hidden-link:{app}" if isinstance(app, str) else \
        Interp(("hidden-link:", *(app.parts if isinstance(app, Interp) else (app,))))
    name = cx.value(f["name"])
    return {"kind": "standard", "tags": {link: "Resource"}, "SyntheticMonitorId": name, "Name": name,
            "Kind": "standard", **obj({k: v for k, v in own(f).items() if k != "application_insights_id"}, cx, {
                "name": None, "resource_group_name": None, "location": "location", "description": "Description",
                "enabled": "Enabled", "frequency": "Frequency", "timeout": "Timeout", "retry_enabled": "RetryEnabled",
                "geo_locations": Custom(lambda v, c: {"Locations": [{"Id": x} for x in c.value(v)]}),
                "request": Custom(lambda v, c: {"Request": obj(v[0], c, {
                    "url": "RequestUrl", "http_verb": "HttpVerb", "follow_redirects_enabled": "FollowRedirects",
                    "parse_dependent_requests_enabled": "ParseDependentRequests", "body": "RequestBody",
                    "header": Custom(lambda x, c2: {"Headers": [{"key": c2.value(h["name"]),
                                                                 "value": c2.value(h["value"])} for h in x]})},
                    f"{c.where}.request")}),
                "validation_rules": Custom(lambda v, c: {"ValidationRules": obj(v[0], c, {
                    "expected_status_code": "ExpectedHttpStatusCode", "ssl_check_enabled": "SSLCheck",
                    "ssl_cert_remaining_lifetime": "SSLCertRemainingLifetimeCheck"},
                    f"{c.where}.validation_rules")})})}


# ------------------------------------------------------------------ scripted checks (Container Apps)

_VNET = {"infrastructure_subnet_id": "infrastructureSubnetId", "internal_load_balancer_enabled": "internal"}


def _app_environment(f, cx):
    """A Container Apps environment with workload profiles, in a virtual network when it names an infrastructure
    subnet (internal: no public address)."""
    vnet = {form: cx.value(f[k]) for k, form in _VNET.items() if k in f}
    return {**obj({k: v for k, v in own(f).items() if k not in _VNET}, cx, {
        **BASE, "zone_redundancy_enabled": "zoneRedundant", "public_network_access": "publicNetworkAccess",
        "workload_profile": Nest("workloadProfiles", {"name": "name", "workload_profile_type": "workloadProfileType",
                                                      "minimum_count": "minimumCount",
                                                      "maximum_count": "maximumCount"}, True)}),
            **({"vnetConfiguration": vnet} if vnet else {})}


# A scheduled job's container sizes are decimals, which Bicep writes only through json()
def _decimal(v):
    return Call("json", (str(v),)) if isinstance(v, float) else v


def _job_env(e, cx):
    """A job container's environment variable: a value, or a reference to one of the job's secrets."""
    return {"name": cx.value(e["name"]),
            **({"secretRef": cx.value(e["secret_name"])} if "secret_name" in e else {"value": cx.value(e["value"])})}


def _job_secret(s, cx):
    """A job's secret: a value (a secure parameter), or a Key Vault secret read with a user-assigned identity."""
    return {"name": cx.value(s["name"]), **({"keyVaultUrl": cx.value(s["key_vault_secret_id"]),
                                            "identity": cx.value(s["identity"])} if "key_vault_secret_id" in s else
                                           {"value": cx.value(s["value"])})}


def _job_container(c, cx):
    return {"name": cx.value(c["name"]), "image": cx.value(c["image"]),
            **({"command": cx.value(c["command"])} if "command" in c else {}),
            "resources": {"cpu": _decimal(cx.value(c["cpu"])), "memory": cx.value(c["memory"])},
            **({"env": [_job_env(e, cx) for e in c["env"]]} if c.get("env") else {})}


def _app_job(f, cx):
    """A scheduled Container Apps job (the scripted checks, check_jobs: image delivery): its environment and workload
    profile, user-assigned identity, schedule, secrets (a value, or a Key Vault secret read with the identity), the
    registries it pulls from with that identity, and its containers."""
    trigger = f["schedule_trigger_config"][0]
    config = {"triggerType": "Schedule",
              **({"replicaTimeout": cx.value(f["replica_timeout_in_seconds"])}
                 if "replica_timeout_in_seconds" in f else {}),
              **({"replicaRetryLimit": cx.value(f["replica_retry_limit"])} if "replica_retry_limit" in f else {}),
              "scheduleTriggerConfig": obj(trigger, cx, {"cron_expression": "cronExpression",
                                                         "parallelism": "parallelism",
                                                         "replica_completion_count": "replicaCompletionCount"},
                                           f"{cx.where}.schedule_trigger_config"),
              **({"secrets": [_job_secret(x, cx) for x in f["secret"]]} if f.get("secret") else {}),
              **({"registries": [{"server": cx.value(r["server"]), "identity": cx.value(r["identity"])}
                                 for r in f["registry"]]} if f.get("registry") else {})}
    unknown = sorted(set(own(f)) - {"name", "resource_group_name", "location", "container_app_environment_id",
                                    "workload_profile_name", "replica_timeout_in_seconds", "replica_retry_limit",
                                    "schedule_trigger_config", "identity", "secret", "registry", "template"})
    if unknown:
        raise SystemExit(f"{cx.where}: no ARM form for {', '.join(unknown)}")
    return {"location": cx.value(f["location"]), **_identity(f["identity"], cx),
            "environmentId": cx.value(f["container_app_environment_id"]),
            **({"workloadProfileName": cx.value(f["workload_profile_name"])} if "workload_profile_name" in f else {}),
            "configuration": config,
            "template": {"containers": [_job_container(c, cx) for c in f["template"][0]["container"]]}}


def _script_job(f, block):
    """Why a check job stays Terraform: in the script form (no registry) it reads its runner from a file beside the
    root (file()), which a template has no form for; else None."""
    return None if f.get("registry") else (
        "in the script form the check job reads its runner from a file beside the root (file()), which a template "
        "has no form for: it is applied after the template, with the environment, identity and grants it reads")


TYPES = {
    "azurerm_network_security_group": Native(Arm("Microsoft.Network/networkSecurityGroups", NETWORK), BASE,
                                             {"id": "id", "name": "name"}, "name", "map"),
    "azurerm_network_security_rule": Native(None, merge=Merge("network_security_group_name", _rule,
                                                              {"id": _sub_id("securityRules")})),
    "azurerm_lb": Native(Arm("Microsoft.Network/loadBalancers", NETWORK), _lb, {
        "id": "id", "name": "name",
        "frontend_ip_configuration[0].id": FromBlock(lambda nid, f: Interp((
            ResourceId(nid), f"/frontendIPConfigurations/{f['frontend_ip_configuration'][0]['name']}")))},
        "name", "map"),
    "azurerm_lb_backend_address_pool": Native(None, merge=Merge("loadbalancer_id", _lb_child(
        "backendAddressPools", {}), {"id": _sub_id("backendAddressPools")})),
    "azurerm_lb_probe": Native(None, merge=Merge("loadbalancer_id", _lb_child("probes", {
        "protocol": "protocol", "port": "port", "request_path": "requestPath", "interval_in_seconds":
        "intervalInSeconds", "number_of_probes": "numberOfProbes"}), {"id": _sub_id("probes")})),
    "azurerm_lb_rule": Native(None, merge=Merge("loadbalancer_id", lambda props, f, cx: _lb_child(
        "loadBalancingRules", {
            "protocol": "protocol", "frontend_port": "frontendPort", "backend_port": "backendPort",
            "frontend_ip_configuration_name": Custom(lambda v, c: {"frontendIPConfiguration": {"id": Interp((
                ResourceId(c.logical(_lb_address(f))), f"/frontendIPConfigurations/{v}"))}}),
            "backend_address_pool_ids": Custom(lambda v, c: {"backendAddressPools": [{"id": x}
                                                                                       for x in c.value(v)]}),
            "probe_id": Custom(lambda v, c: {"probe": {"id": c.value(v)}}),
            "idle_timeout_in_minutes": "idleTimeoutInMinutes", "enable_floating_ip": "enableFloatingIP",
            "load_distribution": "loadDistribution", "disable_outbound_snat": "disableOutboundSnat"})(props, f, cx),
        {"id": _sub_id("loadBalancingRules")})),
    "azurerm_network_interface": Native(Arm("Microsoft.Network/networkInterfaces", NETWORK), {
        **BASE, "ip_configuration": Custom(_ip_configuration)}, {"id": "id", "name": "name"}, "name", "map"),
    "azurerm_network_interface_security_group_association": Native(None, merge=Merge(
        "network_interface_id", lambda props, f, cx: {**props, "networkSecurityGroup": {
            "id": cx.value(f["network_security_group_id"])}})),
    "azurerm_network_interface_backend_address_pool_association": Native(None, merge=Merge(
        "network_interface_id", _nic_pool)),
    "azurerm_nat_gateway": Native(Arm("Microsoft.Network/natGateways", NETWORK), {
        **BASE, "sku_name": Custom(lambda v, cx: {"sku": {"name": cx.value(v)}}),
        "idle_timeout_in_minutes": "idleTimeoutInMinutes", "zones": "zones"}, {"id": "id"}, "name", "map"),
    "azurerm_nat_gateway_public_ip_association": Native(None, merge=Merge(
        "nat_gateway_id", lambda props, f, cx: {**props, "publicIpAddresses": [
            *props.get("publicIpAddresses", []), {"id": cx.value(f["public_ip_address_id"])}]})),
    "azurerm_route_table": Native(Arm("Microsoft.Network/routeTables", NETWORK), {
        **BASE, "bgp_route_propagation_enabled": Custom(lambda v, cx: {"disableBgpRoutePropagation": not v}),
        # routes inline: the table's PUT replaces them
        "route": Custom(lambda v, cx: {"routes": _named(v, cx, {
            "address_prefix": "addressPrefix", "next_hop_type": "nextHopType",
            "next_hop_in_ip_address": "nextHopIpAddress"}, "route")})},
        {"id": "id"}, "name", "map"),
    # identities
    "azurerm_user_assigned_identity": Native(Arm("Microsoft.ManagedIdentity/userAssignedIdentities", IDENTITY), BASE,
                                             {"id": "id", "principal_id": "principalId", "client_id": "clientId"},
                                             "name", "map"),
    "azurerm_federated_identity_credential": Native(Arm(
        "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials", IDENTITY,
        Parent("user_assigned_identity_id", "Microsoft.ManagedIdentity/userAssignedIdentities")), {
        "name": None, "user_assigned_identity_id": None, "audience": "audiences", "issuer": "issuer",
        "subject": "subject"}, {"id": "id"}, "name"),
    # logs
    "azurerm_log_analytics_workspace": Native(Arm("Microsoft.OperationalInsights/workspaces", OPINSIGHTS,
                                                  fields=("location", "tags")), {
        **BASE, "sku": Custom(lambda v, cx: {"sku": {"name": cx.value(v)}}), "retention_in_days": "retentionInDays"},
        {"id": "id", "workspace_id": "customerId", "name": "name"}, "name", "map"),
    # access, subscription and tenant scope
    "azurerm_role_assignment": Native(Arm("Microsoft.Authorization/roleAssignments", AUTH, name=_assignment_name,
                                          extends="scope"), {
        "name": None, "scope": None, "principal_id": "principalId", "principal_type": "principalType",
        "role_definition_name": Custom(lambda v, cx: {"roleDefinitionId": _role_definition(cx.value(v), cx.where)}),
        "role_definition_id": "roleDefinitionId", "description": "description", "condition": "condition",
        "condition_version": "conditionVersion", "skip_service_principal_aad_check": None}, {"id": "id"}, "name"),
    "azurerm_pim_eligible_role_assignment": Native(Arm("Microsoft.Authorization/roleEligibilityScheduleRequests",
                                                       PIM, name=_assignment_name, extends="scope"),
                                                   lambda f, cx: _pim(f, cx), {"id": "id"}, "name"),
    "azurerm_security_center_subscription_pricing": Native(Arm("Microsoft.Security/pricings", "2024-01-01",
                                                               name="resource_type", deploy="subscription"),
                                                           _pricing, {"id": "id"}, "resource_type"),
    "azurerm_security_center_server_vulnerability_assessments_setting": Native(Arm(
        "Microsoft.Security/serverVulnerabilityAssessmentsSettings", "2023-05-01", name=Fixed("AzureServersSetting"),
        deploy="subscription"), lambda f, cx: {"kind": "AzureServersSetting", **obj(own(f), cx, {
            "vulnerability_assessment_provider": "selectedProvider"})}, {"id": "id"}, "name"),
    "azurerm_subscription_policy_assignment": Native(Arm("Microsoft.Authorization/policyAssignments", "2025-03-01",
                                                         extends="subscription_id"), {
        "name": None, "subscription_id": None, "policy_definition_id": "policyDefinitionId",
        "display_name": "displayName", "description": "description", "parameters": Custom(
            lambda v, cx: {"parameters": cx.value(v)}), "enforce": Custom(
            lambda v, cx: {"enforcementMode": "Default" if v else "DoNotEnforce"}),
        "not_scopes": "notScopes", "location": "location", "identity": Custom(_identity)}, {"id": "id"}, "name",
        keep=_unknown_initiative),
    # Microsoft Sentinel: extension resources on the workspace (the rule names the workspace, after its onboarding)
    "azurerm_sentinel_log_analytics_workspace_onboarding": Native(
        Arm("Microsoft.SecurityInsights/onboardingStates", SENTINEL, name=Fixed("default"), extends="workspace_id"),
        lambda f, cx: {}, {"id": "id"}),
    "azurerm_sentinel_alert_rule_scheduled": Native(
        Arm("Microsoft.SecurityInsights/alertRules", SENTINEL, extends="log_analytics_workspace_id"), _scheduled_rule,
        {"id": "id"}, "name"),
    "azurerm_monitor_diagnostic_setting": Native(Arm("Microsoft.Insights/diagnosticSettings", "2021-05-01-preview",
                                                     extends="target_resource_id"), _diagnostic, {"id": "id"},
                                                 "name"),
    "azurerm_monitor_aad_diagnostic_setting": Native(Arm("microsoft.aadiam/diagnosticSettings", "2017-04-01",
                                                         deploy="tenant"), lambda f, cx: obj(own(f), cx, {
        "name": None, "log_analytics_workspace_id": "workspaceId", "storage_account_id": "storageAccountId",
        "eventhub_authorization_rule_id": "eventHubAuthorizationRuleId", "eventhub_name": "eventHubName",
        "enabled_log": Custom(lambda v, c: {"logs": _logs(v, c)})}), {"id": "id"}, "name"),
    "azurerm_consumption_budget_resource_group": Native(Arm("Microsoft.Consumption/budgets", "2024-08-01",
                                                            extends="resource_group_id"), _budget, {"id": "id"},
                                                        "name"),
    "azurerm_logic_app_workflow": Native(Arm("Microsoft.Logic/workflows", "2019-05-01"), _workflow,
                                         {"id": "id", "identity[0].principal_id": "identity.principalId"}, "name",
                                         "map"),
    "azurerm_logic_app_trigger_recurrence": Native(None, merge=Merge("logic_app_id", _recurrence)),
    "azurerm_logic_app_action_custom": Native(None, merge=Merge("logic_app_id", _custom_action)),
    "azapi_resource": Native(Arm(lambda f: tuple(f["type"].split("@")), None, extends="parent_id"), _azapi,
                             {"id": "id", "identity[0].principal_id": "identity.principalId"}, "name", "map"),
    # edge and private connectivity
    "azurerm_application_gateway": Native(Arm("Microsoft.Network/applicationGateways", NETWORK,
                                              fields=("location", "tags", "zones", "identity")), _gateway,
                                          {"id": "id", "name": "name"}, "name", "map"),
    "azurerm_web_application_firewall_policy": Native(Arm(
        "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies", NETWORK), _waf_policy, {"id": "id"},
        "name", "map"),
    "azurerm_private_endpoint": Native(Arm("Microsoft.Network/privateEndpoints", NETWORK), _private_endpoint,
                                       {"id": "id"}, "name", "map", expand=_dns_zone_group),
    "azurerm_private_link_service": Native(Arm("Microsoft.Network/privateLinkServices", NETWORK), _link_service,
                                           {"id": "id", "alias": "alias"}, "name", "map"),
    "azurerm_firewall_policy_rule_collection_group": Native(Arm(
        "Microsoft.Network/firewallPolicies/ruleCollectionGroups", NETWORK,
        Parent("firewall_policy_id", "Microsoft.Network/firewallPolicies")), _rule_collection_group, {"id": "id"},
        "name"),
    "azurerm_network_watcher_flow_log": Native(Arm("Microsoft.Network/networkWatchers/flowLogs", NETWORK,
                                                   Parent("network_watcher_name", "Microsoft.Network/networkWatchers",
                                                          "name")), _flow_log, {"id": "id"}, "name", "map"),
    # backup and security automation
    "azurerm_data_protection_backup_vault": Native(Arm("Microsoft.DataProtection/backupVaults", BACKUP),
                                                   _backup_vault, {"id": "id", "name": "name",
                                                                   "identity[0].principal_id": "identity.principalId"},
                                                   "name", "map"),
    "azurerm_data_protection_backup_vault_customer_managed_key": Native(None, merge=Merge(
        "data_protection_backup_vault_id", _backup_vault_key)),
    "azurerm_data_protection_backup_policy_disk": Native(Arm(
        "Microsoft.DataProtection/backupVaults/backupPolicies", BACKUP,
        Parent("vault_id", "Microsoft.DataProtection/backupVaults")), _disk_policy, {"id": "id"}, "name"),
    "azurerm_data_protection_backup_instance_disk": Native(Arm(
        "Microsoft.DataProtection/backupVaults/backupInstances", BACKUP,
        Parent("vault_id", "Microsoft.DataProtection/backupVaults")), _disk_instance, {"id": "id"}, "name"),
    "azurerm_security_center_automation": Native(Arm("Microsoft.Security/automations", "2019-01-01-preview"),
                                                 _automation, {"id": "id"}, "name", "map"),
    # the legacy contact API azurerm's resource writes (the 2020/2023 previews take emails and role notifications)
    "azurerm_security_center_contact": Native(Arm("Microsoft.Security/securityContacts", "2017-08-01-preview",
                                                  deploy="subscription"), _contact, {"id": "id"}, "name"),
    # compute
    "azurerm_linux_virtual_machine": Native(Arm("Microsoft.Compute/virtualMachines", COMPUTE), _vm,
                                            {"id": "id", "name": "name",
                                             "identity[0].principal_id": "identity.principalId"}, "name", "map"),
    "azurerm_virtual_machine_data_disk_attachment": Native(None, merge=Merge("virtual_machine_id", _data_disk)),
    "azurerm_linux_virtual_machine_scale_set": Native(Arm("Microsoft.Compute/virtualMachineScaleSets", COMPUTE),
                                                      _scale_set, {"id": "id", "name": "name"}, "name", "map"),
    "azurerm_monitor_autoscale_setting": Native(Arm("Microsoft.Insights/autoscalesettings", AUTOSCALE), _autoscale,
                                                {"id": "id"}, "name", "map"),
    "azurerm_managed_disk": Native(Arm("Microsoft.Compute/disks", DISKS), _disk, {"id": "id"}, "name", "map"),
    "azurerm_virtual_machine_extension": Native(Arm("Microsoft.Compute/virtualMachines/extensions", COMPUTE,
                                                    Parent("virtual_machine_id", "Microsoft.Compute/virtualMachines")),
                                                lambda f, cx: {"location": Member(Call("resourceGroup", ()),
                                                                                  "location"), **obj(own(f), cx, {
                                                    "name": None, "virtual_machine_id": None, "publisher": "publisher",
                                                    "type": "type", "type_handler_version": "typeHandlerVersion",
                                                    "auto_upgrade_minor_version": "autoUpgradeMinorVersion",
                                                    "automatic_upgrade_enabled": "enableAutomaticUpgrade",
                                                    "settings": "settings"})},
                                                {"id": "id"}, "name", "map"),
    # storage
    "azurerm_storage_account": Native(Arm("Microsoft.Storage/storageAccounts", STORAGE), _account,
                                      {"id": "id", "name": "name"}, "name", "map", expand=_blob_service),
    "azurerm_storage_account_customer_managed_key": Native(None, merge=Merge("storage_account_id", _account_key)),
    "azurerm_storage_container": Native(Arm("Microsoft.Storage/storageAccounts/blobServices/containers", STORAGE,
                                            Parent("storage_account_id", "Microsoft.Storage/storageAccounts",
                                                   via="blob")), {
        "name": None, "storage_account_id": None,
        "container_access_type": Custom(lambda v, cx: {"publicAccess": {"private": "None", "blob": "Blob",
                                                                        "container": "Container"}[cx.value(v)]}),
        "metadata": "metadata"}, {"id": "id", "name": "name"}, "name"),
    "azurerm_storage_container_immutability_policy": Native(Arm(
        "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies", STORAGE,
        Parent("storage_container_resource_manager_id", "Microsoft.Storage/storageAccounts/blobServices/containers"),
        Fixed("default")), {
        "storage_container_resource_manager_id": None,
        "immutability_period_in_days": "immutabilityPeriodSinceCreationInDays",
        "protected_append_writes_enabled": "allowProtectedAppendWrites",
        "locked": Custom(lambda v, cx: {} if not v else _locked(cx))}, {"id": "id"}, "name"),
    "azurerm_storage_management_policy": Native(Arm("Microsoft.Storage/storageAccounts/managementPolicies", STORAGE,
                                                    Parent("storage_account_id",
                                                           "Microsoft.Storage/storageAccounts"), Fixed("default")),
                                                {"storage_account_id": None, "rule": Custom(_management_rules)},
                                                {"id": "id"}, "name"),
    # databases
    "azurerm_postgresql_flexible_server": Native(Arm("Microsoft.DBforPostgreSQL/flexibleServers", POSTGRES),
                                                 _flexible("privateDnsZoneArmResourceId"),
                                                 {"id": "id", "name": "name", "fqdn": "fullyQualifiedDomainName"},
                                                 "name", "map"),
    "azurerm_postgresql_flexible_server_configuration": _configuration(
        "Microsoft.DBforPostgreSQL/flexibleServers/configurations", POSTGRES,
        "Microsoft.DBforPostgreSQL/flexibleServers"),
    "azurerm_mysql_flexible_server": Native(Arm("Microsoft.DBforMySQL/flexibleServers", MYSQL),
                                            _flexible("privateDnsZoneResourceId"),
                                            {"id": "id", "name": "name", "fqdn": "fullyQualifiedDomainName"},
                                            "name", "map"),
    "azurerm_mysql_flexible_server_configuration": _configuration(
        "Microsoft.DBforMySQL/flexibleServers/configurations", MYSQL, "Microsoft.DBforMySQL/flexibleServers", "name"),
    # monitoring
    "azurerm_log_analytics_workspace_table_custom_log": Native(Arm(
        "Microsoft.OperationalInsights/workspaces/tables", OPINSIGHTS,
        Parent("workspace_id", "Microsoft.OperationalInsights/workspaces"), fields=()), lambda f, cx: obj(own(f), cx, {
            "name": None, "workspace_id": None, "plan": "plan", "retention_in_days": "retentionInDays",
            "total_retention_in_days": "totalRetentionInDays",
            "column": Custom(lambda v, c: {"schema": {"name": c.value(f["name"]), "columns": [
                {"name": c.value(x["name"]), "type": c.value(x["type"])} for x in v]}})}), {"id": "id"}, "name"),
    # a workspace's logs exported to an existing Event Hub on their way to a SIEM (siem_export.py)
    "azurerm_log_analytics_data_export_rule": Native(Arm(
        "Microsoft.OperationalInsights/workspaces/dataExports", OPINSIGHTS,
        Parent("workspace_resource_id", "Microsoft.OperationalInsights/workspaces"), fields=()), lambda f, cx: {
            "destination": {"resourceId": cx.value(f["destination_resource_id"])},
            "tableNames": cx.value(f["table_names"]), "enable": cx.value(f.get("enabled", True))},
        {"id": "id"}, "name"),
    "azurerm_log_analytics_workspace_table": Native(Arm(
        "Microsoft.OperationalInsights/workspaces/tables", OPINSIGHTS,
        Parent("workspace_id", "Microsoft.OperationalInsights/workspaces"), fields=()), {
        "name": None, "workspace_id": None, "plan": "plan", "retention_in_days": "retentionInDays",
        "total_retention_in_days": "totalRetentionInDays"}, {"id": "id"}, "name"),
    "azurerm_monitor_data_collection_rule": Native(Arm("Microsoft.Insights/dataCollectionRules", INSIGHTS), _dcr,
                                                   {"id": "id", "immutable_id": "immutableId"}, "name", "map"),
    "azurerm_monitor_data_collection_rule_association": Native(Arm(
        "Microsoft.Insights/dataCollectionRuleAssociations", INSIGHTS, extends="target_resource_id"), {
        "name": None, "target_resource_id": None, "data_collection_rule_id": "dataCollectionRuleId",
        "data_collection_endpoint_id": "dataCollectionEndpointId", "description": "description"}, {"id": "id"},
        "name"),
    "azurerm_monitor_metric_alert": Native(Arm("Microsoft.Insights/metricAlerts", "2026-01-01"), _metric_alert,
                                           {"id": "id"}, "name", "map"),
    "azurerm_monitor_scheduled_query_rules_alert_v2": Native(Arm("Microsoft.Insights/scheduledQueryRules",
                                                                 "2026-03-01"), _query_alert, {"id": "id"}, "name",
                                                             "map"),
    "azurerm_management_lock": Native(Arm("Microsoft.Authorization/locks", "2020-05-01", extends="scope"), {
        "name": None, "scope": None, "lock_level": "level", "notes": "notes"}, {"id": "id"}, "name"),
    "azurerm_monitor_data_collection_endpoint": Native(Arm("Microsoft.Insights/dataCollectionEndpoints", INSIGHTS), {
        **BASE, "kind": "kind", "description": "description"},
        {"id": "id", "logs_ingestion_endpoint": "logsIngestion.endpoint"}, "name", "map"),
    # DNS records (public and private zones), Traffic Manager
    **RECORDS,
    "azurerm_traffic_manager_profile": Native(Arm("Microsoft.Network/trafficmanagerprofiles", TM), _traffic_manager,
                                              {"id": "id", "fqdn": "dnsConfig.fqdn"}, "name", "map"),
    "azurerm_traffic_manager_external_endpoint": Native(Arm(
        "Microsoft.Network/trafficmanagerprofiles/ExternalEndpoints", TM,
        Parent("profile_id", "Microsoft.Network/trafficmanagerprofiles")), {
        "name": None, "profile_id": None, "target": "target", "weight": "weight", "priority": "priority",
        "endpoint_location": "endpointLocation", "enabled": _status("endpointStatus")}, {"id": "id"}, "name"),
    # Front Door
    "azurerm_cdn_frontdoor_profile": Native(Arm("Microsoft.Cdn/profiles", CDN), lambda f, cx: {
        "location": "global", **obj(own(f), cx, {
            "name": None, "resource_group_name": None,
            "sku_name": Custom(lambda v, c: {"sku": {"name": c.value(v)}}),
            "response_timeout_seconds": "originResponseTimeoutSeconds"})},
        {"id": "id", "name": "name", "resource_guid": "frontDoorId"}, "name", "map"),
    "azurerm_cdn_frontdoor_endpoint": Native(_profile_child("afdEndpoints"), lambda f, cx: {
        "location": "global", **obj(own(f), cx, {"name": None, "cdn_frontdoor_profile_id": None,
                                                 "enabled": _status("enabledState")})},
        {"id": "id", "host_name": "hostName"}, "name", "map"),
    "azurerm_cdn_frontdoor_origin_group": Native(_profile_child("originGroups"), {
        "name": None, "cdn_frontdoor_profile_id": None, "session_affinity_enabled": _status("sessionAffinityState"),
        "restore_traffic_time_to_healed_or_new_endpoint_in_minutes":
            "trafficRestorationTimeToHealedOrNewEndpointsInMinutes",
        "load_balancing": Nest("loadBalancingSettings", {
            "sample_size": "sampleSize", "successful_samples_required": "successfulSamplesRequired",
            "additional_latency_in_milliseconds": "additionalLatencyInMilliseconds"}),
        "health_probe": Nest("healthProbeSettings", {
            "protocol": "probeProtocol", "path": "probePath", "interval_in_seconds": "probeIntervalInSeconds",
            "request_type": "probeRequestType"})}, {"id": "id"}, "name"),
    "azurerm_cdn_frontdoor_origin": Native(_profile_child("originGroups/origins", "cdn_frontdoor_origin_group_id",
                                                          "Microsoft.Cdn/profiles/originGroups"), {
        "name": None, "cdn_frontdoor_origin_group_id": None, "enabled": _status("enabledState"),
        "host_name": "hostName", "http_port": "httpPort", "https_port": "httpsPort",
        "origin_host_header": "originHostHeader", "priority": "priority", "weight": "weight",
        "certificate_name_check_enabled": "enforceCertificateNameCheck"}, {"id": "id"}, "name"),
    "azurerm_cdn_frontdoor_secret": Native(_profile_child("secrets"), _fd_secret, {"id": "id"}, "name"),
    "azurerm_cdn_frontdoor_custom_domain": Native(_profile_child("customDomains"), {
        "name": None, "cdn_frontdoor_profile_id": None, "host_name": "hostName",
        "dns_zone_id": Custom(lambda v, cx: {"azureDnsZone": {"id": cx.value(v)}}),
        "tls": Custom(lambda v, cx: {"tlsSettings": obj(v[0], cx, {
            "certificate_type": "certificateType", "minimum_version": "minimumTlsVersion",
            "cdn_frontdoor_secret_id": Custom(lambda x, c: {"secret": {"id": c.value(x)}})}, f"{cx.where}.tls")})},
        {"id": "id", "validation_token": "validationProperties.validationToken"}, "name"),
    # a route waits for its origins: Front Door refuses a route to an origin group without one
    "azurerm_cdn_frontdoor_route": Native(_profile_child("afdEndpoints/routes", "cdn_frontdoor_endpoint_id",
                                                         "Microsoft.Cdn/profiles/afdEndpoints"), {
        "name": None, "cdn_frontdoor_endpoint_id": None, "cdn_frontdoor_origin_ids": None,
        "cdn_frontdoor_origin_group_id": Custom(lambda v, cx: {"originGroup": {"id": cx.value(v)}}),
        "cdn_frontdoor_custom_domain_ids": Custom(lambda v, cx: {"customDomains": [{"id": x}
                                                                                   for x in cx.value(v)]}),
        "cdn_frontdoor_origin_path": "originPath", "patterns_to_match": "patternsToMatch",
        "supported_protocols": "supportedProtocols", "forwarding_protocol": "forwardingProtocol",
        "https_redirect_enabled": _status("httpsRedirect"), "link_to_default_domain": _status("linkToDefaultDomain"),
        "enabled": _status("enabledState")}, {"id": "id"}, "name",
        waits=lambda f: (f.get("cdn_frontdoor_origin_ids", ()),)),
    "azurerm_cdn_frontdoor_custom_domain_association": Native(None, merge=Merge("cdn_frontdoor_route_ids",
                                                                                _fd_route_domains)),
    "azurerm_cdn_frontdoor_security_policy": Native(_profile_child("securityPolicies"), _fd_security, {"id": "id"},
                                                    "name"),
    "azurerm_cdn_frontdoor_firewall_policy": Native(Arm("Microsoft.Network/FrontDoorWebApplicationFirewallPolicies",
                                                        FD_WAF), _fd_waf, {"id": "id"}, "name", "map"),
    # network: peering, VPN, NAT
    "azurerm_virtual_network_peering": Native(Arm("Microsoft.Network/virtualNetworks/virtualNetworkPeerings", NETWORK,
                                                  Parent("virtual_network_name", "Microsoft.Network/virtualNetworks",
                                                         "name")), {
        "name": None, "resource_group_name": None, "virtual_network_name": None,
        "remote_virtual_network_id": Custom(lambda v, cx: {"remoteVirtualNetwork": {"id": cx.value(v)}}),
        "allow_virtual_network_access": "allowVirtualNetworkAccess", "allow_forwarded_traffic": "allowForwardedTraffic",
        "allow_gateway_transit": "allowGatewayTransit", "use_remote_gateways": "useRemoteGateways"},
        {"id": "id"}, "name"),
    "azurerm_local_network_gateway": Native(Arm("Microsoft.Network/localNetworkGateways", NETWORK), {
        **BASE, "gateway_address": "gatewayIpAddress", "gateway_fqdn": "fqdn",
        "address_space": Custom(lambda v, cx: {"localNetworkAddressSpace": {"addressPrefixes": cx.value(v)}}),
        "bgp_settings": Nest("bgpSettings", {"asn": "asn", "bgp_peering_address": "bgpPeeringAddress",
                                             "peer_weight": "peerWeight"})}, {"id": "id"}, "name", "map"),
    # a VPN connection is an azapi_resource (plumbing, U.5: azurerm's keeps its shared key in state), translated as
    # every azapi resource is
    "azurerm_nat_gateway_public_ip_prefix_association": Native(None, merge=Merge(
        "nat_gateway_id", lambda props, f, cx: {**props, "publicIpPrefixes": [
            *props.get("publicIpPrefixes", []), {"id": cx.value(f["public_ip_prefix_id"])}]})),
    # availability tests, the scripted checks' environment, policy exemptions
    "azurerm_container_app_environment": Native(Arm("Microsoft.App/managedEnvironments", APP), _app_environment,
                                                {"id": "id"}, "name", "map"),
    "azurerm_container_app_job": Native(Arm("Microsoft.App/jobs", APP), _app_job, {"id": "id"}, "name", "map",
                                        keep=_script_job),
    "azurerm_application_insights_standard_web_test": Native(Arm("Microsoft.Insights/webtests", WEBTESTS), _web_test,
                                                             {"id": "id"}, "name", "map"),
    "azurerm_subscription_policy_exemption": Native(Arm("Microsoft.Authorization/policyExemptions", EXEMPTIONS,
                                                        extends="subscription_id"), {
        "name": None, "subscription_id": None, "policy_assignment_id": "policyAssignmentId",
        "exemption_category": "exemptionCategory", "policy_definition_reference_ids": "policyDefinitionReferenceIds",
        "expires_on": "expiresOn", "description": "description", "display_name": "displayName",
        "metadata": "metadata"}, {"id": "id"}, "name"),
}


def _locked(cx):
    raise SystemExit(f"{cx.where}: a locked immutability policy is locked by an action ARM templates don't take")


# The API versions of the existing resources templates read by a literal id or by name (parents, extended resources)
APIS = {**{n.type.type: n.type.api_version for n in TYPES.values()
           if isinstance(n.type, Arm) and isinstance(n.type.type, str)},
        "Microsoft.KeyVault/vaults/secrets": KEYVAULT, "Microsoft.KeyVault/vaults/keys": KEYVAULT,
        "Microsoft.Storage/storageAccounts/blobServices": STORAGE, "Microsoft.Network/publicIPAddresses": NETWORK,
        "Microsoft.ContainerService/managedClusters": AKS, "Microsoft.Network/firewallPolicies": NETWORK,
        "Microsoft.Network/networkWatchers": NETWORK, "Microsoft.Network/networkSecurityGroups": NETWORK,
        "Microsoft.Network/virtualNetworks": NETWORK, "Microsoft.Compute/virtualMachines": COMPUTE,
        "Microsoft.Storage/storageAccounts": STORAGE, "Microsoft.KeyVault/vaults": KEYVAULT,
        "Microsoft.OperationalInsights/workspaces": OPINSIGHTS, "Microsoft.Network/privateDnsZones": PRIVATE_DNS,
        "Microsoft.Network/dnsZones": DNS,
        "Microsoft.DBforPostgreSQL/flexibleServers": POSTGRES,
        "Microsoft.ManagedIdentity/userAssignedIdentities": IDENTITY}


def arm_files(m, files, what, targets):
    """{path: TfFile | text} of environment m's ARM templates from its Azure Terraform render, for the targets
    (bicep, arm)."""
    return translated(m, files, TYPES, NO_NATIVE, DATA, what, targets, KEPT, APIS, INPUT_SCOPES)


def arm_translation(m, files, what):
    """The arm_render.Translation of environment m's Azure Terraform render by this table."""
    return translation(m, files, TYPES, NO_NATIVE, DATA, what, KEPT, APIS, INPUT_SCOPES)

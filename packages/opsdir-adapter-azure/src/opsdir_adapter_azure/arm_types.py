"""The Azure render's Terraform types as ARM (5.6, decisions 2592 and 2605): one row per resource type the renderers
write (arm_render translates by it), what the lookups Terraform makes are natively (existing resources, the
deployment's own resource group and subscription, secure parameters), the types ARM has no form for, and the types
kept in Terraform for a stated reason. API versions are the latest stable ones in Microsoft's template reference
(research 2595); bicep build and lint check every rendered template against them. Pure data and small pure
converters.
"""
from opsdir_format_arm.template import Call, Interp, Member, ResourceId
from opsdir_format_terraform.native import Computed, Custom, FromBlock, Merge, Native, Nest, obj, one, own
from .arm_render import Arm, Existing, Fixed, Lookup, Parent, Secure, translated, translation

NETWORK, IDENTITY, INSIGHTS, OPINSIGHTS = "2025-09-01", "2023-01-31", "2024-03-11", "2025-07-01"
KEYVAULT, AKS, PIM = "2024-11-01", "2025-05-01", "2024-09-01-preview"
# Types ARM has no form for: they stay in the Terraform root beside the templates (research 2595).
NO_NATIVE = frozenset({"azapi_data_plane_resource", "azuread_conditional_access_policy"})
_SUBNET = ("a property of the landing zone's subnet: ARM sets it only by re-declaring the whole subnet, which the "
           "landing zone keeps")
# Types kept in Terraform for a stated reason.
KEPT = {
    "azurerm_subnet_network_security_group_association": _SUBNET,
    "azurerm_subnet_route_table_association": _SUBNET,
    "azurerm_subnet_nat_gateway_association": _SUBNET,
}
# Built-in role definitions by name -> their GUIDs: Microsoft's built-in roles page; "built-in roles have the same role
# ID across clouds" (Azure role definitions page). Research 2612.
ROLES = {
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
    "azurerm_private_dns_zone": _lookup("Microsoft.Network/privateDnsZones", "2024-06-01", {"id": "id"}),
    "azurerm_log_analytics_workspace": _lookup("Microsoft.OperationalInsights/workspaces", OPINSIGHTS,
                                               {"id": "id", "workspace_id": "customerId", "location": "location"}),
    "azurerm_kubernetes_cluster": _lookup("Microsoft.ContainerService/managedClusters", AKS,
                                          {"id": "id", "oidc_issuer_url": "oidcIssuerProfile.issuerURL"}),
    "azurerm_role_definition": lambda f, a: (Computed(lambda f, value: _role_definition(value(f["name"]),
                                                                                         "data.azurerm_role_definition"))
                                             if a in ("id", "role_definition_id") else None),
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

COMPUTE, DISKS, STORAGE, POSTGRES, BACKUP = "2026-04-01", "2025-01-02", "2025-06-01", "2025-08-01", "2025-02-01"


def _identity(v, cx):
    """An identity block as ARM's identity: its type, user-assigned identities keyed by id."""
    b = v[0]
    ids = cx.value(b.get("identity_ids", ()))
    return {"identity": {"type": cx.value(b["type"]),
                         **({"userAssignedIdentities": {i: {} for i in ids}} if ids else {})}}


def _vm(f, cx):
    """A Linux virtual machine: hardware, OS profile (SSH keys only), storage (image, OS disk), NICs."""
    user = cx.value(f["admin_username"])
    disk = one(f, "os_disk")
    keys = [{"path": f"/home/{user}/.ssh/authorized_keys", "keyData": cx.value(k["public_key"])}
            for k in f.get("admin_ssh_key", ())]
    rest = {k: v for k, v in own(f).items() if k not in ("admin_ssh_key", "os_disk", "admin_username", "size",
                                                         "computer_name", "network_interface_ids",
                                                         "source_image_id")}
    unknown = sorted(set(disk) - {"caching", "storage_account_type", "disk_encryption_set_id"})
    if unknown:
        raise SystemExit(f"{cx.where}.os_disk: no ARM form for {', '.join(unknown)}")
    managed = {"storageAccountType": cx.value(disk["storage_account_type"]),
               **({"diskEncryptionSet": {"id": cx.value(disk["disk_encryption_set_id"])}}
                  if "disk_encryption_set_id" in disk else {})}
    return {**obj(rest, cx, {**BASE, "zone": Custom(lambda v, c: {"zones": [c.value(v)]}),
                             "identity": Custom(_identity)}),
            "hardwareProfile": {"vmSize": cx.value(f["size"])},
            "osProfile": {"computerName": cx.value(f.get("computer_name", f["name"])), "adminUsername": user,
                          "linuxConfiguration": {"disablePasswordAuthentication": True,
                                                 "ssh": {"publicKeys": keys}}},
            "storageProfile": {"imageReference": {"id": cx.value(f["source_image_id"])},
                               "osDisk": {"createOption": "FromImage", "caching": cx.value(disk["caching"]),
                                          "managedDisk": managed}},
            "networkProfile": {"networkInterfaces": [{"id": i} for i in cx.value(f["network_interface_ids"])]}}


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
    settings = obj(one(f, "blob_properties"), cx, {"versioning_enabled": "isVersioningEnabled"},
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


def _postgres(f, cx):
    """A PostgreSQL flexible server: sku from Terraform's tier-prefixed name, storage in GB, its network, the
    write-only administrator password (an ephemeral secret: a secure parameter), its customer-managed key."""
    tier, _, sku = cx.value(f["sku_name"]).partition("_")
    key = one(f, "customer_managed_key")
    return {"sku": {"name": sku, "tier": SKU_TIERS[tier]},
            **obj({k: v for k, v in own(f).items() if k not in ("sku_name", "customer_managed_key")}, cx, {
                **BASE, "version": "version", "zone": "availabilityZone",
                "administrator_login": "administratorLogin", "administrator_password_wo": "administratorLoginPassword",
                "administrator_password_wo_version": None,
                "storage_mb": Custom(lambda v, c: {"storage": {"storageSizeGB": c.value(v) // 1024}}),
                "backup_retention_days": Custom(lambda v, c: {"backup": {"backupRetentionDays": c.value(v)}}),
                "delegated_subnet_id": None, "private_dns_zone_id": None, "public_network_access_enabled": None,
                "identity": Custom(_identity)}),
            "network": {**({"delegatedSubnetResourceId": cx.value(f["delegated_subnet_id"])}
                           if "delegated_subnet_id" in f else {}),
                        **({"privateDnsZoneArmResourceId": cx.value(f["private_dns_zone_id"])}
                           if "private_dns_zone_id" in f else {}),
                        **({"publicNetworkAccess": "Enabled" if f["public_network_access_enabled"] else "Disabled"}
                           if "public_network_access_enabled" in f else {})},
            **({"dataEncryption": {"type": "AzureKeyVault", "primaryKeyURI": cx.value(key["key_vault_key_id"]),
                                   "primaryUserAssignedIdentityId": cx.value(
                                       key["primary_user_assigned_identity_id"])}} if key else {})}


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
            "trusted_root_certificate_names": Custom(lambda v, c: {"trustedRootCertificates": [
                _self_child(c, "trustedRootCertificates", x) for x in c.value(v)]})}),
        "probe": ("probes", {"protocol": "protocol", "host": "host", "port": "port", "path": "path",
                             "interval": "interval", "timeout": "timeout", "unhealthy_threshold": "unhealthyThreshold",
                             "pick_host_name_from_backend_http_settings": "pickHostNameFromBackendHttpSettings",
                             "match": Custom(lambda v, c: {"match": {"statusCodes": c.value(v[0]["status_code"])}})}),
        "http_listener": ("httpListeners", {
            "frontend_ip_configuration_name": ref("frontendIPConfigurations"),
            "frontend_port_name": ref("frontendPorts"), "protocol": "protocol", "host_name": "hostName",
            "ssl_certificate_name": ref("sslCertificates")}),
        "request_routing_rule": ("requestRoutingRules", {
            "priority": "priority", "rule_type": "ruleType", "http_listener_name": ref("httpListeners"),
            "backend_address_pool_name": ref("backendAddressPools"),
            "backend_http_settings_name": ref("backendHttpSettingsCollection")}),
        "ssl_certificate": ("sslCertificates", {"key_vault_secret_id": "keyVaultSecretId"}),
        "trusted_root_certificate": ("trustedRootCertificates", {"key_vault_secret_id": "keyVaultSecretId"})}
    found = {key: _named(f[tf], cx, spec, tf) for tf, (key, spec) in parts.items() if tf in f}
    rest = {k: v for k, v in own(f).items() if k not in parts}
    return {**found, **obj(rest, cx, {
        **BASE, "zones": "zones", "identity": Custom(_identity),
        "sku": Custom(lambda v, c: {"sku": obj(v[0], c, {"name": "name", "tier": "tier", "capacity": "capacity"},
                                                f"{c.where}.sku")}),
        "autoscale_configuration": Custom(lambda v, c: {"autoscaleConfiguration": obj(v[0], c, {
            "min_capacity": "minCapacity", "max_capacity": "maxCapacity"}, f"{c.where}.autoscale_configuration")}),
        "ssl_policy": Custom(lambda v, c: {"sslPolicy": obj(v[0], c, {
            "policy_type": "policyType", "policy_name": "policyName", "min_protocol_version": "minProtocolVersion",
            "cipher_suites": "cipherSuites"}, f"{c.where}.ssl_policy")}),
        "firewall_policy_id": Custom(lambda v, c: {"firewallPolicy": {"id": c.value(v)}}),
        "enable_http2": "enableHttp2"})}


_REF_KEYS = {"probes": "probe", "frontendIPConfigurations": "frontendIPConfiguration",
             "frontendPorts": "frontendPort", "sslCertificates": "sslCertificate", "httpListeners": "httpListener",
             "backendAddressPools": "backendAddressPool", "backendHttpSettingsCollection": "backendHttpSettings"}


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


def _rule_collection_group(f, cx):
    """A firewall policy rule collection group: its application rule collections (filter collections)."""
    def collection(c):
        return {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": cx.value(c["name"]),
                "priority": cx.value(c["priority"]), "action": {"type": cx.value(c["action"])},
                "rules": [{"ruleType": "ApplicationRule", **obj(r, cx, {
                    "name": "name", "source_addresses": "sourceAddresses", "destination_fqdns": "targetFqdns",
                    "destination_fqdn_tags": "fqdnTags", "description": "description",
                    "protocols": Custom(lambda v, c2: {"protocols": [
                        {"protocolType": c2.value(x["type"]), "port": c2.value(x["port"])} for x in v]})},
                    f"{cx.where}.rule")} for r in c.get("rule", ())]}
    unknown = sorted(set(own(f)) - {"name", "firewall_policy_id", "priority", "application_rule_collection"})
    if unknown:
        raise SystemExit(f"{cx.where}: no ARM form for {', '.join(unknown)}")
    return {"priority": cx.value(f["priority"]),
            "ruleCollections": [collection(c) for c in f.get("application_rule_collection", ())]}


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


def _vault_key(props, f, cx):
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


def _automation(f, cx):
    return obj(own(f), cx, {
        **BASE, "description": "description", "enabled": "isEnabled",
        "scopes": Custom(lambda v, c: {"scopes": [{"scopePath": x} for x in c.value(v)]}),
        "source": Custom(lambda v, c: {"sources": [obj(x, c, {"event_source": "eventSource"}, f"{c.where}.source")
                                                   for x in v]}),
        "action": Custom(lambda v, c: {"actions": [{"actionType": c.value(x["type"]), **(
            {"workspaceResourceId": c.value(x["resource_id"])} if c.value(x["type"]) == "Workspace" else
            {"logicAppResourceId": c.value(x["resource_id"])} if c.value(x["type"]) == "LogicApp" else
            {"eventHubResourceId": c.value(x["resource_id"])})} for x in v]})})

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


def _azapi(f, cx):
    """An azapi resource: its body, whose properties are the resource's (the rest top-level fields)."""
    body = cx.value(f.get("body", {}))
    rest = sorted(set(own(f)) - {"type", "name", "parent_id", "body", "schema_validation_enabled"})
    if rest:
        raise SystemExit(f"{cx.where}: no ARM form for {', '.join(rest)}")
    return {**{k: v for k, v in body.items() if k != "properties"}, **body.get("properties", {})}

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
        **BASE, "bgp_route_propagation_enabled": Custom(lambda v, cx: {"disableBgpRoutePropagation": not v})},
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
    "azapi_resource": Native(Arm(lambda f: tuple(f["type"].split("@")), None, extends="parent_id"), _azapi,
                             {"id": "id"}, "name"),
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
    "azurerm_private_dns_a_record": Native(Arm("Microsoft.Network/privateDnsZones/A", "2024-06-01",
                                               Parent("private_dns_zone_id", "Microsoft.Network/privateDnsZones")), {
        "name": None, "private_dns_zone_id": None, "ttl": "ttl",
        "records": Custom(lambda v, cx: {"aRecords": [{"ipv4Address": x} for x in cx.value(v)]})},
        {"id": "id", "fqdn": "fqdn"}, "name", "map", tags_key="metadata"),
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
        "data_protection_backup_vault_id", _vault_key)),
    "azurerm_data_protection_backup_policy_disk": Native(Arm(
        "Microsoft.DataProtection/backupVaults/backupPolicies", BACKUP,
        Parent("vault_id", "Microsoft.DataProtection/backupVaults")), _disk_policy, {"id": "id"}, "name"),
    "azurerm_data_protection_backup_instance_disk": Native(Arm(
        "Microsoft.DataProtection/backupVaults/backupInstances", BACKUP,
        Parent("vault_id", "Microsoft.DataProtection/backupVaults")), _disk_instance, {"id": "id"}, "name"),
    "azurerm_security_center_automation": Native(Arm("Microsoft.Security/automations", "2019-01-01-preview"),
                                                 _automation, {"id": "id"}, "name", "map"),
    # compute
    "azurerm_linux_virtual_machine": Native(Arm("Microsoft.Compute/virtualMachines", COMPUTE), _vm,
                                            {"id": "id", "name": "name",
                                             "identity[0].principal_id": "identity.principalId"}, "name", "map"),
    "azurerm_virtual_machine_data_disk_attachment": Native(None, merge=Merge("virtual_machine_id", _data_disk)),
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
                                                 _postgres, {"id": "id", "name": "name",
                                                             "fqdn": "fullyQualifiedDomainName"}, "name", "map"),
    "azurerm_postgresql_flexible_server_configuration": Native(Arm(
        "Microsoft.DBforPostgreSQL/flexibleServers/configurations", POSTGRES,
        Parent("server_id", "Microsoft.DBforPostgreSQL/flexibleServers")), {
        "name": None, "server_id": None, "value": Custom(lambda v, cx: {"value": cx.value(v),
                                                                         "source": "user-override"})},
        {"id": "id"}, "name"),
    # monitoring
    "azurerm_log_analytics_workspace_table_custom_log": Native(Arm(
        "Microsoft.OperationalInsights/workspaces/tables", OPINSIGHTS,
        Parent("workspace_id", "Microsoft.OperationalInsights/workspaces"), fields=()), lambda f, cx: obj(own(f), cx, {
            "name": None, "workspace_id": None, "plan": "plan", "retention_in_days": "retentionInDays",
            "column": Custom(lambda v, c: {"schema": {"name": c.value(f["name"]), "columns": [
                {"name": c.value(x["name"]), "type": c.value(x["type"])} for x in v]}})}), {"id": "id"}, "name"),
    "azurerm_monitor_data_collection_rule": Native(Arm("Microsoft.Insights/dataCollectionRules", INSIGHTS), _dcr,
                                                   {"id": "id"}, "name", "map"),
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
        **BASE, "kind": "kind", "description": "description"}, {"id": "id"}, "name", "map"),
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
        "Microsoft.OperationalInsights/workspaces": OPINSIGHTS, "Microsoft.Network/privateDnsZones": "2024-06-01",
        "Microsoft.DBforPostgreSQL/flexibleServers": POSTGRES,
        "Microsoft.ManagedIdentity/userAssignedIdentities": IDENTITY}


def arm_files(m, files, what, targets):
    """{path: TfFile | text} of environment m's ARM templates from its Azure Terraform render, for the targets
    (bicep, arm)."""
    return translated(m, files, TYPES, NO_NATIVE, DATA, what, targets, KEPT, APIS)


def arm_translation(m, files, what):
    """The arm_render.Translation of environment m's Azure Terraform render by this table."""
    return translation(m, files, TYPES, NO_NATIVE, DATA, what, KEPT, APIS)

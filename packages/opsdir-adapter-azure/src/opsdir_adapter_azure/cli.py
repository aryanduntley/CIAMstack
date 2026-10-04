"""What the Azure CLI reports about an environment, read into the record's neutral resources. Pure.

The outputs of `az … -o json` (lists or single objects), saved under <cloud>/<env>/ with any file names, are recognized
item by item from their ARM type, or for Key Vault's data plane from their IDs, and normalized to the attribute names
of the matching hashicorp/azurerm resource, so the same mapping reads them as reads Terraform state
(opsdir_adapter_azure.inventory.pairs_resources):

  az network vnet list                  Microsoft.Network/virtualNetworks (+ its subnets and their NSGs)
  az network vnet subnet list           Microsoft.Network/virtualNetworks/subnets
  az vm list -d                         Microsoft.Compute/virtualMachines (-d adds the private addresses)
  az network nic list                   Microsoft.Network/networkInterfaces (+ backend pool and NSG associations)
  az network lb list                    Microsoft.Network/loadBalancers (+ backend pools and rules)
  az network public-ip list             Microsoft.Network/publicIPAddresses
  az network public-ip prefix list      Microsoft.Network/publicIPPrefixes
  az network dns record-set a list      Microsoft.Network/dnszones/A
  az network private-dns record-set a list   Microsoft.Network/privateDnsZones/A
  az network nsg list                   Microsoft.Network/networkSecurityGroups (+ rules, NIC and subnet associations;
                                        the default rules aren't read)
  az network nsg rule list              Microsoft.Network/networkSecurityGroups/securityRules
  az network nat gateway list           Microsoft.Network/natGateways (+ public IP and prefix associations)
  az disk-encryption-set list           Microsoft.Compute/diskEncryptionSets
  az storage container-rm list          Microsoft.Storage/storageAccounts/blobServices/containers (with metadata)
  az keyvault secret list               https://<vault>.vault.azure.net/secrets/<name>: never a value
  az keyvault key list / key show       https://<vault>.vault.azure.net/keys/<name>: key type from `key show`
  az keyvault key rotation-policy show  …/keys/<name>/rotationpolicy: whether the key rotates automatically
  az functionapp list                   Microsoft.Web/sites (kind functionapp: runtime from siteConfig.linuxFxVersion)
  az functionapp function list          Microsoft.Web/sites/functions (timer trigger schedules from config.bindings)
  the edge: application gateways, WAF policies, Front Door, DDoS plans, Traffic Manager, DNS zones and record sets of
  every type, forwarding rules            see cli_edge.py
  access control: identities, role assignments and definitions, PIM, deny assignments, access policies, policy
  assignments, bastions                 see cli_iam.py (az rest output, {"value": [...]}, is read item by item)
Subnets, interfaces and VMs outside the listed virtual networks are counted, not read; secrets, keys and containers
are listed per vault and account, and function apps per resource group, so the importer counts rather than lists the
ones the record doesn't have and nothing names a role for.
"""
import json
from collections import Counter
from functools import reduce

from opsdir.core.contract import Importer
from opsdir.core.inventory import layout_import
from .cli_edge import edge_items
from .cli_iam import iam_items
from .inventory import PROVIDER, arm_segment, pairs_resources

ACCOUNT_WIDE = ("secret", "key", "storage", "job", "identity")
VAULT_HOSTS = (".vault.azure.net", ".vault.usgovcloudapi.net")


def _low(x):
    return (x or "").lower()


def _id(ref):
    """The id of an ARM reference object ({"id": …}), else None."""
    return (ref or {}).get("id") if isinstance(ref, dict) else None


def vault_object(url):
    """(vault, collection, name) of a Key Vault object URL (https://<vault>.vault.azure.net/<secrets|keys>/<name>/…);
    None for anything else."""
    host, _, path = (url or "").partition("://")[2].partition("/")
    parts = path.split("/")
    if not any(host.lower().endswith(h) for h in VAULT_HOSTS) or len(parts) < 2 or parts[0] not in ("secrets", "keys"):
        return None
    return host.split(".")[0].lower(), parts[0], parts[1]


def kind_of(item):
    """What an item is: its ARM type (lower case), or 'kv-secret' / 'kv-key' / 'kv-rotation' for Key Vault objects."""
    if not isinstance(item, dict):
        return None
    if item.get("type"):
        return _low(item["type"])
    if "lifetimeActions" in item:
        return "kv-rotation"
    obj = vault_object(item.get("id") or item.get("kid") or (item.get("key") or {}).get("kid"))
    return {"secrets": "kv-secret", "keys": "kv-key"}.get(obj[1]) if obj else None


def _items(texts):
    """((kind, item) of every item recognized), notices for files and items that aren't."""
    def parse(text):
        try:
            doc = json.loads(text)
        except ValueError:
            return None
        if isinstance(doc, dict) and isinstance(doc.get("value"), list):
            return doc["value"]                                         # az rest: {"value": [...]}
        return doc if isinstance(doc, list) else [doc]
    docs = {p: parse(t) for p, t in sorted(texts.items())}
    kinds = {p: [(kind_of(i), i) for i in doc] for p, doc in docs.items() if doc is not None}
    return ([(k, i) for found in kinds.values() for k, i in found if k],
            (*(f"{p}: not JSON; not read" for p, doc in docs.items() if doc is None),
             *(f"{p}: {n} item(s) that aren't Azure CLI output this importer reads; not read"
               for p, found in kinds.items() for n in (sum(1 for k, _ in found if not k),) if n)))


def _of(items, kind):
    return [i for k, i in items if k == kind.lower()]


def _vnets(items):
    vnets = _of(items, "Microsoft.Network/virtualNetworks")
    listed = [(s, arm_segment(s.get("id"), "virtualNetworks")) for s in _of(items, "Microsoft.Network/virtualNetworks/subnets")]
    subnets = [*((s, v.get("name")) for v in vnets for s in v.get("subnets") or ()), *listed]
    return [*(("azurerm_virtual_network", {"id": v.get("id"), "name": v.get("name"), "tags": v.get("tags") or {},
                                           "resource_group_name": v.get("resourceGroup"),
                                           "address_space": (v.get("addressSpace") or {}).get("addressPrefixes")})
              for v in vnets),
            *(("azurerm_subnet", {"id": s.get("id"), "name": s.get("name"), "virtual_network_name": vnet,
                                  "address_prefixes": s.get("addressPrefixes") or [s.get("addressPrefix")]})
              for s, vnet in subnets),
            *(("azurerm_subnet_network_security_group_association",
               {"subnet_id": s.get("id"), "network_security_group_id": _id(s.get("networkSecurityGroup"))})
              for s, _ in subnets if _id(s.get("networkSecurityGroup")))]


def _vms(items):
    def image(vm):
        ref = ((vm.get("storageProfile") or {}).get("imageReference")) or {}
        return {"source_image_id": ref.get("id"),
                "source_image_reference": [{"publisher": ref.get("publisher"), "offer": ref.get("offer"),
                                            "sku": ref.get("sku"), "version": ref.get("exactVersion") or ref.get("version")}]
                if ref.get("offer") else []}
    return [("azurerm_linux_virtual_machine", {
                "id": vm.get("id"), "name": vm.get("name"), "tags": vm.get("tags") or {},
                "computer_name": (vm.get("osProfile") or {}).get("computerName"),
                "size": (vm.get("hardwareProfile") or {}).get("vmSize"), "zone": (vm.get("zones") or [None])[0],
                "private_ip_address": (vm.get("privateIps") or "").split(",")[0] or None,
                "network_interface_ids": [n.get("id") for n in (vm.get("networkProfile") or {}).get("networkInterfaces") or ()
                                          if n.get("id")], **image(vm)})
            for vm in _of(items, "Microsoft.Compute/virtualMachines")]


def _nics(items):
    nics = _of(items, "Microsoft.Network/networkInterfaces")

    def configs(n):
        return n.get("ipConfigurations") or ()
    return [*(("azurerm_network_interface", {
                "id": n.get("id"), "name": n.get("name"),
                "ip_configuration": [{"name": c.get("name"), "primary": c.get("primary"),
                                      "private_ip_address": c.get("privateIPAddress") or c.get("privateIpAddress"),
                                      "subnet_id": _id(c.get("subnet"))} for c in configs(n)]})
              for n in nics),
            *(("azurerm_network_interface_backend_address_pool_association",
               {"network_interface_id": n.get("id"), "backend_address_pool_id": _id(pool)})
              for n in nics for c in configs(n) for pool in c.get("loadBalancerBackendAddressPools") or ()),
            *(("azurerm_network_interface_security_group_association",
               {"network_interface_id": n.get("id"), "network_security_group_id": _id(n.get("networkSecurityGroup"))})
              for n in nics if _id(n.get("networkSecurityGroup")))]


def _nic_of(ip_config_id):
    """The NIC ID of one of its IP configurations' IDs (…/networkInterfaces/<nic>/ipConfigurations/<name>)."""
    head, sep, _ = (ip_config_id or "").partition("/ipConfigurations/")
    return head if sep else None


def _lbs(items):
    lbs = _of(items, "Microsoft.Network/loadBalancers")
    return [*(("azurerm_lb", {"id": lb.get("id"), "name": lb.get("name"), "tags": lb.get("tags") or {},
                              "frontend_ip_configuration": [
                                  {"name": f.get("name"),
                                   "private_ip_address": f.get("privateIPAddress") or f.get("privateIpAddress"),
                                   "public_ip_address_id": _id(f.get("publicIPAddress") or f.get("publicIpAddress")),
                                   "subnet_id": _id(f.get("subnet"))} for f in lb.get("frontendIPConfigurations") or ()]})
              for lb in lbs),
            *(("azurerm_lb_backend_address_pool", {"id": p.get("id"), "loadbalancer_id": lb.get("id")})
              for lb in lbs for p in lb.get("backendAddressPools") or ()),
            *(("azurerm_network_interface_backend_address_pool_association",
               {"network_interface_id": _nic_of(c.get("id")), "backend_address_pool_id": p.get("id")})
              for lb in lbs for p in lb.get("backendAddressPools") or () for c in p.get("backendIPConfigurations") or ()
              if _nic_of(c.get("id"))),
            *(("azurerm_lb_rule", {"loadbalancer_id": lb.get("id"), "frontend_port": r.get("frontendPort"),
                                   "load_distribution": r.get("loadDistribution"),
                                   "idle_timeout_in_minutes": r.get("idleTimeoutInMinutes")})
              for lb in lbs for r in lb.get("loadBalancingRules") or ()),
            *(("azurerm_lb_probe", {"loadbalancer_id": lb.get("id"), "protocol": p.get("protocol"),
                                    "request_path": p.get("requestPath")})
              for lb in lbs for p in lb.get("probes") or ())]


def _addresses(items):
    return [*(("azurerm_public_ip", {"id": p.get("id"), "name": p.get("name"), "ip_address": p.get("ipAddress")})
              for p in _of(items, "Microsoft.Network/publicIPAddresses")),
            *(("azurerm_public_ip_prefix", {"id": p.get("id"), "ip_prefix": p.get("ipPrefix")})
              for p in _of(items, "Microsoft.Network/publicIPPrefixes"))]


def _records(items):
    def one(r, zone_key, type_):
        fqdn = _low(r.get("fqdn")).rstrip(".")
        zone = arm_segment(r.get("id"), zone_key) or (fqdn[len(r.get("name", "")) + 1:] if r.get("name") != "@" else fqdn)
        return (type_, {"name": r.get("name"), "zone_name": _low(zone), "ttl": r.get("ttl") or r.get("TTL"),
                        "records": [a.get("ipv4Address") for a in r.get("aRecords") or r.get("ARecords") or ()],
                        "target_resource_id": _id(r.get("targetResource"))})
    return [*(one(r, "dnszones", "azurerm_dns_a_record") for r in _of(items, "Microsoft.Network/dnszones/A")),
            *(one(r, "privateDnsZones", "azurerm_private_dns_a_record")
              for r in _of(items, "Microsoft.Network/privateDnsZones/A"))]


def _rule(r):
    return {"name": r.get("name"), "priority": r.get("priority"), "direction": r.get("direction"),
            "access": r.get("access"), "protocol": r.get("protocol"), "description": r.get("description"),
            "source_address_prefix": r.get("sourceAddressPrefix"),
            "source_address_prefixes": r.get("sourceAddressPrefixes") or [],
            "destination_port_range": r.get("destinationPortRange"),
            "destination_port_ranges": r.get("destinationPortRanges") or []}


def _nsgs(items):
    nsgs = _of(items, "Microsoft.Network/networkSecurityGroups")
    return [*(("azurerm_network_security_group", {"id": g.get("id"), "name": g.get("name"), "tags": g.get("tags") or {},
                                                  "resource_group_name": g.get("resourceGroup"),
                                                  "security_rule": [_rule(r) for r in g.get("securityRules") or ()]})
              for g in nsgs),
            *(("azurerm_network_interface_security_group_association",
               {"network_interface_id": n.get("id"), "network_security_group_id": g.get("id")})
              for g in nsgs for n in g.get("networkInterfaces") or ()),
            *(("azurerm_subnet_network_security_group_association",
               {"subnet_id": s.get("id"), "network_security_group_id": g.get("id")})
              for g in nsgs for s in g.get("subnets") or ()),
            *(("azurerm_network_security_rule", {**_rule(r), "resource_group_name": arm_segment(r.get("id"), "resourceGroups"),
                                                 "network_security_group_name": arm_segment(r.get("id"),
                                                                                         "networkSecurityGroups")})
              for r in _of(items, "Microsoft.Network/networkSecurityGroups/securityRules"))]


def _nats(items):
    nats = _of(items, "Microsoft.Network/natGateways")
    return [*(("azurerm_nat_gateway", {"id": n.get("id"), "name": n.get("name"), "tags": n.get("tags") or {}})
              for n in nats),
            *(("azurerm_nat_gateway_public_ip_association",
               {"nat_gateway_id": n.get("id"), "public_ip_address_id": p.get("id")})
              for n in nats for p in n.get("publicIpAddresses") or n.get("publicIPAddresses") or ()),
            *(("azurerm_nat_gateway_public_ip_prefix_association",
               {"nat_gateway_id": n.get("id"), "public_ip_prefix_id": p.get("id")})
              for n in nats for p in n.get("publicIpPrefixes") or n.get("publicIPPrefixes") or ())]


def _vault_name(url):
    """(vault, object name) of a Key Vault object URL."""
    vault, _, name = vault_object(url)
    return vault, name


def _vault_items(items):
    """Key Vault secrets and keys by (vault, name), keys merged across `key list`, `key show` and rotation policies;
    a secret's value is never looked at."""
    secrets = {_vault_name(s.get("id")): s for s in _of(items, "kv-secret")}
    keys = [(_vault_name(k.get("kid") or (k.get("key") or {}).get("kid")), k) for k in _of(items, "kv-key")]
    policies = {_vault_name(p.get("id")): p for p in _of(items, "kv-rotation") if vault_object(p.get("id"))}
    merged = reduce(lambda acc, kv: {**acc, kv[0]: {**acc.get(kv[0], {}),        # key show adds to key list
                                                    **{f: v for f, v in kv[1].items() if v is not None}}}, keys, {})

    def rotation(at):
        if at not in policies:
            return {}
        rotate = [a for a in policies[at].get("lifetimeActions") or () if _low((a.get("action") or {}).get("type")) == "rotate"]
        return {"rotation_policy": [{"automatic": rotate}]}
    return [*(("azurerm_key_vault_secret", {"name": name, "key_vault_id": f"/vaults/{vault}", "tags": s.get("tags") or {}})
              for (vault, name), s in secrets.items() if not s.get("managed")),
            *(("azurerm_key_vault_key", {"name": name, "key_vault_id": f"/vaults/{vault}", "tags": k.get("tags") or {},
                                         "key_type": (k.get("key") or {}).get("kty"), **rotation((vault, name))})
              for (vault, name), k in merged.items() if not k.get("managed"))]


def _stores(items):
    return [*(("azurerm_disk_encryption_set", {"id": s.get("id"), "name": s.get("name"),
                                               "key_vault_key_id": (s.get("activeKey") or {}).get("keyUrl")})
              for s in _of(items, "Microsoft.Compute/diskEncryptionSets")),
            *(("azurerm_storage_container", {"id": c.get("id"), "name": c.get("name"), "metadata": c.get("metadata") or {},
                                             "storage_account_name": arm_segment(c.get("id"), "storageAccounts")})
              for c in _of(items, "Microsoft.Storage/storageAccounts/blobServices/containers"))]


def _fx_runtime(fx):
    """"Python|3.11" (siteConfig.linuxFxVersion) -> {"python_version": "3.11"}, the Terraform application stack."""
    lang, _, version = (fx or "").partition("|")
    return {f"{lang.lower()}_version": version} if lang and version else {}


def _functions(items):
    """Function apps (Microsoft.Web/sites whose kind says functionapp) and their functions."""
    apps = [a for a in _of(items, "Microsoft.Web/sites") if "functionapp" in _low(a.get("kind"))]
    return [*(("azurerm_linux_function_app", {
                "id": a.get("id"), "name": a.get("name"), "tags": a.get("tags") or {},
                "site_config": [{"application_stack": [_fx_runtime((a.get("siteConfig") or {}).get("linuxFxVersion")
                                                                   or a.get("linuxFxVersion"))]}]})
              for a in apps),
            *(("azurerm_function_app_function", {"id": f.get("id"), "name": f.get("name"),
                                                 "function_app_id": (f.get("id") or "").rsplit("/functions/", 1)[0],
                                                 "config_json": json.dumps(f.get("config") or {})})
              for f in _of(items, "Microsoft.Web/sites/functions"))]


def _unique(pairs):
    """Pairs without repeats (a subnet listed inside its network and on its own, an association seen from both ends)."""
    return list({(t, json.dumps(a, sort_keys=True)): (t, a) for t, a in pairs}.values())


def _scoped(pairs):
    """(pairs, notices): subnets, interfaces and VMs of the listed virtual networks only, when any are listed."""
    vnets = {_low(a.get("name")) for t, a in pairs if t == "azurerm_virtual_network"}
    if not vnets:
        return pairs, ()

    def vnet_of(subnet_id):
        return _low(arm_segment(subnet_id, "virtualNetworks"))
    out_nics = {_low(a.get("id")) for t, a in pairs if t == "azurerm_network_interface"
                and any(c.get("subnet_id") and vnet_of(c["subnet_id"]) not in vnets for c in a["ip_configuration"])}
    outside = [(t, a) for t, a in pairs
               if (t == "azurerm_subnet" and _low(a.get("virtual_network_name")) not in vnets)
               or (t == "azurerm_network_interface" and _low(a.get("id")) in out_nics)
               or (t == "azurerm_linux_virtual_machine" and a["network_interface_ids"]
                   and all(_low(n) in out_nics for n in a["network_interface_ids"]))]
    counted = Counter(t for t, _ in outside)
    return ([p for p in pairs if p not in outside],
            tuple(f"{t} ({n}): outside the listed virtual networks ({', '.join(sorted(vnets))}); not read"
                  for t, n in sorted(counted.items())))


def items_resources(items):
    """(resources, notices) of (kind, item) pairs in the shape the Azure CLI prints ARM resources (properties
    flattened): also what ARM templates are read into (opsdir_adapter_azure.arm)."""
    pairs, scope_notices = _scoped(_unique([*_vnets(items), *_vms(items), *_nics(items), *_lbs(items),
                                            *_addresses(items), *_records(items), *_nsgs(items), *_nats(items),
                                            *_vault_items(items), *_stores(items), *_functions(items),
                                            *iam_items(items), *edge_items(items)]))
    resources, notices = pairs_resources(pairs)
    return resources, (*scope_notices, *notices)


def cli_resources(texts):
    """(resources, notices) of an environment's Azure CLI outputs ({path within the folder: text})."""
    items, unknown = _items(texts)
    resources, notices = items_resources(items)
    return resources, (*unknown, *notices)


def read_cli_inventory(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from the Azure CLI outputs under <cloud>/<env>/."""
    return layout_import(files, d, PROVIDER, "Azure", cli_resources, ".json", "Azure CLI output", "vnets.json",
                         summarize=ACCOUNT_WIDE)


CLI_INVENTORY = Importer("cli-inventory", "Azure CLI outputs (az … -o json) under <cloud>/<env>/, as the "
                                          "environment's servers and bindings", read_cli_inventory)

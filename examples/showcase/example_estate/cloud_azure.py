"""What Azure reports the target environment runs (pure: builds documents), from the same fixture data as the record,
with the drift planted here (`opsdir import --dry-run` shows it). The public names are on the corporate DNS team's
Infoblox, so Azure DNS holds the private ones only.

  target/prod, Azure CLI output (az … -o json), with a role map:
    - fw-idm-sync's NSG priority changed in the portal (130 -> 400)
    - ds-3 resized (Standard_D4s_v5 -> Standard_D8s_v5)
    - a management subnet added in the portal, snet-mgmt; roles.json gives it the role subnet-mgmt
    - the LDAPS Private Link Service's alias, which the record doesn't hold yet (the supplier portal connects by it)
  Its network depth as the stack's own Terraform made it: the Key Vault private endpoint and the LDAPS Private Link
  Service.
"""
from .cloud_common import by_role, edge_subnets, hex_id, rows_of, servers_of, service_named
from .infrastructure import SECRET_ROLES, TARGET

SUB = "00000000-0000-0000-0000-000000000000"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-ciam-prod"
NET = f"{RG}/providers/Microsoft.Network"
_DISK_TYPES = {"standard": "Standard_LRS", "ssd": "Premium_LRS", "provisioned": "PremiumV2_LRS"}


# ------------------------------------------------------------------ target/prod: Azure CLI output
def _nic_id(cn):
    return f"{NET}/networkInterfaces/nic-{cn}"


def _subnet_id(ref):
    vnet, sub = ref.split("/")
    return f"{NET}/virtualNetworks/{vnet}/subnets/{sub}"


def _azure_network(p, extra_subnet):
    vnet = p["net"][1]
    subnets = [{"id": _subnet_id(ref), "name": ref.split("/")[1], "addressPrefix": cidr}
               for _, _, ref, cidr, _ in (*p["subnets"], *edge_subnets(p))]
    return [{"id": f"{NET}/virtualNetworks/{vnet}", "name": vnet, "type": "Microsoft.Network/virtualNetworks",
             "resourceGroup": p["rg"], "location": "eastus2", "addressSpace": {"addressPrefixes": [p["net"][2]]},
             "subnets": [*subnets, extra_subnet]}]


def _vm_id(cn):
    return f"{RG}/providers/Microsoft.Compute/virtualMachines/{cn}"


def _disk_id(server, volume):
    return f"{RG}/providers/Microsoft.Compute/disks/disk-{server}-{volume}"


def _data_disks(p, role):
    """(LUN, volume cn, volume attributes) of the data volumes a server role's VMs have, in order."""
    return [(lun, cn, a) for lun, (cn, _, a) in enumerate(
        v for v in rows_of(p.get("volumes") or (), "ciamVolume") if v[2]["ciamTargetRole"] == role)]


def _azure_servers(p, resized):
    refs = {cn: ref for cn, _, ref, _, _ in p["subnets"]}
    vms = [{"id": _vm_id(cn), "name": cn,
            "type": "Microsoft.Compute/virtualMachines", "zones": [zone], "privateIps": ip,
            "hardwareProfile": {"vmSize": resized.get(cn, size)}, "osProfile": {"computerName": cn},
            "storageProfile": {"imageReference": {"id": image}, **({"dataDisks": [
                {"lun": lun, "name": f"disk-{cn}-{vol}", "managedDisk": {"id": _disk_id(cn, vol)}}
                for lun, vol, _ in _data_disks(p, role)]} if _data_disks(p, role) else {})},
            "networkProfile": {"networkInterfaces": [{"id": _nic_id(cn)}]},
            "tags": {"Role": role, "Hostname": host, "Product": version, "ManagedBy": "opsdir"}}
           for cn, role, host, ip, zone, size, image, subnet, version in p["servers"]]
    pools = {s[5]: f"{NET}/loadBalancers/lb-ciam-prod-{s[0]}/backendAddressPools/servers" for s in p["services"]}
    nics = [{"id": _nic_id(cn), "name": f"nic-{cn}", "type": "Microsoft.Network/networkInterfaces",
             "networkSecurityGroup": {"id": f"{NET}/networkSecurityGroups/nsg-ciam-prod-{role}"},
             "ipConfigurations": [{"name": "primary", "primary": True, "privateIPAddress": ip,
                                   "subnet": {"id": _subnet_id(refs[subnet])},
                                   "loadBalancerBackendAddressPools": [{"id": pools[role]}] if role in pools else []}]}
            for cn, role, host, ip, zone, size, image, subnet, version in p["servers"]]
    return vms, nics


def _azure_lb(cn, fqdn, ports, ip, pref):
    lb = f"{NET}/loadBalancers/lb-ciam-prod-{cn}"
    frontend = {"publicIPAddress": {"id": f"{NET}/publicIPAddresses/{pref}"}} if pref else \
        {"privateIPAddress": ip, "subnet": {"id": _subnet_id(f"{TARGET['net'][1]}/snet-ds")}}
    return {"id": lb, "name": f"lb-ciam-prod-{cn}", "type": "Microsoft.Network/loadBalancers",
            "frontendIPConfigurations": [{"name": "frontend", **frontend}],
            "backendAddressPools": [{"id": f"{lb}/backendAddressPools/servers", "name": "servers"}],
            "loadBalancingRules": [{"name": f"tcp-{port}", "frontendPort": port, "backendPort": port} for port in ports],
            "tags": {"Service": fqdn, "ManagedBy": "opsdir"}}


def _azure_record(fqdn, zone, ip, private):
    """An A record as `az network (private-)dns record-set a list` prints it."""
    name, kind = fqdn[:-len(zone) - 1], "privateDnsZones" if private else "dnszones"
    return {"id": f"{RG}/providers/Microsoft.Network/{kind}/{zone}/A/{name}", "name": name, "fqdn": f"{fqdn}.",
            "type": f"Microsoft.Network/{kind}/A", ("aRecords" if private else "ARecords"): [{"ipv4Address": ip}]}


def _azure_services(p):
    """(load balancers, public IPs, public A records, private A records) of the environment's service names."""
    services = [(cn, fqdn, zone, ports, ip, pref) for cn, _, fqdn, zone, _, _, ports, ip, pref, _ in p["services"]]
    return ([_azure_lb(cn, fqdn, ports, ip, pref) for cn, fqdn, zone, ports, ip, pref in services],
            [{"id": f"{NET}/publicIPAddresses/{pref}", "name": pref, "ipAddress": ip,
              "type": "Microsoft.Network/publicIPAddresses"} for cn, fqdn, zone, ports, ip, pref in services if pref],
            [_azure_record(fqdn, zone, ip, False) for cn, fqdn, zone, ports, ip, pref in services if pref],
            [_azure_record(fqdn, zone, ip, True) for cn, fqdn, zone, ports, ip, pref in services if not pref])


def _azure_nsgs(p, priorities):
    """The network security groups: one per server role on its servers' NICs, one per database role on the database's
    delegated subnet (carrying its role: no NIC says what it guards)."""
    roles = list(dict.fromkeys(s[1] for s in p["servers"]))
    databases = {role: (cn, by_role(p["subnets"], a["ciamSubnetRole"])[0], a) for _, cn, role, a in p["databases"]}
    rules = [(trole, {"name": cn, "priority": priorities.get(cn, 100 + 10 * i), "direction": "Inbound",
                      "access": "Allow", "protocol": "Tcp", "sourceAddressPrefixes": cidrs,
                      "destinationPortRanges": [str(port) for port in ports],
                      "description": f"consumer {consumer}" if consumer else role})
             for i, (cn, role, cidrs, ports, trole, consumer, _) in enumerate(p["fw"])]
    return [{"id": f"{NET}/networkSecurityGroups/nsg-ciam-prod-{role}", "name": f"nsg-ciam-prod-{role}",
             "type": "Microsoft.Network/networkSecurityGroups", "resourceGroup": p["rg"],
             "securityRules": [r for t, r in rules if t == role],
             "networkInterfaces": [{"id": _nic_id(s[0])} for s in p["servers"] if s[1] == role],
             "tags": {"ManagedBy": "opsdir"}}
            for role in roles] + \
        [{"id": f"{NET}/networkSecurityGroups/nsg-ciam-prod-{role}", "name": f"nsg-ciam-prod-{role}",
          "type": "Microsoft.Network/networkSecurityGroups", "resourceGroup": p["rg"],
          "securityRules": [{"name": f"{role}-clients", "priority": 100, "direction": "Inbound", "access": "Allow",
                             "protocol": "Tcp", "sourceAddressPrefixes": a["ciamSourceCidr"],
                             "destinationPortRanges": [a["ciamPort"]], "description": f"clients of database {cn}"}],
          "subnets": [{"id": _subnet_id(subnet)}], "tags": {"Name": cn, "Role": role, "ManagedBy": "opsdir"}}
         for role, (cn, subnet, a) in databases.items()]


def _azure_vault(p):
    vault = p["key"][0].split("://", 1)[1].split("/")[0]
    key_name = p["key"][0].rsplit("/", 1)[1]
    url = f"https://{vault}.vault.azure.net"
    return ([{"id": f"{url}/secrets/{role}", "name": role, "attributes": {"enabled": True}, "tags": {}}
             for role in SECRET_ROLES],
            [{"kid": f"{url}/keys/{key_name}", "name": key_name, "attributes": {"enabled": True}}],
            {"key": {"kid": f"{url}/keys/{key_name}/4f1e", "kty": "RSA"}, "attributes": {"enabled": True}},
            [{"id": p["key"][1], "name": p["key"][1].rsplit("/", 1)[1], "type": "Microsoft.Compute/diskEncryptionSets",
              "activeKey": {"keyUrl": f"{url}/keys/{key_name}/4f1e"}}])


def _azure_network_depth(p):
    """(private endpoints, Private Link Services) as the Azure CLI lists them: the Key Vault endpoint with its DNS zone
    group, the LDAPS Private Link Service (its alias, which the record doesn't hold yet)."""
    endpoints, links = [], []
    for oc, cn, role, a in p["network"]:
        if oc == "ciamPrivateEndpoint":
            subnet = by_role(p["subnets"], a["ciamSubnetRole"])[0]
            endpoints += [{"id": a["ciamProviderRef"], "name": a["ciamProviderRef"].rsplit("/", 1)[1],
                           "type": "Microsoft.Network/privateEndpoints", "tags": {"Role": role, "ManagedBy": "opsdir"},
                           "subnet": {"id": _subnet_id(subnet)},
                           "privateLinkServiceConnections": [{
                               "name": cn, "privateLinkServiceId": f"{RG}/providers/Microsoft.KeyVault/vaults/kv-ciam-prod",
                               "groupIds": ["vault"]}],
                           "ipConfigurations": [{"name": "primary", "privateIPAddress": a["ciamFrontendIp"]}]},
                          {"id": f"{a['ciamProviderRef']}/privateDnsZoneGroups/default",
                           "type": "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
                           "privateDnsZoneConfigs": [{"privateDnsZoneId": a["ciamDnsZoneRef"]}]}]
        elif oc == "ciamEndpointService":
            lb = f"{NET}/loadBalancers/lb-ciam-prod-{service_named(p, a['ciamServiceRole'])}"
            links.append({"id": a["ciamProviderRef"], "name": a["ciamProviderRef"].rsplit("/", 1)[1],
                          "type": "Microsoft.Network/privateLinkServices", "tags": {"Role": role, "ManagedBy": "opsdir"},
                          "alias": f"pls-ciam-prod-{cn}.{hex_id('alias', cn, n=8)}.eastus2.azure.privatelinkservice",
                          "loadBalancerFrontendIpConfigurations": [{"id": f"{lb}/frontendIPConfigurations/frontend"}],
                          "ipConfigurations": [{"name": "primary", "subnet": {
                              "id": _subnet_id(by_role(p["subnets"], a["ciamSubnetRole"])[0])}}],
                          "visibility": {"subscriptions": [a["ciamVisibleTo"]]}, "autoApproval": {"subscriptions": []}})
    return endpoints, links


def _azure_disks(p):
    """The managed disks as `az disk list` prints them: each data volume of a role a disk on each of its VMs, in its
    zone, encrypted with the disk encryption set, tagged with its volume, role and server."""
    return [{"id": _disk_id(s[0], cn), "name": f"disk-{s[0]}-{cn}", "type": "Microsoft.Compute/disks",
             "location": "eastus2", "zones": [s[4]], "sku": {"name": _DISK_TYPES[a["ciamVolumeClass"]]},
             "diskSizeGB": int(a["ciamVolumeSizeGb"]),
             **({"diskIOPSReadWrite": int(a["ciamIops"])} if a.get("ciamIops") else {}),
             **({"diskMBpsReadWrite": int(a["ciamThroughputMb"])} if a.get("ciamThroughputMb") else {}),
             "encryption": {"type": "EncryptionAtRestWithCustomerKey", "diskEncryptionSetId": p["key"][1]},
             "managedBy": _vm_id(s[0]), "diskState": "Attached",
             "tags": {"Volume": cn, "Role": role, "Server": s[0],
                      **({"SnapshotPolicy": a["ciamSnapshotPolicyRole"]} if a.get("ciamSnapshotPolicyRole") else {}),
                      "ManagedBy": "opsdir"}}
            for cn, role, a in rows_of(p.get("volumes") or (), "ciamVolume")
            for s in servers_of(p, a["ciamTargetRole"])]


def _azure_databases(p):
    """The managed databases as `az postgres flexible-server list` and `parameter list` print them (the parameters
    set on the server only), and `az lock list` the locks on them."""
    servers, configs, locks = [], [], []
    for _, cn, role, a in p["databases"]:
        ref = a["ciamProviderRef"]
        subnet = by_role(p["subnets"], a["ciamSubnetRole"])[0]
        ha = a["ciamDbHighAvailability"] == "zone-redundant"
        servers.append({"id": ref, "name": cn, "type": "Microsoft.DBforPostgreSQL/flexibleServers",
                        "location": "eastus2", "version": a["ciamDbEngineVersion"],
                        "sku": {"name": a["ciamInstanceSize"], "tier": "GeneralPurpose"},
                        "storage": {"storageSizeGb": int(a["ciamDbStorageGb"]), "autoGrow": "Disabled"},
                        "availabilityZone": a["ciamZone"], "fullyQualifiedDomainName": a["ciamFqdn"],
                        "highAvailability": {"mode": "ZoneRedundant" if ha else "Disabled"},
                        "backup": {"backupRetentionDays": int(a["ciamRetentionDays"]), "geoRedundantBackup": "Disabled"},
                        "network": {"delegatedSubnetResourceId": _subnet_id(subnet),
                                    "publicNetworkAccess": "Disabled"},
                        "dataEncryption": {"type": "AzureKeyVault",
                                           "primaryKeyURI": f"https://{p['key'][0].split('://')[1].split('/')[0]}"
                                                            f".vault.azure.net/keys/{p['key'][0].rsplit('/', 1)[1]}/4f1e"},
                        "tags": {"Role": role, "ManagedBy": "opsdir"}})
        configs += [{"id": f"{ref}/configurations/{k}", "name": k, "value": v, "source": "user-override",
                     "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations"}
                    for k, v in (x.split("=", 1) for x in a["ciamDbParameter"])]
        locks += [{"id": f"{ref}/providers/Microsoft.Authorization/locks/{cn}-no-delete", "name": f"{cn}-no-delete",
                   "level": "CanNotDelete", "type": "Microsoft.Authorization/locks"}
                  ] if a["ciamDbDeletionProtection"] == "TRUE" else []
    return servers, configs, locks


def target_inventory():
    """{file name: text} of the target environment's Azure CLI output and role map, with the planted drift."""
    p = TARGET
    mgmt = {"id": _subnet_id(f"{p['net'][1]}/snet-mgmt"), "name": "snet-mgmt", "addressPrefix": "10.60.9.0/28"}
    vms, nics = _azure_servers(p, {"ds-3": "Standard_D8s_v5"})
    lbs, ips, _, private = _azure_services(p)         # the public names are on the corporate DNS team's Infoblox
    nat_ip = {"id": f"{NET}/publicIPAddresses/pip-natgw-ciam-prod", "name": "pip-natgw-ciam-prod",
              "ipAddress": p["egress"][1][:-3], "type": "Microsoft.Network/publicIPAddresses"}
    secrets, keys, key_show, sets = _azure_vault(p)
    return {"vnets.json": _azure_network(p, mgmt), "vms.json": vms, "nics.json": nics, "lbs.json": lbs,
            "public-ips.json": [*ips, nat_ip],
            "private-dns-id.cloud.example-aero.test.json": private,
            "nsgs.json": _azure_nsgs(p, {"fw-idm-sync": 400}),
            "nat-gateways.json": [{"id": f"{NET}/natGateways/{p['egress'][0]}", "name": p["egress"][0],
                                   "type": "Microsoft.Network/natGateways",
                                   "publicIpAddresses": [{"id": nat_ip["id"]}]}],
            "disk-encryption-sets.json": sets, "disks.json": _azure_disks(p), "kv-secrets.json": secrets, "kv-keys.json": keys,
            "kv-key-disk-cmk.json": key_show,
            "private-endpoints.json": _azure_network_depth(p)[0], "private-link-services.json": _azure_network_depth(p)[1],
            "postgres-servers.json": _azure_databases(p)[0], "postgres-parameters.json": _azure_databases(p)[1],
            "locks.json": _azure_databases(p)[2],
            "roles.json": {f"{p['net'][1]}/snet-mgmt": "subnet-mgmt"}}

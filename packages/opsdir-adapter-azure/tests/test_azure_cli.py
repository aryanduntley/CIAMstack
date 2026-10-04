"""Azure CLI outputs read into an environment's servers and bindings: outputs that match the record change nothing,
whatever the files are called; what the CLI says replaces the record's values (an HSM key that rotates, found through
`key show` and its rotation policy); subnets listed on their own or inside their network are read once; VMs outside the
listed virtual networks are counted; NSG default rules aren't read; account-wide listings count what the record doesn't
have; a secret's value never appears."""
import json

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.cli import cli_resources, read_cli_inventory, vault_object

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourceGroups/rg-ciam-prod"
NET = f"{RG}/providers/Microsoft.Network"
VNET = f"{NET}/virtualNetworks/vnet-ciam-prod"
IMG = f"{SUB}/resourceGroups/rg-ciam-images/providers/Microsoft.Compute/images/pingds-7.5.1-rhel9"
DES = f"{RG}/providers/Microsoft.Compute/diskEncryptionSets/des-ciam-prod"
KV = "https://kv-ciam-prod.vault.azure.net"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return make_directory((), {}, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="azure",
             ciamRegion="eastus2"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=vnet,{B}", ("ciamNetwork",), cn="vnet", ciamBindingRole="network", ciamCidr="10.60.0.0/16",
             ciamProviderRef="vnet-ciam-prod", ciamResourceGroup="rg-ciam-prod"),
        _row(f"cn=snet-ds,{B}", ("ciamSubnetBinding",), cn="snet-ds", ciamBindingRole="subnet-ds",
             ciamCidr="10.60.1.0/24", ciamProviderRef="vnet-ciam-prod/snet-ds"),
        _row(f"cn=snet-pf,{B}", ("ciamSubnetBinding",), cn="snet-pf", ciamBindingRole="subnet-pf",
             ciamCidr="10.60.2.0/24", ciamProviderRef="vnet-ciam-prod/snet-pf"),
        _row(f"cn=ds-1,{ENV}", ("ciamServer",), cn="ds-1", ciamServerRole="ds", ciamHostname="ds-1.az.internal.test",
             ciamSubnet=f"cn=snet-ds,{B}", ciamPrivateIp="10.60.1.11", ciamZone="1",
             ciamInstanceSize="Standard_D4s_v5", ciamImageRef=IMG),
        _row(f"cn=pf-engine-1,{ENV}", ("ciamServer",), cn="pf-engine-1", ciamServerRole="pf-engine",
             ciamHostname="pf-engine-1.az.internal.test", ciamSubnet=f"cn=snet-pf,{B}", ciamPrivateIp="10.60.2.21",
             ciamZone="1", ciamInstanceSize="Standard_D2s_v5", ciamImageRef=IMG),
        _row(f"cn=svc-ldaps,{B}", ("ciamServiceName",), cn="svc-ldaps", ciamBindingRole="ds-ldaps-service",
             ciamFqdn="ldap.id.example.test", ciamDnsZone="id.example.test", ciamTargetRole="ds", ciamPort="1636",
             ciamFrontendIp="10.60.1.100", ciamEdgeFact="tls-mode passthrough", ciamTtlSeconds="300"),
        _row(f"cn=svc-sso,{B}", ("ciamServiceName",), cn="svc-sso", ciamBindingRole="pf-sso-service",
             ciamFqdn="sso.example.test", ciamDnsZone="example.test", ciamTargetRole="pf-engine", ciamPort="443",
             ciamFrontendIp="198.51.100.77", ciamProviderRef="pip-ciam-sso-prod", ciamEdgeFact="tls-mode passthrough"),
        _row(f"cn=fw-app,{B}", ("ciamFirewallRule",), cn="fw-app", ciamBindingRole="fw-consumer-app",
             ciamSourceCidr=["10.30.0.0/24"], ciamPort="1636", ciamProtocol="tcp", ciamTargetRole="ds",
             ciamRulePriority="100"),
        _row(f"cn=secret-root,{B}", ("ciamSecretRef",), cn="secret-root", ciamBindingRole="ds-root-password",
             ciamRefUri="azkv://kv-ciam-prod/ds-root-password"),
        _row(f"cn=key-disk,{B}", ("ciamKeyRef",), cn="key-disk", ciamBindingRole="disk-encryption",
             ciamRefUri="azkv-key://kv-ciam-prod/keys/disk-cmk", ciamProviderRef=DES, ciamProtectionLevel="software",
             ciamAutoRotate="FALSE"),
        _row(f"cn=backup,{B}", ("ciamBackupTarget",), cn="backup", ciamBindingRole="backup-target",
             ciamStorageRef="azblob://stciamprod/ds-backups"),
        _row(f"cn=egress-pf,{B}", ("ciamEgress",), cn="egress-pf", ciamBindingRole="pf-egress",
             ciamCidr="203.0.113.200/32", ciamProviderRef="natgw-ciam-prod")))


def _nic(name, subnet, ip, pool=None):
    return {"id": f"{NET}/networkInterfaces/nic-{name}", "name": f"nic-{name}",
            "type": "Microsoft.Network/networkInterfaces",
            "ipConfigurations": [{"name": "primary", "primary": True, "privateIPAddress": ip,
                                  "subnet": {"id": f"{VNET}/subnets/{subnet}"},
                                  "loadBalancerBackendAddressPools": [{"id": pool}] if pool else None}]}


def _vm(name, role, size, host):
    return {"id": f"{RG}/providers/Microsoft.Compute/virtualMachines/{name}", "name": name,
            "type": "Microsoft.Compute/virtualMachines", "zones": ["1"], "privateIps": "10.60.1.11" if role == "ds" else "10.60.2.21",
            "hardwareProfile": {"vmSize": size}, "osProfile": {"computerName": name, "adminPassword": None},
            "storageProfile": {"imageReference": {"id": IMG}},
            "networkProfile": {"networkInterfaces": [{"id": f"{NET}/networkInterfaces/nic-{name}"}]},
            "tags": {"Role": role, "Hostname": host}}


def _lb(name, frontend, port):
    lb = f"{NET}/loadBalancers/lb-ciam-prod-{name}"
    return {"id": lb, "name": f"lb-ciam-prod-{name}", "type": "Microsoft.Network/loadBalancers",
            "frontendIPConfigurations": [{"name": "frontend", **frontend}],
            "backendAddressPools": [{"id": f"{lb}/backendAddressPools/servers"}],
            "loadBalancingRules": [{"name": f"tcp-{port}", "frontendPort": port, "backendPort": port}]}


def _outputs(**over):
    """{path: output} as `az … -o json` prints it."""
    pip = f"{NET}/publicIPAddresses/pip-ciam-sso-prod"
    nsg = lambda role: f"{NET}/networkSecurityGroups/nsg-ciam-prod-{role}"  # noqa: E731
    base = {
        "network.json": [{"id": VNET, "name": "vnet-ciam-prod", "type": "Microsoft.Network/virtualNetworks",
                          "resourceGroup": "rg-ciam-prod", "addressSpace": {"addressPrefixes": ["10.60.0.0/16"]},
                          "subnets": [{"id": f"{VNET}/subnets/snet-ds", "name": "snet-ds", "addressPrefix": "10.60.1.0/24"},
                                      {"id": f"{VNET}/subnets/snet-pf", "name": "snet-pf", "addressPrefixes": ["10.60.2.0/24"]}]}],
        "subnets.json": [{"id": f"{VNET}/subnets/snet-ds", "name": "snet-ds", "addressPrefix": "10.60.1.0/24",
                          "type": "Microsoft.Network/virtualNetworks/subnets"}],
        "vms.json": [_vm("ds-1", "ds", "Standard_D4s_v5", "ds-1.az.internal.test"),
                     _vm("pf-engine-1", "pf-engine", "Standard_D2s_v5", "pf-engine-1.az.internal.test")],
        "nics.json": [_nic("ds-1", "snet-ds", "10.60.1.11", f"{NET}/loadBalancers/lb-ciam-prod-svc-ldaps/backendAddressPools/servers"),
                      _nic("pf-engine-1", "snet-pf", "10.60.2.21")],
        "lbs.json": [_lb("svc-ldaps", {"privateIPAddress": "10.60.1.100", "subnet": {"id": f"{VNET}/subnets/snet-ds"}}, 1636),
                     {**_lb("svc-sso", {"publicIPAddress": {"id": pip}}, 443), "backendAddressPools": [
                         {"id": f"{NET}/loadBalancers/lb-ciam-prod-svc-sso/backendAddressPools/servers",
                          "backendIPConfigurations": [{"id": f"{NET}/networkInterfaces/nic-pf-engine-1/ipConfigurations/primary"}]}]}],
        "public-ips.json": [{"id": pip, "name": "pip-ciam-sso-prod", "ipAddress": "198.51.100.77",
                             "type": "Microsoft.Network/publicIPAddresses"},
                            {"id": f"{NET}/publicIPAddresses/pip-natgw", "name": "pip-natgw", "ipAddress": "203.0.113.200",
                             "type": "Microsoft.Network/publicIPAddresses"}],
        "dns-public.json": [{"id": f"{RG}/providers/Microsoft.Network/dnszones/example.test/A/sso", "name": "sso",
                             "fqdn": "sso.example.test.", "type": "Microsoft.Network/dnszones/A",
                             "ARecords": [{"ipv4Address": "198.51.100.77"}]}],
        "dns-private.json": [{"id": f"{RG}/providers/Microsoft.Network/privateDnsZones/id.example.test/A/ldap",
                              "name": "ldap", "fqdn": "ldap.id.example.test.", "type": "Microsoft.Network/privateDnsZones/A",
                              "aRecords": [{"ipv4Address": "10.60.1.100"}]}],
        "nsgs.json": [{"id": nsg("ds"), "name": "nsg-ciam-prod-ds", "resourceGroup": "rg-ciam-prod",
                       "type": "Microsoft.Network/networkSecurityGroups",
                       "networkInterfaces": [{"id": f"{NET}/networkInterfaces/nic-ds-1"}],
                       "securityRules": [{"name": "fw-app", "priority": 100, "direction": "Inbound", "access": "Allow",
                                          "protocol": "Tcp", "sourceAddressPrefixes": ["10.30.0.0/24"],
                                          "destinationPortRanges": ["1636"], "description": "consumer app"}],
                       "defaultSecurityRules": [{"name": "AllowVnetInBound", "priority": 65000, "direction": "Inbound",
                                                 "access": "Allow", "protocol": "*",
                                                 "sourceAddressPrefix": "VirtualNetwork", "destinationPortRange": "*"}]}],
        "nat.json": [{"id": f"{NET}/natGateways/natgw-ciam-prod", "name": "natgw-ciam-prod",
                      "type": "Microsoft.Network/natGateways",
                      "publicIpAddresses": [{"id": f"{NET}/publicIPAddresses/pip-natgw"}]}],
        "des.json": [{"id": DES, "name": "des-ciam-prod", "type": "Microsoft.Compute/diskEncryptionSets",
                      "activeKey": {"keyUrl": f"{KV}/keys/disk-cmk/9f8e"}}],
        "containers.json": [{"id": f"{RG}/providers/Microsoft.Storage/storageAccounts/stciamprod/blobServices/default/"
                                   f"containers/ds-backups", "name": "ds-backups", "metadata": {},
                             "type": "Microsoft.Storage/storageAccounts/blobServices/containers"}],
        "kv-secrets.json": [{"id": f"{KV}/secrets/ds-root-password", "name": "ds-root-password",
                             "attributes": {"enabled": True}, "managed": None, "tags": {}}],
        "kv-keys.json": [{"kid": f"{KV}/keys/disk-cmk", "name": "disk-cmk", "attributes": {"enabled": True}}],
        "kv-key-disk-cmk.json": {"key": {"kid": f"{KV}/keys/disk-cmk/9f8e", "kty": "RSA"}, "attributes": {"enabled": True}},
        "kv-rotation-disk-cmk.json": {"id": f"{KV}/keys/disk-cmk/rotationpolicy", "lifetimeActions": [
            {"action": {"type": "Notify"}, "trigger": {"timeBeforeExpiry": "P30D"}}]}}
    return {f"main/prod/{p}": json.dumps(doc) for p, doc in {**base, **over}.items()}


def _after(d, imported):
    scopes = [s.lower() for s, _ in imported.groups]
    kept = {n: e for n, e in d.entries.items() if n not in scopes}
    added = {e.norm: e for e in (*(c for c in imported.containers if c.norm not in d.entries),
                                 *(e for _, es in imported.groups for e in es))}
    return d._replace(entries={**kept, **added})


def test_the_importer_is_registered_on_the_adapter():
    assert [i.name for i in ADAPTER.importers] == ["terraform-state", "cli-inventory", "arm"]


def test_outputs_that_match_the_record_change_nothing():
    d = _record()
    imported = read_cli_inventory(_outputs(), d, ())
    assert len(imported.groups) == 12 and not import_changes(d, imported), imported.notices
    assert imported.notices == ()


def test_what_the_cli_says_replaces_the_records_values():
    d = _record()
    changed = _outputs(**{"kv-key-disk-cmk.json": {"key": {"kid": f"{KV}/keys/disk-cmk/9f8e", "kty": "RSA-HSM"}},
                          "kv-rotation-disk-cmk.json": {"id": f"{KV}/keys/disk-cmk/rotationpolicy", "lifetimeActions": [
                              {"action": {"type": "Rotate"}, "trigger": {"timeAfterCreate": "P90D"}}]}})
    key = get(_after(d, read_cli_inventory(changed, d, ())), f"cn=key-disk,{B}")
    assert (one(key, "ciamProtectionLevel"), one(key, "ciamAutoRotate"), one(key, "ciamProviderRef")) == \
        ("hsm", "TRUE", DES)


def test_vms_outside_the_listed_networks_are_counted_and_default_rules_not_read():
    other = [{**_vm("jump", "ops", "Standard_B1s", "jump.other.test"),
              "networkProfile": {"networkInterfaces": [{"id": f"{NET}/networkInterfaces/nic-jump"}]}}]
    nic = [{**_nic("jump", "snet-x", "10.99.0.4"),
            "ipConfigurations": [{"name": "primary", "privateIPAddress": "10.99.0.4",
                                  "subnet": {"id": f"{NET}/virtualNetworks/vnet-other/subnets/snet-x"}}]}]
    imported = read_cli_inventory(_outputs(**{"vms-other.json": other, "nics-other.json": nic}), _record(), ())
    assert set(imported.notices) == {
        "azurerm_linux_virtual_machine (1): outside the listed virtual networks (vnet-ciam-prod); not read",
        "azurerm_network_interface (1): outside the listed virtual networks (vnet-ciam-prod); not read"}


def test_account_wide_listings_count_what_the_record_does_not_have():
    secrets = [{"id": f"{KV}/secrets/ds-root-password", "name": "ds-root-password"},
               *({"id": f"{KV}/secrets/app-{i}", "name": f"app-{i}"} for i in range(4)),
               {"id": f"{KV}/secrets/cert-backed", "name": "cert-backed", "managed": True}]
    imported = read_cli_inventory(_outputs(**{"kv-secrets.json": secrets}), _record(), ())
    assert imported.notices == (
        "main/prod: 4 secret resource(s) not in the record and naming no role, e.g. app-0, app-1, app-2 (tag them "
        "Role, name them in roles.json, or record them); not imported",)


def test_unrecognized_files_and_items_are_named_and_values_never_appear():
    texts = {"notes.json": "not json", "mixed.json": json.dumps([{"id": "x", "name": "y"},
                                                                  {"id": f"{KV}/secrets/s", "name": "s",
                                                                   "value": "S3cr3t"}])}
    resources, notices = cli_resources(texts)
    assert notices == ("notes.json: not JSON; not read",
                       "mixed.json: 1 item(s) that aren't Azure CLI output this importer reads; not read")
    assert [r.ref for r in resources] == ["azkv://kv-ciam-prod/s"] and "S3cr3t" not in str(resources)


def test_key_vault_urls_are_recognized_in_both_clouds():
    assert vault_object(f"{KV}/keys/disk-cmk/9f8e") == ("kv-ciam-prod", "keys", "disk-cmk")
    assert vault_object("https://kv-gov.vault.usgovcloudapi.net/secrets/a") == ("kv-gov", "secrets", "a")
    assert vault_object("https://example.test/secrets/a") is None

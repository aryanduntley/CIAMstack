"""Azure Terraform state read into an environment's servers and bindings: a state that matches the record changes
nothing; what the cloud says replaces the record's values (a resized VM, an HSM key that now rotates); a new tagged VM
is added and an untagged one named; security rules are read by name with their priorities, and their target role is
that of the VMs the group guards; secret values and sensitive attributes are never read; only Azure environments laid
out as <cloud>/<env>/ are imported; kinds a state doesn't report are left as recorded."""
import json

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one, values
from opsdir_adapter_azure.inventory import read_terraform_state, state_resources
from opsdir_format_terraform.state import read_state
from support import SUPERS

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourceGroups/rg-ciam-prod"
NET = f"{RG}/providers/Microsoft.Network"
VNET = f"{NET}/virtualNetworks/vnet-ciam-prod"
IMG = f"{SUB}/resourceGroups/rg-ciam-images/providers/Microsoft.Compute/images/pingds-7.5.1-rhel9"
DES = f"{RG}/providers/Microsoft.Compute/diskEncryptionSets/des-ciam-prod"
KV = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-ciam-prod"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record(*extra):
    return make_directory((), SUPERS, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="azure",
             ciamRegion="eastus2"),
        _row("cloud=other,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="other", ciamCloudProvider="aws",
             ciamRegion="us-east-1"),
        _row("env=prod,cloud=other,ou=environments,dc=ciam-ops", ("ciamEnvironment",), env="prod"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=vnet,{B}", ("ciamNetwork",), cn="vnet", ciamBindingRole="network", ciamCidr="10.60.0.0/16",
             ciamProviderRef="vnet-ciam-prod", ciamResourceGroup="rg-ciam-prod",
             ciamOwner="cn=netsec,ou=owners,dc=ciam-ops"),
        _row(f"cn=snet-ds,{B}", ("ciamSubnetBinding",), cn="snet-ds", ciamBindingRole="subnet-ds",
             ciamCidr="10.60.1.0/24", ciamProviderRef="vnet-ciam-prod/snet-ds"),
        _row(f"cn=snet-pf,{B}", ("ciamSubnetBinding",), cn="snet-pf", ciamBindingRole="subnet-pf",
             ciamCidr="10.60.2.0/24", ciamProviderRef="vnet-ciam-prod/snet-pf"),
        _row(f"cn=ds-1,{ENV}", ("ciamServer",), cn="ds-1", ciamServerRole="ds", ciamHostname="ds-1.az.internal.test",
             ciamSubnet=f"cn=snet-ds,{B}", ciamPrivateIp="10.60.1.11", ciamZone="1",
             ciamInstanceSize="Standard_D4s_v5", ciamImageRef=IMG, ciamProductVersion="PingDS 7.5.1"),
        _row(f"cn=pf-engine-1,{ENV}", ("ciamServer",), cn="pf-engine-1", ciamServerRole="pf-engine",
             ciamHostname="pf-engine-1.az.internal.test", ciamSubnet=f"cn=snet-pf,{B}", ciamPrivateIp="10.60.2.21",
             ciamZone="1", ciamInstanceSize="Standard_D2s_v5", ciamImageRef=IMG),
        _row(f"cn=svc-ldaps,{B}", ("ciamServiceName",), cn="svc-ldaps", ciamBindingRole="ds-ldaps-service",
             ciamFqdn="ldap.id.example.test", ciamDnsZone="id.example.test", ciamTargetRole="ds", ciamPort="1636",
             ciamFrontendIp="10.60.1.100", ciamEdgeFact="tls-mode passthrough", ciamTtlSeconds="300"),
        _row(f"cn=svc-sso,{B}", ("ciamServiceName",), cn="svc-sso", ciamBindingRole="pf-sso-service",
             ciamFqdn="sso.example.test", ciamDnsZone="example.test", ciamTargetRole="pf-engine", ciamPort="443",
             ciamFrontendIp="198.51.100.77", ciamProviderRef="pip-ciam-sso-prod", ciamEdgeFact="tls-mode passthrough", ciamTtlSeconds="300"),
        _row(f"cn=fw-app,{B}", ("ciamFirewallRule",), cn="fw-app", ciamBindingRole="fw-consumer-app",
             ciamSourceCidr=["10.30.0.0/24"], ciamPort="1636", ciamProtocol="tcp", ciamTargetRole="ds",
             ciamRulePriority="100", ciamAllowsConsumer="cn=app,ou=consumers,dc=ciam-ops"),
        _row(f"cn=fw-sso-public,{B}", ("ciamFirewallRule",), cn="fw-sso-public", ciamBindingRole="fw-sso-public",
             ciamSourceCidr=["0.0.0.0/0"], ciamPort="443", ciamProtocol="tcp", ciamTargetRole="pf-engine",
             ciamRulePriority="110"),
        _row(f"cn=secret-root,{B}", ("ciamSecretRef",), cn="secret-root", ciamBindingRole="ds-root-password",
             ciamRefUri="azkv://kv-ciam-prod/ds-root-password", ciamLastRotated="20260302000000Z"),
        _row(f"cn=key-disk,{B}", ("ciamKeyRef",), cn="key-disk", ciamBindingRole="disk-encryption",
             ciamRefUri="azkv-key://kv-ciam-prod/keys/disk-cmk", ciamProviderRef=DES, ciamProtectionLevel="software",
             ciamAutoRotate="FALSE"),
        _row(f"cn=backup,{B}", ("ciamBackupTarget",), cn="backup", ciamBindingRole="backup-target",
             ciamStorageRef="azblob://stciamprod/ds-backups", ciamRetentionDays="35"),
        _row(f"cn=egress-pf,{B}", ("ciamEgress",), cn="egress-pf", ciamBindingRole="pf-egress",
             ciamCidr="203.0.113.200/32", ciamProviderRef="natgw-ciam-prod"),
        *extra))


def _res(mode, type_, name, attrs, sensitive=()):
    return {"mode": mode, "type": type_, "name": name, "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
            "instances": [{"schema_version": 0, "attributes": attrs,
                           "sensitive_attributes": [[{"type": "get_attr", "value": s}] for s in sensitive]}]}


def _nic(name, subnet, ip):
    return _res("managed", "azurerm_network_interface", name.replace("-", "_"), {
        "id": f"{NET}/networkInterfaces/nic-{name}", "name": f"nic-{name}", "private_ip_address": ip,
        "ip_configuration": [{"name": "primary", "primary": True, "private_ip_address": ip,
                              "subnet_id": f"{VNET}/subnets/{subnet}"}]})


def _vm(name, role, size, zone, host, extra_tags=None):
    return _res("managed", "azurerm_linux_virtual_machine", name.replace("-", "_"), {
        "id": f"{RG}/providers/Microsoft.Compute/virtualMachines/{name}", "name": name,
        "computer_name": name, "size": size, "zone": zone, "source_image_id": IMG,
        "network_interface_ids": [f"{NET}/networkInterfaces/nic-{name}"], "custom_data": "IyEvYmluL3NoIHNlY3JldA==",
        "tags": {"Role": role, "Hostname": host, "ManagedBy": "opsdir", **(extra_tags or {})}},
        sensitive=("custom_data",))


def _nsg(role):
    return _res("managed", "azurerm_network_security_group", role.replace("-", "_"), {
        "id": f"{NET}/networkSecurityGroups/nsg-ciam-prod-{role}", "name": f"nsg-ciam-prod-{role}",
        "resource_group_name": "rg-ciam-prod", "security_rule": [], "tags": {"ManagedBy": "opsdir"}})


def _nsg_nic(role, name):
    return _res("managed", "azurerm_network_interface_security_group_association", name.replace("-", "_"), {
        "network_interface_id": f"{NET}/networkInterfaces/nic-{name}",
        "network_security_group_id": f"{NET}/networkSecurityGroups/nsg-ciam-prod-{role}"})


def _rule(name, role, prefixes, ports, priority, **over):
    return _res("managed", "azurerm_network_security_rule", name.replace("-", "_"), {
        "name": name, "priority": priority, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
        "source_port_range": "*", "destination_port_ranges": ports, "source_address_prefixes": prefixes,
        "destination_address_prefix": "*", "resource_group_name": "rg-ciam-prod",
        "network_security_group_name": f"nsg-ciam-prod-{role}", **over})


def _lb(name, frontend, pool_nics, ports, record):
    lb = f"{NET}/loadBalancers/lb-ciam-prod-{name}"
    pool = f"{lb}/backendAddressPools/servers"
    n = name.replace("-", "_")
    return (_res("managed", "azurerm_lb", n, {"id": lb, "name": f"lb-ciam-prod-{name}", "sku": "Standard",
                                              "frontend_ip_configuration": [{"name": "frontend", **frontend}],
                                              "tags": {"ManagedBy": "opsdir"}}),
            _res("managed", "azurerm_lb_backend_address_pool", n, {"id": pool, "name": "servers", "loadbalancer_id": lb}),
            *(_res("managed", "azurerm_network_interface_backend_address_pool_association", f"{n}_{i}", {
                "network_interface_id": f"{NET}/networkInterfaces/nic-{nic}", "ip_configuration_name": "primary",
                "backend_address_pool_id": pool}) for i, nic in enumerate(pool_nics)),
            *(_res("managed", "azurerm_lb_rule", f"{n}_{p}", {"name": f"tcp-{p}", "loadbalancer_id": lb,
                                                           "frontend_port": p, "backend_port": p,
                                                           "backend_address_pool_ids": [pool]}) for p in ports),
            record)


def _state(*changes):
    pip = f"{NET}/publicIPAddresses/pip-ciam-sso-prod"
    resources = [
        _res("data", "azurerm_resource_group", "main", {"id": RG, "name": "rg-ciam-prod", "location": "eastus2"}),
        _res("data", "azurerm_virtual_network", "main", {"id": VNET, "name": "vnet-ciam-prod",
                                                         "resource_group_name": "rg-ciam-prod",
                                                         "address_space": ["10.60.0.0/16"]}),
        *(_res("data", "azurerm_subnet", s.replace("-", "_"), {
            "id": f"{VNET}/subnets/{s}", "name": s, "virtual_network_name": "vnet-ciam-prod",
            "resource_group_name": "rg-ciam-prod", "address_prefixes": [cidr]})
          for s, cidr in (("snet-ds", "10.60.1.0/24"), ("snet-pf", "10.60.2.0/24"))),
        _nic("ds-1", "snet-ds", "10.60.1.11"),
        _vm("ds-1", "ds", "Standard_D4s_v5", "1", "ds-1.az.internal.test", {"Product": "PingDS 7.5.1"}),
        _nic("pf-engine-1", "snet-pf", "10.60.2.21"),
        _vm("pf-engine-1", "pf-engine", "Standard_D2s_v5", "1", "pf-engine-1.az.internal.test"),
        _nsg("ds"), _nsg("pf-engine"), _nsg_nic("ds", "ds-1"), _nsg_nic("pf-engine", "pf-engine-1"),
        _rule("fw-app", "ds", ["10.30.0.0/24"], ["1636"], 100, description="consumer app"),
        _rule("fw-sso-public", "pf-engine", ["0.0.0.0/0"], ["443"], 110),
        *_lb("svc-ldaps", {"private_ip_address": "10.60.1.100", "subnet_id": f"{VNET}/subnets/snet-ds"}, ["ds-1"],
             [1636], _res("managed", "azurerm_private_dns_a_record", "svc_ldaps", {
                 "name": "ldap", "zone_name": "id.example.test", "records": ["10.60.1.100"], "ttl": 300,
                 "fqdn": "ldap.id.example.test."})),
        _res("data", "azurerm_public_ip", "svc_sso", {"id": pip, "name": "pip-ciam-sso-prod", "ip_address": "198.51.100.77"}),
        *_lb("svc-sso", {"public_ip_address_id": pip}, ["pf-engine-1"], [443],
             _res("managed", "azurerm_dns_a_record", "svc_sso", {
                 "name": "sso", "zone_name": "example.test", "records": ["198.51.100.77"], "ttl": 300})),
        _res("data", "azurerm_key_vault", "kv", {"id": KV, "name": "kv-ciam-prod", "sku_name": "standard"}),
        _res("data", "azurerm_key_vault_secret", "ds_root_password", {
            "id": "https://kv-ciam-prod.vault.azure.net/secrets/ds-root-password/0a1b", "name": "ds-root-password",
            "key_vault_id": KV, "value": "S3cr3t-Passw0rd!"}, sensitive=("value",)),
        _res("managed", "azurerm_key_vault_key", "disk_cmk", {
            "id": "https://kv-ciam-prod.vault.azure.net/keys/disk-cmk/9f8e", "name": "disk-cmk", "key_vault_id": KV,
            "key_type": "RSA", "key_size": 3072, "rotation_policy": []}),
        _res("managed", "azurerm_disk_encryption_set", "main", {
            "id": DES, "name": "des-ciam-prod", "key_vault_key_id": "https://kv-ciam-prod.vault.azure.net/keys/disk-cmk/9f8e"}),
        _res("data", "azurerm_storage_container", "ds_backups", {
            "id": "https://stciamprod.blob.core.windows.net/ds-backups", "name": "ds-backups",
            "storage_account_name": "stciamprod"}),
        _res("data", "azurerm_public_ip", "natgw", {"id": f"{NET}/publicIPAddresses/pip-natgw",
                                                    "name": "pip-natgw", "ip_address": "203.0.113.200"}),
        _res("managed", "azurerm_nat_gateway", "main", {"id": f"{NET}/natGateways/natgw-ciam-prod",
                                                        "name": "natgw-ciam-prod"}),
        _res("managed", "azurerm_nat_gateway_public_ip_association", "main", {
            "nat_gateway_id": f"{NET}/natGateways/natgw-ciam-prod", "public_ip_address_id": f"{NET}/publicIPAddresses/pip-natgw"}),
        _res("managed", "random_password", "admin", {"id": "none", "result": "p4ss-w0rd-not-real"}, sensitive=("result",)),
        *changes]
    return json.dumps({"version": 4, "terraform_version": "1.9.5", "serial": 7, "lineage": "0c1d", "outputs": {},
                       "resources": resources})


def _after(d, imported):
    scopes = [s.lower() for s, _ in imported.groups]
    kept = {n: e for n, e in d.entries.items() if n not in scopes}
    added = {e.norm: e for e in (*(c for c in imported.containers if c.norm not in d.entries),
                                 *(e for _, es in imported.groups for e in es))}
    return d._replace(entries={**kept, **added})


def test_a_state_that_matches_the_record_changes_nothing():
    d = _record()
    imported = read_terraform_state({"main/prod/terraform.tfstate": _state()}, d, ())
    assert not import_changes(d, imported), imported.notices
    assert "random_password (1): not read (holds secret values, or isn't modeled yet)" in imported.notices
    assert not [n for n in imported.notices if "is in the record but not in" in n]


def test_what_the_cloud_says_replaces_the_records_values_and_keeps_the_rest():
    d = _record()
    changed = _state().replace('"size": "Standard_D4s_v5"', '"size": "Standard_D8s_v5"') \
        .replace('"key_type": "RSA", "key_size": 3072, "rotation_policy": []',
                 '"key_type": "RSA-HSM", "key_size": 3072, "rotation_policy": [{"automatic": [{"time_before_expiry": '
                 '"P30D"}], "expire_after": "P1Y"}]') \
        .replace('"priority": 110', '"priority": 120')
    after = _after(d, read_terraform_state({"main/prod/terraform.tfstate": changed}, d, ()))
    assert one(get(after, f"cn=ds-1,{ENV}"), "ciamInstanceSize") == "Standard_D8s_v5"
    key = get(after, f"cn=key-disk,{B}")
    assert (one(key, "ciamProtectionLevel"), one(key, "ciamAutoRotate"), one(key, "ciamProviderRef")) == \
        ("hsm", "TRUE", DES)
    assert one(get(after, f"cn=fw-sso-public,{B}"), "ciamRulePriority") == "120"
    assert one(get(after, f"cn=secret-root,{B}"), "ciamLastRotated") == "20260302000000Z"
    assert one(get(after, f"cn=vnet,{B}"), "ciamOwner") == "cn=netsec,ou=owners,dc=ciam-ops"


def test_a_new_tagged_vm_is_added_and_an_untagged_one_named():
    d = _record()
    extra = (_nic("ds-2", "snet-ds", "10.60.1.12"), _vm("ds-2", "ds", "Standard_D4s_v5", "2", "ds-2.az.internal.test"),
             _nic("jump", "snet-ds", "10.60.1.50"),
             _res("managed", "azurerm_linux_virtual_machine", "jump", {
                 "id": f"{RG}/providers/Microsoft.Compute/virtualMachines/jump", "name": "jump", "computer_name": "jump",
                 "size": "Standard_B1s", "network_interface_ids": [f"{NET}/networkInterfaces/nic-jump"]}))
    imported = read_terraform_state({"main/prod/terraform.tfstate": _state(*extra)}, d, ())
    after = _after(d, imported)
    ds2 = get(after, f"cn=ds-2,{ENV}")
    assert (one(ds2, "ciamServerRole"), one(ds2, "ciamSubnet"), one(ds2, "ciamPrivateIp"), one(ds2, "ciamZone")) == \
        ("ds", f"cn=snet-ds,{B}", "10.60.1.12", "2")
    assert "main/prod: server ds-2 added (role ds)" in imported.notices
    assert "main/prod: server jump (ciamPrivateIp 10.60.1.50) is not in the record and names no role (tag it Role, " \
           "name it in roles.json, or record it); not imported" in imported.notices


def test_security_rules_are_read_by_name_with_the_role_of_the_vms_they_guard():
    extra = (_rule("fw-debug", "ds", ["*"], ["1636", "8000-8100"], 4000),
             _rule("fw-lb-probe", "ds", ["AzureLoadBalancer"], ["1636"], 4010),
             _rule("deny-rest", "ds", ["*"], ["*"], 4096, access="Deny"))
    resources, notices = state_resources(_state(*extra))
    rules = {r.name: r for r in resources if r.kind == "firewall"}
    assert set(rules) == {"fw-app", "fw-sso-public", "fw-debug", "fw-lb-probe"}
    assert rules["fw-sso-public"].attrs["ciamTargetRole"] == ("pf-engine",)
    assert (rules["fw-debug"].attrs["ciamSourceCidr"], rules["fw-debug"].attrs["ciamPort"]) == (("0.0.0.0/0",), ("1636",))
    assert "ciamSourceCidr" not in rules["fw-lb-probe"].attrs
    assert set(notices) >= {
        "security rules (1 inbound deny): not read (the record holds inbound allow rules)",
        "security rule fw-lb-probe: source AzureLoadBalancer is a service tag, not an address range; not recorded",
        "security rule fw-debug: port 8000-8100 is not a single port; not recorded"}


def test_services_come_from_load_balancers_their_dns_records_and_pools():
    services = {r.name: r for r in state_resources(_state())[0] if r.kind == "service"}
    ldaps, sso = services["lb-ciam-prod-svc-ldaps"], services["lb-ciam-prod-svc-sso"]
    assert (ldaps.attrs["ciamFqdn"], ldaps.attrs["ciamDnsZone"], ldaps.attrs["ciamPort"], ldaps.attrs["ciamTargetRole"],
            ldaps.attrs["ciamFrontendIp"]) == (("ldap.id.example.test",), ("id.example.test",), ("1636",), ("ds",),
                                               ("10.60.1.100",))
    assert "ciamProviderRef" not in ldaps.attrs
    assert (sso.attrs["ciamFrontendIp"], sso.attrs["ciamProviderRef"], sso.attrs["ciamTargetRole"]) == \
        (("198.51.100.77",), ("pip-ciam-sso-prod",), ("pf-engine",))


def test_secret_values_and_sensitive_attributes_are_never_read():
    (secret,) = [r for r in read_state(_state())[0] if r.type == "azurerm_key_vault_secret"]
    assert "value" not in secret.attributes
    unmarked = _state().replace('"sensitive_attributes": [[{"type": "get_attr", "value": "value"}]]',
                                '"sensitive_attributes": []')
    dump = str(state_resources(unmarked)[0])
    assert "S3cr3t" not in dump and "p4ss" not in dump and "IyEv" not in dump


def test_only_azure_environments_laid_out_by_cloud_and_environment_are_imported():
    d = _record()
    imported = read_terraform_state({"other/prod/terraform.tfstate": _state(), "terraform.tfstate": _state(),
                                     "main/test/terraform.tfstate": _state()}, d, ())
    assert imported.groups == ()
    assert set(imported.notices) >= {
        "other/prod: not an Azure environment in the record; not imported",
        "terraform.tfstate: put each environment's Terraform state under <cloud>/<env>/ (e.g. "
        "source/prod/terraform.tfstate); not imported",
        "main/test: no such environment in the record; nothing imported"}


def test_a_kind_the_state_does_not_report_is_left_as_recorded():
    d = _record()
    without = json.loads(_state())
    without["resources"] = [r for r in without["resources"] if r["type"] != "azurerm_storage_container"]
    imported = read_terraform_state({"main/prod/terraform.tfstate": json.dumps(without)}, d, ())
    assert not [n for n in imported.notices if n.startswith("main/prod: backup ")]
    assert values(get(_after(d, imported), f"cn=backup,{B}"), "ciamStorageRef") == ("azblob://stciamprod/ds-backups",)


def test_a_containers_role_comes_from_its_metadata():
    d = _record()
    extra = (_res("managed", "azurerm_storage_container", "archive", {
                 "id": "https://stciamprod.blob.core.windows.net/ds-archive", "name": "ds-archive",
                 "storage_account_name": "stciamprod", "metadata": {"Role": "backup-archive"}}),)
    imported = read_terraform_state({"main/prod/terraform.tfstate": _state(*extra)}, d, ())
    assert values(get(_after(d, imported), f"cn=ds-archive,{B}"), "ciamBindingRole") == ("backup-archive",)
    assert "main/prod: storage ds-archive added (role backup-archive)" in imported.notices


def test_the_environments_role_map_names_what_azure_cannot_tag():
    d = _record()
    extra = (_res("data", "azurerm_subnet", "snet_admin", {
                 "id": f"{VNET}/subnets/snet-admin", "name": "snet-admin", "virtual_network_name": "vnet-ciam-prod",
                 "address_prefixes": ["10.60.9.0/28"]}),
             _rule("fw-admin", "ds", ["10.60.9.0/28"], ["4444"], 120))
    files = {"main/prod/terraform.tfstate": _state(*extra)}
    untagged = read_terraform_state(files, d, ())
    assert "main/prod: subnet snet-admin (ciamCidr 10.60.9.0/28) is not in the record and names no role (tag it Role, " \
           "name it in roles.json, or record it); not imported" in untagged.notices
    roles = json.dumps({"vnet-ciam-prod/snet-admin": "subnet-admin", "fw-admin": "fw-admin", "fw-gone": "fw-x"})
    imported = read_terraform_state({**files, "main/prod/roles.json": roles}, d, ())
    after = _after(d, imported)
    subnet, rule = get(after, f"cn=snet-admin,{B}"), get(after, f"cn=fw-admin,{B}")
    assert (one(subnet, "ciamBindingRole"), one(subnet, "ciamProviderRef")) == ("subnet-admin", "vnet-ciam-prod/snet-admin")
    assert (one(rule, "ciamBindingRole"), one(rule, "ciamTargetRole"), one(rule, "ciamRulePriority")) == \
        ("fw-admin", "ds", "120")
    assert "main/prod/roles.json: fw-gone matches nothing the source reports" in imported.notices
    assert not import_changes(after, read_terraform_state({**files, "main/prod/roles.json": roles}, after, ()))
    broken = read_terraform_state({**files, "main/prod/roles.json": "{"}, d, ())
    assert "main/prod/roles.json: not JSON; not used" in broken.notices

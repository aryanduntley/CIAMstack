"""Azure Terraform state and CLI outputs imported into the store, against Postgres: a tagged VM is added under an
approved change with its subnet linked, nothing secret reaches the store, and importing the same source again changes
nothing."""
import json
import os

import pytest

import support
from opsdir import operations as ops
from opsdir.core.interchange.ldif import parse
from opsdir.store import postgres as db

pytestmark = pytest.mark.integration

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
VNET = "/subscriptions/0/resourceGroups/rg-ciam-prod/providers/Microsoft.Network/virtualNetworks/vnet-ciam-prod"
KV = "/subscriptions/0/resourceGroups/rg-ciam-prod/providers/Microsoft.KeyVault/vaults/kv-ciam-prod"
BASE = f"""dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=environments,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: environments

dn: cloud=main,ou=environments,dc=ciam-ops
objectClass: top
objectClass: ciamCloud
cloud: main
ciamCloudProvider: azure
ciamRegion: eastus2

dn: {ENV}
objectClass: top
objectClass: ciamEnvironment
env: prod

dn: ou=bindings,{ENV}
objectClass: top
objectClass: organizationalUnit
ou: bindings

dn: cn=snet-ds,ou=bindings,{ENV}
objectClass: top
objectClass: ciamSubnetBinding
cn: snet-ds
ciamBindingRole: subnet-ds
ciamCidr: 10.60.1.0/24
ciamProviderRef: vnet-ciam-prod/snet-ds

dn: ou=changes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-TF-1,ou=changes,dc=ciam-ops
objectClass: top
objectClass: ciamChange
cn: CHG-TF-1
ciamTitle: Record the environment from its Terraform state
ciamChangeStatus: approved
"""


def _res(mode, type_, name, attrs, sensitive=()):
    return {"mode": mode, "type": type_, "name": name, "instances": [
        {"attributes": attrs, "sensitive_attributes": [[{"type": "get_attr", "value": s}] for s in sensitive]}]}


STATE = json.dumps({"version": 4, "resources": [
    _res("data", "azurerm_subnet", "snet_ds", {"id": f"{VNET}/subnets/snet-ds", "name": "snet-ds",
                                               "virtual_network_name": "vnet-ciam-prod",
                                               "address_prefixes": ["10.60.1.0/24"]}),
    _res("managed", "azurerm_network_interface", "ds_1", {
        "id": "/subscriptions/0/nic-ds-1", "ip_configuration": [
            {"name": "primary", "private_ip_address": "10.60.1.11", "subnet_id": f"{VNET}/subnets/snet-ds"}]}),
    _res("managed", "azurerm_linux_virtual_machine", "ds_1", {
        "id": "/subscriptions/0/vm-ds-1", "name": "ds-1", "computer_name": "ds-1", "size": "Standard_D4s_v5",
        "zone": "1", "network_interface_ids": ["/subscriptions/0/nic-ds-1"],
        "tags": {"Role": "ds", "Hostname": "ds-1.az.internal.test"}}),
    _res("data", "azurerm_key_vault_secret", "root", {"name": "ds-root-password", "key_vault_id": KV,
                                                      "value": "S3cr3t-Passw0rd!",
                                                      "tags": {"Role": "ds-root-password"}},
         sensitive=("value",))]})


@pytest.fixture
def conn():
    c = db.connect(support.reachable(support.integration_dsn(os.environ), "OPSDIR_TEST_DSN", support.CREATE_TEST_DB))
    ops.init(c)
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def test_a_state_is_imported_under_a_change_and_again_changes_nothing(conn):
    files = {"main/prod/terraform.tfstate": STATE}
    preview = ops.preview_import(conn, "azure/terraform-state", files)
    assert ops.apply_preview(conn, preview, "CHG-TF-1").lines
    row = conn.execute(f"select attrs from opsdir.entry where dn = 'cn=ds-1,{ENV}'").fetchone()[0]
    assert (row["ciamSubnet"], row["ciamServerRole"], row["ciamPrivateIp"]) == \
        ([f"cn=snet-ds,ou=bindings,{ENV}"], ["ds"], ["10.60.1.11"])
    secret = conn.execute(f"select attrs from opsdir.entry where dn = 'cn=ds-root-password,ou=bindings,{ENV}'")
    assert secret.fetchone()[0]["ciamRefUri"] == ["azkv://kv-ciam-prod/ds-root-password"]
    assert "S3cr3t" not in str(conn.execute("select jsonb_agg(attrs) from opsdir.entry").fetchone()[0])
    assert ops.preview_import(conn, "azure/terraform-state", files).changes == ()


CLI = {"network.json": [{"id": VNET, "name": "vnet-ciam-prod", "type": "Microsoft.Network/virtualNetworks",
                         "addressSpace": {"addressPrefixes": ["10.60.0.0/16"]},
                         "subnets": [{"id": f"{VNET}/subnets/snet-ds", "name": "snet-ds",
                                      "addressPrefix": "10.60.1.0/24"}]}],
       "nics.json": [{"id": "/subscriptions/0/nic-ds-1", "type": "Microsoft.Network/networkInterfaces",
                      "ipConfigurations": [{"name": "primary", "privateIPAddress": "10.60.1.11",
                                            "subnet": {"id": f"{VNET}/subnets/snet-ds"}}]}],
       "vms.json": [{"id": "/subscriptions/0/vm-ds-1", "name": "ds-1", "type": "Microsoft.Compute/virtualMachines",
                     "hardwareProfile": {"vmSize": "Standard_D4s_v5"}, "zones": ["1"],
                     "networkProfile": {"networkInterfaces": [{"id": "/subscriptions/0/nic-ds-1"}]},
                     "tags": {"Role": "ds", "Hostname": "ds-1.az.internal.test"}}]}


def test_cli_outputs_are_imported_under_a_change_and_again_change_nothing(conn):
    files = {f"main/prod/{p}": json.dumps(doc) for p, doc in CLI.items()}
    preview = ops.preview_import(conn, "azure/cli-inventory", files)
    assert ops.apply_preview(conn, preview, "CHG-TF-1").lines
    row = conn.execute(f"select attrs from opsdir.entry where dn = 'cn=ds-1,{ENV}'").fetchone()[0]
    assert (row["ciamSubnet"], row["ciamPrivateIp"]) == ([f"cn=snet-ds,ou=bindings,{ENV}"], ["10.60.1.11"])
    assert ops.preview_import(conn, "azure/cli-inventory", files).changes == ()

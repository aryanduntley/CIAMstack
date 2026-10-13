"""Compute groups on Azure (5.8): a Linux scale set with the role's disks (the boot volume as its os_disk, data volumes
as data disks at LUN 0, 1, ..., named by the scale set's tags BootVolume and DataVolumes), one network interface in
its first subnet with the role's NSG and the service names' backend pools, its role's identity, and an autoscale
setting between its sizes; an adopted one imported. The scale set's disks read back as the role's volumes."""
import json

from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.cli import cli_resources
from opsdir_adapter_azure.compute_groups import render_groups
from opsdir_adapter_azure.inventory import state_resources
from network_fixtures import BETA, entry, model

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/providers"
DES = f"{SUB}/Microsoft.Compute/diskEncryptionSets/des-ciam"
KEY = entry(BETA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption",
            ciamRefUri="azkv-key://kv-ciam/keys/disk", ciamProviderRef=DES)
BOOT = entry(BETA, "vol-app-boot", "ciamVolume", ciamBindingRole="volume-app-boot", ciamTargetRole="app",
             ciamVolumeKind="boot", ciamVolumeSizeGb="64", ciamVolumeClass="ssd")
DATA = entry(BETA, "vol-app-data", "ciamVolume", ciamBindingRole="volume-app-data", ciamTargetRole="app",
             ciamVolumeKind="data", ciamMountPath="/opt/app", ciamVolumeSizeGb="256", ciamVolumeClass="provisioned",
             ciamIops="6000", ciamThroughputMb="250")
GROUP = entry(BETA, "vmss-app", "ciamComputeGroup", ciamBindingRole="compute-app", ciamTargetRole="app",
              ciamImageRef=f"{SUB}/Microsoft.Compute/images/app", ciamInstanceSize="Standard_D2s_v5",
              ciamMinSize="2", ciamMaxSize="5", ciamSpansZone=("1", "2"), ciamSubnetRole=("subnet-web", "subnet-ds"))
POOLS = {"app": (("${azurerm_lb_backend_address_pool.svc_app.id}",),
                 ("${azurerm_application_gateway.svc_web.id}/backendAddressPools/servers",))}


def _flat(text):
    return " ".join(text.split())


def _render(*records, pools=None):
    m = model(beta=records)[2]
    des = next((b for b in m.bindings if "ciamKeyRef" in b.classes), None)
    return _flat("\n\n".join(as_text(render_groups(m, des, (), pools or {}))))


def test_a_group_is_a_scale_set_with_its_roles_disks_and_an_autoscale_setting():
    out = _render(KEY, BOOT, DATA, GROUP, pools=POOLS)
    for text in ('resource "azurerm_linux_virtual_machine_scale_set" "vmss_app" { name = "vmss-ciam-prod-vmss-app"',
                 'sku = "Standard_D2s_v5" instances = 2 zones = ["1", "2"]',
                 'os_disk { caching = "ReadWrite" storage_account_type = "Premium_LRS" disk_size_gb = 64 '
                 f'disk_encryption_set_id = "{DES}" }}',
                 'data_disk { lun = 0 caching = "None" storage_account_type = "PremiumV2_LRS" create_option = "Empty" '
                 "disk_size_gb = 256 disk_iops_read_write = 6000 disk_mbps_read_write = 250 "
                 f'disk_encryption_set_id = "{DES}" }}',
                 "# a scale set's instances share one subnet: subnet-web, not subnet-ds",
                 "network_security_group_id = azurerm_network_security_group.app.id",
                 "subnet_id = data.azurerm_subnet.subnet_web.id",
                 "load_balancer_backend_address_pool_ids = [azurerm_lb_backend_address_pool.svc_app.id]",
                 'application_gateway_backend_address_pool_ids = ["${azurerm_application_gateway.svc_web.id}/'
                 'backendAddressPools/servers"]',
                 'BootVolume = "vol-app-boot" DataVolumes = "0=vol-app-data"',
                 "# vmss-app's instances mount vol-app-data at /opt/app (their own configuration, not Terraform)",
                 'resource "azurerm_monitor_autoscale_setting" "vmss_app" { name = "autoscale-vmss-ciam-prod-vmss-app"',
                 "target_resource_id = azurerm_linux_virtual_machine_scale_set.vmss_app.id",
                 'profile { name = "default" capacity { default = 2 minimum = 2 maximum = 5 } }'):
        assert _flat(text) in out, text
    assert "import" not in out


def test_an_adopted_scale_set_is_imported_and_its_autoscale_setting_said():
    ref = f"{SUB}/Microsoft.Compute/virtualMachineScaleSets/legacy-app"
    adopted = entry(BETA, "vmss-app", "ciamComputeGroup", ciamBindingRole="compute-app", ciamTargetRole="app",
                    ciamProviderRef=ref, ciamMinSize="1", ciamMaxSize="2", ciamDesiredSize="1")
    out = _render(KEY, adopted)
    assert 'name = "legacy-app"' in out and _flat(f'import {{ to = azurerm_linux_virtual_machine_scale_set.vmss_app '
                                                  f'id = "{ref}" }}') in out
    assert "# vmss-app exists: an autoscale setting it already has must be imported by hand" in out


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": f"r{i}",
         "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for i, (t, a) in enumerate(resources)]})


SCALE_SET = ("azurerm_linux_virtual_machine_scale_set", {
        "id": f"{SUB}/Microsoft.Compute/virtualMachineScaleSets/vmss-app", "name": "vmss-app", "instances": 2,
        "sku": "Standard_D2s_v5", "zones": ["1", "2"], "source_image_id": f"{SUB}/Microsoft.Compute/images/app",
        "tags": {"Role": "app", "BootVolume": "vol-app-boot", "DataVolumes": "0=vol-app-data"},
        "os_disk": [{"storage_account_type": "Premium_LRS", "disk_size_gb": 64, "disk_encryption_set_id": DES}],
        "data_disk": [{"lun": 0, "storage_account_type": "PremiumV2_LRS", "disk_size_gb": 256,
                       "disk_iops_read_write": 6000, "disk_mbps_read_write": 250,
                       "disk_encryption_set_id": DES}]})
ENCRYPTION = ("azurerm_disk_encryption_set", {"id": DES,
                                              "key_vault_key_id": "https://kv-ciam.vault.azure.net/keys/disk/1"})


def test_a_scale_sets_disks_read_back_as_the_roles_volumes():
    volumes = {r.ref: (r.attrs, r.links) for r in state_resources(_state(SCALE_SET, ENCRYPTION))[0]
               if r.kind == "volume"}
    assert volumes == {
        "vol-app-data": ({"ciamVolumeKind": ("data",), "ciamVolumeSizeGb": ("256",),
                          "ciamVolumeClass": ("provisioned",), "ciamIops": ("6000",), "ciamThroughputMb": ("250",),
                          "ciamVolumeEncrypted": ("TRUE",), "ciamTargetRole": ("app",)},
                         {"ciamEncryptedByRole": "azkv-key://kv-ciam/keys/disk"}),
        "vol-app-boot": ({"ciamVolumeKind": ("boot",), "ciamVolumeSizeGb": ("64",), "ciamVolumeClass": ("ssd",),
                          "ciamVolumeEncrypted": ("TRUE",), "ciamTargetRole": ("app",)},
                         {"ciamEncryptedByRole": "azkv-key://kv-ciam/keys/disk"})}


def test_the_cli_and_an_arm_template_read_a_scale_set_and_its_autoscale_setting_as_state_does():
    ss_id = SCALE_SET[1]["id"]
    managed = {"storageAccountType": "PremiumV2_LRS", "diskEncryptionSet": {"id": DES}}
    items = [{"id": ss_id, "name": "vmss-app", "type": "Microsoft.Compute/virtualMachineScaleSets",
              "location": "eastus2", "sku": {"name": "Standard_D2s_v5", "capacity": 2}, "zones": ["1", "2"],
              "tags": SCALE_SET[1]["tags"], "orchestrationMode": "Uniform",
              "virtualMachineProfile": {
                  "osProfile": {"linuxConfiguration": {"disablePasswordAuthentication": True}},
                  "storageProfile": {
                      "imageReference": {"id": f"{SUB}/Microsoft.Compute/images/app"},
                      "osDisk": {"diskSizeGB": 64, "managedDisk": {"storageAccountType": "Premium_LRS",
                                                                    "diskEncryptionSet": {"id": DES}}},
                      "dataDisks": [{"lun": 0, "diskSizeGB": 256, "diskIOPSReadWrite": 6000,
                                     "diskMBpsReadWrite": 250, "managedDisk": managed}]}}},
             {"id": f"{SUB}/Microsoft.Insights/autoscalesettings/autoscale-app", "name": "autoscale-app",
              "type": "Microsoft.Insights/autoscalesettings", "targetResourceUri": ss_id,
              "profiles": [{"name": "default", "capacity": {"default": "2", "minimum": "2", "maximum": "5"}}]},
             {"id": DES, "name": "des-ciam", "type": "Microsoft.Compute/diskEncryptionSets",
              "activeKey": {"keyUrl": "https://kv-ciam.vault.azure.net/keys/disk/1"}}]
    state = ("azurerm_monitor_autoscale_setting", {"id": items[1]["id"], "name": "autoscale-app",
                                                   "target_resource_id": ss_id,
                                                   "profile": [{"name": "default", "capacity": [
                                                       {"default": 2, "minimum": 2, "maximum": 5}]}]})

    def found(resources):
        return {(r.kind, r.ref): (r.attrs, r.links) for r in resources if r.kind in ("compute", "volume")}
    cli = found(cli_resources({"scale-sets.json": json.dumps(items[:1]), "autoscale.json": json.dumps(items[1:2]),
                               "des.json": json.dumps(items[2:])})[0])
    by_state = found(state_resources(_state(SCALE_SET, ENCRYPTION, state))[0])
    assert cli == by_state and cli[("compute", ss_id)][0]["ciamMaxSize"] == ("5",)

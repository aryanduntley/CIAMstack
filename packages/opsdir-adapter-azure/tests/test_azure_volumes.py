"""Disks on Azure: a role's boot volume as each VM's os_disk (size, type, the disk encryption set of its key role; an
OS disk can't be provisioned-IOPS), the VM tagged BootVolume; each data volume a managed disk in the VM's zone with
its attachment at LUN 0..; an unencrypted record or a key without a disk encryption set said (Azure always
encrypts), snapshot policies a comment until the Backup vault. Read back from state, the CLI and ARM."""
import json

from opsdir.core.environment import servers_with_role
from opsdir_adapter_azure.arm import arm_resources
from opsdir_adapter_azure.cli import cli_resources
from opsdir_adapter_azure.inventory import state_resources
from opsdir_adapter_azure.volumes import boot_tag, os_disk, server_volumes, snapshot_policy_notes
from network_fixtures import BETA, entry, model

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/providers"
DES = f"{SUB}/Microsoft.Compute/diskEncryptionSets/des-ciam"
VM = f"{SUB}/Microsoft.Compute/virtualMachines/ds-1"
KEY = entry(BETA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption",
            ciamRefUri="azkv-key://kv-ciam/keys/disk", ciamProviderRef=DES)
BOOT = entry(BETA, "vol-ds-boot", "ciamVolume", ciamBindingRole="volume-ds-boot", ciamTargetRole="ds",
             ciamVolumeKind="boot", ciamVolumeSizeGb="64", ciamVolumeClass="ssd")
DATA = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
             ciamVolumeKind="data", ciamMountPath="/opt/ds/db", ciamVolumeSizeGb="256", ciamVolumeClass="provisioned",
             ciamIops="6000", ciamThroughputMb="250", ciamSnapshotPolicyRole="snapshots-daily")
POLICY = entry(BETA, "snapshots-daily", "ciamSnapshotPolicy", ciamBindingRole="snapshots-daily", ciamRetentionDays="7")


def _m(*records):
    return model(beta=records)[2]


def _flat(text):
    return " ".join(text.split())


def _ds1(m):
    return servers_with_role(m, "ds")[0]


def test_the_boot_volume_is_the_os_disk_and_the_vm_names_it():
    m = _m(KEY, BOOT, DATA)
    notes, disk = os_disk(m, _ds1(m), None)
    assert notes == () and dict(disk.body) == {"caching": "ReadWrite", "storage_account_type": "Premium_LRS",
                                               "disk_size_gb": 64, "disk_encryption_set_id": DES}
    assert boot_tag(m, _ds1(m)) == {"BootVolume": "vol-ds-boot"}
    provisioned = entry(BETA, "vol-ds-boot", "ciamVolume", ciamBindingRole="volume-ds-boot", ciamTargetRole="ds",
                        ciamVolumeKind="boot", ciamVolumeClass="provisioned")
    p = _m(KEY, provisioned)
    notes, disk = os_disk(p, _ds1(p), None)
    assert notes == ("# vol-ds-boot: an OS disk can't be PremiumV2_LRS: Premium_LRS",)
    assert dict(disk.body)["storage_account_type"] == "Premium_LRS"


def test_without_a_boot_volume_the_os_disk_is_as_before():
    m = _m(KEY)
    des = next(b for b in m.bindings if b.dn.startswith("cn=key-disk"))
    assert os_disk(m, _ds1(m), des)[1].body == (("caching", "ReadWrite"), ("storage_account_type", "Premium_LRS"),
                                                ("disk_encryption_set_id", DES))
    assert boot_tag(m, _ds1(m)) == {}


def test_a_data_volume_is_a_managed_disk_attached_at_its_lun():
    m = _m(KEY, BOOT, DATA, POLICY)
    out = _flat("\n\n".join(server_volumes(m, _ds1(m))))
    for text in ('resource "azurerm_managed_disk" "ds_1_vol_ds_data"', 'name = "disk-ds-1-vol-ds-data"',
                 'zone = "zone-a"', 'storage_account_type = "PremiumV2_LRS"', 'create_option = "Empty"',
                 "disk_size_gb = 256", "disk_iops_read_write = 6000", "disk_mbps_read_write = 250",
                 f'disk_encryption_set_id = "{DES}"', 'SnapshotPolicy = "snapshots-daily"', 'Server = "ds-1"',
                 'resource "azurerm_virtual_machine_data_disk_attachment" "ds_1_vol_ds_data"',
                 "managed_disk_id = azurerm_managed_disk.ds_1_vol_ds_data.id",
                 "virtual_machine_id = azurerm_linux_virtual_machine.ds_1.id", "lun = 0", 'caching = "None"',
                 "# ds-1 mounts vol-ds-data at /opt/ds/db (its own configuration, not Terraform)"):
        assert _flat(text) in out, text
    (note,) = snapshot_policy_notes(m)
    assert "Azure Backup's disk backup, in a Backup vault: not rendered yet (4.10 task 5)" in note


def test_azure_always_encrypts_and_a_key_without_a_disk_encryption_set_is_said():
    off = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
                ciamVolumeKind="data", ciamVolumeEncrypted="FALSE")
    m = _m(KEY, off)
    out = "\n".join(server_volumes(m, _ds1(m)))
    assert "# vol-ds-data: recorded as not encrypted; Azure encrypts every managed disk at rest" in out
    assert "disk_encryption_set_id" not in out
    bare = entry(BETA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption", ciamRefUri="azkv-key://kv/keys/k")
    m = _m(bare, DATA)
    assert "key role disk-encryption names no disk encryption set (ciamProviderRef); Azure's own key encrypts it" \
        in "\n".join(server_volumes(m, _ds1(m)))


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": f"r{i}", "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for i, (t, a) in enumerate(resources)]})


ENCRYPTION_SET = ("azurerm_disk_encryption_set", {"id": DES, "key_vault_key_id":
                                                  "https://kv-ciam.vault.azure.net/keys/disk/0123"})
DISK = ("azurerm_managed_disk", {"id": f"{SUB}/Microsoft.Compute/disks/disk-ds-1-vol-ds-data", "name": "disk-ds-1",
                                 "storage_account_type": "PremiumV2_LRS", "disk_size_gb": 256,
                                 "disk_iops_read_write": 6000, "disk_mbps_read_write": 250,
                                 "disk_encryption_set_id": DES,
                                 "tags": {"Volume": "vol-ds-data", "Role": "volume-ds-data"}})
ATTACH = ("azurerm_virtual_machine_data_disk_attachment", {"managed_disk_id": DISK[1]["id"], "virtual_machine_id": VM,
                                                           "lun": 0})
VM_STATE = ("azurerm_linux_virtual_machine", {"id": VM, "name": "ds-1",
                                              "tags": {"Role": "ds", "BootVolume": "vol-ds-boot"},
                                              "os_disk": [{"storage_account_type": "Premium_LRS", "disk_size_gb": 64,
                                                           "disk_encryption_set_id": DES}]})


def _by(resources):
    return {(r.kind, r.ref): r for r in resources}


def test_disks_are_read_back_from_state():
    by = _by(state_resources(_state(ENCRYPTION_SET, DISK, ATTACH, VM_STATE))[0])
    data = by[("volume", "vol-ds-data")]
    assert data.attrs == {"ciamVolumeKind": ("data",), "ciamVolumeSizeGb": ("256",), "ciamVolumeClass": ("provisioned",),
                          "ciamIops": ("6000",), "ciamThroughputMb": ("250",), "ciamVolumeEncrypted": ("TRUE",),
                          "ciamTargetRole": ("ds",)}
    assert data.links == {"ciamEncryptedByRole": "azkv-key://kv-ciam/keys/disk"} and data.role == "volume-ds-data"
    boot = by[("volume", "vol-ds-boot")]
    assert boot.attrs == {"ciamVolumeKind": ("boot",), "ciamVolumeSizeGb": ("64",), "ciamVolumeClass": ("ssd",),
                          "ciamVolumeEncrypted": ("TRUE",), "ciamTargetRole": ("ds",)}


def test_an_untagged_data_disk_on_the_environments_vms_is_named():
    bare = ("azurerm_managed_disk", {"id": f"{SUB}/Microsoft.Compute/disks/extra", "name": "extra", "tags": {}})
    stray = ("azurerm_managed_disk", {"id": f"{SUB}/Microsoft.Compute/disks/elsewhere", "name": "elsewhere"})
    attach = ("azurerm_virtual_machine_data_disk_attachment", {"managed_disk_id": bare[1]["id"],
                                                               "virtual_machine_id": VM})
    _, notices = state_resources(_state(VM_STATE, bare, attach, stray))
    assert "managed disk extra (ds-1) carries no tag Volume: which of the record's volumes it is can't be told; not " \
           "recorded" in notices
    assert not [n for n in notices if "elsewhere" in n]


def test_the_cli_and_an_arm_template_read_the_same():
    vm = {"id": VM, "name": "ds-1", "type": "Microsoft.Compute/virtualMachines",
          "tags": {"Role": "ds", "BootVolume": "vol-ds-boot"},
          "storageProfile": {"osDisk": {"name": "ds-1-os", "diskSizeGB": 64, "managedDisk": {
              "id": f"{SUB}/Microsoft.Compute/disks/ds-1-os", "storageAccountType": "Premium_LRS",
              "diskEncryptionSet": {"id": DES}}},
              "dataDisks": [{"lun": 0, "managedDisk": {"id": DISK[1]["id"]}}]}}
    disk = {"id": DISK[1]["id"], "name": "disk-ds-1-vol-ds-data", "type": "Microsoft.Compute/disks", "zones": ["1"],
            "sku": {"name": "PremiumV2_LRS"}, "diskSizeGB": 256, "diskIOPSReadWrite": 6000, "diskMBpsReadWrite": 250,
            "encryption": {"type": "EncryptionAtRestWithCustomerKey", "diskEncryptionSetId": DES}, "managedBy": VM,
            "tags": {"Volume": "vol-ds-data", "Role": "volume-ds-data"}}
    os_item = {"id": f"{SUB}/Microsoft.Compute/disks/ds-1-os", "name": "ds-1-os", "type": "Microsoft.Compute/disks",
               "osType": "Linux", "managedBy": VM}
    resources, _ = cli_resources({"vms.json": json.dumps([vm]), "disks.json": json.dumps([disk, os_item])})
    by = _by(resources)
    assert by[("volume", "vol-ds-data")].attrs["ciamVolumeSizeGb"] == ("256",)
    assert by[("volume", "vol-ds-data")].attrs["ciamTargetRole"] == ("ds",)
    assert by[("volume", "vol-ds-boot")].attrs["ciamVolumeSizeGb"] == ("64",)
    template = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0", "resources": [
                    {"type": "Microsoft.Compute/disks", "apiVersion": "2023-04-02", "name": "disk-ds-1-vol-ds-data",
                     "location": "eastus", "zones": ["1"], "sku": {"name": "PremiumV2_LRS"},
                     "tags": {"Volume": "vol-ds-data", "Role": "volume-ds-data"},
                     "properties": {"diskSizeGB": 256, "diskIOPSReadWrite": 6000, "diskMBpsReadWrite": 250,
                                    "creationData": {"createOption": "Empty"}}}]}
    arm, _ = arm_resources({"disks/azuredeploy.json": json.dumps(template)})
    assert _by(arm)[("volume", "vol-ds-data")].attrs["ciamVolumeClass"] == ("provisioned",)

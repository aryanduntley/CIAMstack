"""The Azure CLI's managed disks (and an ARM template's, read the same way), normalized to the attribute names of the
matching hashicorp/azurerm resources (opsdir_adapter_azure.volumes reads both). Pure.

  az disk list                          Microsoft.Compute/disks -> azurerm_managed_disk (a VM's OS disk is the VM's
                                        os_disk instead: its storageProfile names it)
  az vm list                            each VM's storageProfile: its osDisk (size, type, disk encryption set) as
                                        its os_disk, its dataDisks (LUN, disk) as data disk attachments
"""

DISKS = "microsoft.compute/disks"
VMS = "microsoft.compute/virtualmachines"
READ = (DISKS,)                     # what an ARM template's reader reads of these


def _id(o):
    return (o or {}).get("id") if isinstance(o, dict) else o


def _low(v):
    return (v or "").lower()


def os_disk_of(vm):
    """A VM's os_disk attributes from its storageProfile.osDisk ([] when it names none)."""
    osd = (vm.get("storageProfile") or {}).get("osDisk") or {}
    managed = osd.get("managedDisk") or {}
    if not osd:
        return []
    return [{"name": osd.get("name"), "disk_size_gb": osd.get("diskSizeGB") or osd.get("diskSizeGb"),
             "storage_account_type": managed.get("storageAccountType"),
             "disk_encryption_set_id": _id(managed.get("diskEncryptionSet")), "managed_disk_id": _id(managed)}]


def disk_items(items):
    """(azurerm type, attributes) pairs of the data disks and their attachments to the VMs."""
    vms = [i for k, i in items if k == VMS]
    os_disks = {_low(_id(((vm.get("storageProfile") or {}).get("osDisk") or {}).get("managedDisk"))) for vm in vms}
    listed = [(vm.get("id"), d) for vm in vms for d in (vm.get("storageProfile") or {}).get("dataDisks") or ()]
    by_vm = {_low(_id(d.get("managedDisk"))) for _, d in listed}
    disks = [d for k, d in items if k == DISKS and _low(d.get("id")) not in os_disks and not d.get("osType")]
    return [*(("azurerm_managed_disk", {
                "id": d.get("id"), "name": d.get("name"), "zone": (d.get("zones") or [None])[0],
                "storage_account_type": (d.get("sku") or {}).get("name"),
                "disk_size_gb": d.get("diskSizeGB") or d.get("diskSizeGb"),
                "disk_iops_read_write": d.get("diskIOPSReadWrite"), "disk_mbps_read_write": d.get("diskMBpsReadWrite"),
                "disk_encryption_set_id": (d.get("encryption") or {}).get("diskEncryptionSetId"),
                "tags": d.get("tags") or {}}) for d in disks),
            *(("azurerm_virtual_machine_data_disk_attachment", {
                "managed_disk_id": _id(d.get("managedDisk")), "virtual_machine_id": vm, "lun": d.get("lun")})
              for vm, d in listed),
            *(("azurerm_virtual_machine_data_disk_attachment", {"managed_disk_id": d.get("id"),
                                                                 "virtual_machine_id": d.get("managedBy")})
              for d in disks if d.get("managedBy") and _low(d.get("id")) not in by_vm)]

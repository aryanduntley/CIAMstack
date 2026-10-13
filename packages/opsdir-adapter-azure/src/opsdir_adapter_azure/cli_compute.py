"""The Azure CLI's virtual machine scale sets and autoscale settings (and an ARM template's, read the same way:
properties flattened), normalized to the attribute names of the matching hashicorp/azurerm resources (inventory reads
compute groups from them, volumes a scale set's disks). Pure.

  az vmss list                    Microsoft.Compute/virtualMachineScaleSets -> azurerm_linux_virtual_machine_scale_set
                                  (azurerm_windows_virtual_machine_scale_set when its OS profile is Windows's,
                                  azurerm_orchestrated_virtual_machine_scale_set when its orchestration is Flexible):
                                  size and instance count (its sku), zones, image, OS and data disks, tags
  az monitor autoscale list       Microsoft.Insights/autoscalesettings -> azurerm_monitor_autoscale_setting (its target
                                  and each profile's capacity)
"""

SCALE_SETS = "microsoft.compute/virtualmachinescalesets"
AUTOSCALE = "microsoft.insights/autoscalesettings"
READ = (SCALE_SETS, AUTOSCALE)       # what an ARM template's reader reads of these


def _id(o):
    return (o or {}).get("id") if isinstance(o, dict) else o


def _size(d):
    return d.get("diskSizeGB") or d.get("diskSizeGb")


def _kind(s):
    profile = (s.get("virtualMachineProfile") or {}).get("osProfile") or {}
    return ("azurerm_orchestrated_virtual_machine_scale_set" if s.get("orchestrationMode") == "Flexible" else
            "azurerm_windows_virtual_machine_scale_set" if profile.get("windowsConfiguration") else
            "azurerm_linux_virtual_machine_scale_set")


def _number(v):
    return int(v) if isinstance(v, str) and v.isdigit() else v


def _scale_set(s):
    storage = (s.get("virtualMachineProfile") or {}).get("storageProfile") or {}
    image, osd = storage.get("imageReference") or {}, storage.get("osDisk") or {}
    managed = osd.get("managedDisk") or {}
    return (_kind(s), {
        "id": s.get("id"), "name": s.get("name"), "location": s.get("location"),
        "sku": (s.get("sku") or {}).get("name"), "instances": _number((s.get("sku") or {}).get("capacity")),
        "zones": s.get("zones") or [], "tags": s.get("tags") or {},
        "source_image_id": image.get("id"),
        "source_image_reference": [] if image.get("id") or not image.get("offer") else [
            {k: image.get(k) for k in ("publisher", "offer", "sku", "version")}],
        "os_disk": [{"disk_size_gb": _size(osd), "storage_account_type": managed.get("storageAccountType"),
                     "disk_encryption_set_id": _id(managed.get("diskEncryptionSet"))}] if osd else [],
        "data_disk": [{"lun": d.get("lun"), "disk_size_gb": _size(d),
                       "storage_account_type": (d.get("managedDisk") or {}).get("storageAccountType"),
                       "disk_iops_read_write": d.get("diskIOPSReadWrite") or d.get("diskIopsReadWrite"),
                       "disk_mbps_read_write": d.get("diskMBpsReadWrite") or d.get("diskMbpsReadWrite"),
                       "disk_encryption_set_id": _id((d.get("managedDisk") or {}).get("diskEncryptionSet"))}
                      for d in storage.get("dataDisks") or ()]})


def _autoscale(a):
    return ("azurerm_monitor_autoscale_setting", {
        "id": a.get("id"), "name": a.get("name"), "target_resource_id": a.get("targetResourceUri"),
        "profile": [{"name": p.get("name"), "capacity": [{k: _number((p.get("capacity") or {}).get(k))
                                                          for k in ("default", "minimum", "maximum")}]}
                    for p in a.get("profiles") or ()]})


def compute_items(items):
    """(azurerm type, attributes) pairs of the scale sets and autoscale settings among (kind, item) pairs."""
    return [*(_scale_set(i) for k, i in items if k == SCALE_SETS),
            *(_autoscale(i) for k, i in items if k == AUTOSCALE)]

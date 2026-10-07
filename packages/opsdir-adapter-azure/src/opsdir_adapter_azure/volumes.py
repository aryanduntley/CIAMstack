"""Azure: each server role's disks (opsdir.domains.data.volumes), rendered as Terraform and read back. Pure.

  the boot disk (the role's boot volume): each VM's os_disk, its size (disk_size_gb) and type (storage_account_type
  from its class; an OS disk can't be provisioned-IOPS: Premium_LRS, said), encrypted with the disk encryption set of
  its key role (the disk-encryption binding's when it names none); the VM tagged BootVolume
  each data volume of the role, per VM: an azurerm_managed_disk in the VM's zone (size, type, IOPS and MB/s where the
  type takes them, the disk encryption set), tagged Volume, Role, Server and SnapshotPolicy, attached at LUN 0, 1, ...
  in the volumes' order (caching None: a database's writes); the VM mounts it at its ciamMountPath itself
  Azure encrypts every managed disk at rest: a volume recorded unencrypted is a comment (Azure's own key encrypts it);
  a key role with no disk encryption set leaves the platform key, said. A snapshot policy has no Azure setting of its
  own: scheduled disk snapshots are Azure Backup's disk backup, which a backup plan renders (backups.py): a comment
  says so.
Class to type: standard Standard_LRS, ssd Premium_LRS, provisioned PremiumV2_LRS (TYPES; the reader also takes
StandardSSD_LRS and the zone-redundant ones as ssd, UltraSSD_LRS as provisioned).

Read back from (azurerm type, attributes) pairs, Terraform state as it is or the CLI and ARM normalized to it
(cli_disk.py): azurerm_managed_disk (+ azurerm_virtual_machine_data_disk_attachment) grouped by tag Volume into one
volume of the role their VMs run (the most common size, type, IOPS, MB/s; the key of its disk encryption set as its
key role),
each VM's os_disk as the boot volume its tag BootVolume names; a disk an Azure Backup backup instance protects follows
that instance's policy (its snapshot policy role: the backup plan's). A data disk attached to the environment's VMs
without a Volume tag is named.
"""
from collections import Counter

from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND, of_class, one_role
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.data.volumes import (POLICY, boot_volume, data_volumes, is_encrypted, volume_key_role,
                                         volume_policy)
from opsdir.domains.network.stack import kept_by, owned
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from opsdir_format_terraform.state import first_block
from .backups import disk_policies
from .cmk import key_ref
from .identities import LOC, RG
from .account import tagged

TYPES = {"standard": "Standard_LRS", "ssd": "Premium_LRS", "provisioned": "PremiumV2_LRS"}
CLASSES = {"Standard_LRS": "standard", "StandardSSD_LRS": "ssd", "StandardSSD_ZRS": "ssd", "Premium_LRS": "ssd",
           "Premium_ZRS": "ssd", "PremiumV2_LRS": "provisioned", "UltraSSD_LRS": "provisioned"}
PROVISIONED = ("PremiumV2_LRS", "UltraSSD_LRS")     # the types IOPS and MB/s are set on


def _int(v, attr):
    return int(one(v, attr)) if one(v, attr) else None


def _given(*pairs):
    return tuple((k, v) for k, v in pairs if v is not None)


def _encryption_set(m, v):
    """(the volume's disk_encryption_set_id argument, or (), and comments)."""
    if not is_encrypted(v):
        return (), (f"# {rdn_value(v)}: recorded as not encrypted; Azure encrypts every managed disk at rest (with "
                    "its own key when no disk encryption set is named)",)
    role = volume_key_role(v)
    b = one_role(m, role)
    if b is None:
        return (), (f"# {rdn_value(v)}: {UNBOUND}{role}: no key binding for role {role}; Azure's own key encrypts it",)
    if not one(b, "ciamProviderRef"):
        return (), (f"# {rdn_value(v)}: key role {role} names no disk encryption set (ciamProviderRef); Azure's own "
                    "key encrypts it",)
    return (("disk_encryption_set_id", one(b, "ciamProviderRef")),), ()


def os_disk(m, s, des):
    """(comments, the os_disk Block) of VM s: its role's boot volume (size, type, disk encryption set), else Premium_LRS
    encrypted with the disk-encryption binding's set (des: that binding, or None)."""
    v = boot_volume(m, one(s, "ciamServerRole"))
    if v is None:
        encryption = (("disk_encryption_set_id", one(des, "ciamProviderRef")) if des and one(des, "ciamProviderRef")
                      else ("#", "UNBOUND: no disk-encryption binding in this environment"))
        return (), Block((("caching", "ReadWrite"), ("storage_account_type", "Premium_LRS"), encryption))
    kind = TYPES.get(one(v, "ciamVolumeClass"), "Premium_LRS")
    encryption, notes = _encryption_set(m, v)
    note = (f"# {rdn_value(v)}: an OS disk can't be {kind}: Premium_LRS",) if kind in PROVISIONED else ()
    return (*notes, *note), Block((("caching", "ReadWrite"),
                                   ("storage_account_type", "Premium_LRS" if kind in PROVISIONED else kind),
                                   *_given(("disk_size_gb", _int(v, "ciamVolumeSizeGb"))), *encryption))


def boot_tag(m, s):
    """The VM tag naming its boot volume ({'BootVolume': cn}), or {} when its role records none."""
    v = boot_volume(m, one(s, "ciamServerRole"))
    return {"BootVolume": rdn_value(v)} if v is not None else {}


def server_volumes(m, s):
    """HCL for VM s's data volumes: each a managed disk in its zone and its attachment."""
    n, out = tf_name(rdn_value(s)), []
    for lun, v in enumerate(data_volumes(m, one(s, "ciamServerRole"))):
        if not owned(v):
            out.append(f"# Volume '{rdn_value(v)}' of {rdn_value(s)} is kept by {kept_by(m, v)}: not rendered here")
            continue
        dn, kind, policy = tf_name(f"{rdn_value(s)}_{rdn_value(v)}"), TYPES.get(one(v, "ciamVolumeClass"),
                                                                              "Premium_LRS"), volume_policy(m, v)
        encryption, notes = _encryption_set(m, v)
        tags = {"Volume": rdn_value(v), "Role": one(v, "ciamBindingRole"), "Server": rdn_value(s),
                **({"SnapshotPolicy": one(policy, "ciamBindingRole")} if policy is not None else {}),
                "ManagedBy": "opsdir"}
        out += [*notes,
                *((f"# {rdn_value(s)} mounts {rdn_value(v)} at {one(v, 'ciamMountPath')} (its own configuration, not "
                   "Terraform)",) if one(v, "ciamMountPath") else ()),
                block("resource", ["azurerm_managed_disk", dn], [
                    ("name", f"disk-{rdn_value(s)}-{rdn_value(v)}"), ("location", LOC), ("resource_group_name", RG),
                    ("zone", one(s, "ciamZone")), ("storage_account_type", kind), ("create_option", "Empty"),
                    *_given(("disk_size_gb", _int(v, "ciamVolumeSizeGb")),
                            ("disk_iops_read_write", _int(v, "ciamIops") if kind in PROVISIONED else None),
                            ("disk_mbps_read_write", _int(v, "ciamThroughputMb") if kind in PROVISIONED else None)),
                    *encryption, ("tags", tagged(m, tags))]),
                block("resource", ["azurerm_virtual_machine_data_disk_attachment", dn], [
                    ("managed_disk_id", ref(f"azurerm_managed_disk.{dn}.id")),
                    ("virtual_machine_id", ref(f"azurerm_linux_virtual_machine.{n}.id")), ("lun", lun),
                    ("caching", "None")])]
    return tuple(out)


def snapshot_policy_notes(m):
    """Comments for environment m's snapshot policies: Azure snapshots managed disks on a schedule only with Azure
    Backup's disk backup, which a backup plan renders (opsdir_adapter_azure.backups); someone else's named."""
    return tuple(f"# Snapshot policy '{rdn_value(p)}' (role {one(p, 'ciamBindingRole')}): "
                 + (f"kept by {kept_by(m, p)}: not rendered here" if not owned(p) else
                    "Azure snapshots managed disks on a schedule with Azure Backup's disk backup, in a Backup vault: "
                    "record a backup plan (ciamBackupPlan) with this role and a vault, which renders as one")
                 for p in of_class(m, POLICY))


# ------------------------------------------------------------------ read back
def _low(v):
    return (v or "").lower()


def _common(values_):
    found = Counter(v for v in values_ if v not in (None, ""))
    return found.most_common(1)[0][0] if found else None


VMS = ("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine")


def volume_resources(pairs):
    """(volume resources, notices) of (azurerm type, attributes) pairs: data disks grouped by tag Volume, VMs' OS
    disks by their tag BootVolume."""
    vms = {_low(v.get("id")): v for v in of_types(pairs, *VMS) if v.get("id")}
    sets = {_low(e.get("id")): key_ref(e.get("key_vault_key_id"))
            for e in of_types(pairs, "azurerm_disk_encryption_set")}

    def key(des):
        return sets.get(_low(des)) if des else None
    attached = {_low(a.get("managed_disk_id")): vms.get(_low(a.get("virtual_machine_id")), {})
                for a in of_types(pairs, "azurerm_virtual_machine_data_disk_attachment")}
    disks = [d for d in of_types(pairs, "azurerm_managed_disk") if d.get("id")]
    followed = disk_policies(pairs)
    named = {}
    for d in disks:
        named.setdefault((d.get("tags") or {}).get("Volume"), []).append(d)

    def data(name, found):
        kinds = [d.get("storage_account_type") for d in found]
        return resource("volume", name, {
            "ciamVolumeKind": "data", "ciamVolumeSizeGb": _common(d.get("disk_size_gb") for d in found),
            "ciamVolumeClass": _common(CLASSES.get(k) for k in kinds),
            "ciamIops": _common(d.get("disk_iops_read_write") for d in found
                                if d.get("storage_account_type") in PROVISIONED),
            "ciamThroughputMb": _common(d.get("disk_mbps_read_write") for d in found
                                        if d.get("storage_account_type") in PROVISIONED),
            "ciamVolumeEncrypted": "TRUE",
            "ciamTargetRole": _common(tagged_role(attached.get(_low(d.get("id")), {}).get("tags") or {})
                                      for d in found)},
            links={"ciamEncryptedByRole": key(_common(d.get("disk_encryption_set_id") for d in found)),
                   "ciamSnapshotPolicyRole": _common(followed.get(_low(d.get("id"))) for d in found)},
            name=name, role=_common(tagged_role(d.get("tags") or {}) for d in found), tags=found[0].get("tags") or {})
    booted = {}
    for vm in vms.values():
        if (vm.get("tags") or {}).get("BootVolume"):
            booted.setdefault(vm["tags"]["BootVolume"], []).append((vm, first_block(vm.get("os_disk"))))

    def boot(name, found):
        osd = [o for _, o in found]
        return resource("volume", name, {
            "ciamVolumeKind": "boot", "ciamVolumeSizeGb": _common(o.get("disk_size_gb") for o in osd),
            "ciamVolumeClass": _common(CLASSES.get(o.get("storage_account_type")) for o in osd),
            "ciamVolumeEncrypted": "TRUE",
            "ciamTargetRole": _common(tagged_role(vm.get("tags") or {}) for vm, _ in found)},
            links={"ciamEncryptedByRole": key(_common(o.get("disk_encryption_set_id") for o in osd))}, name=name)
    return ((*(data(name, found) for name, found in named.items() if name),
             *(boot(name, found) for name, found in booted.items())),
            tuple(f"managed disk {d.get('name') or d.get('id')} ({attached[_low(d.get('id'))].get('name')}) carries "
                  "no tag Volume: which of the record's volumes it is can't be told; not recorded"
                  for d in named.get(None, ()) if attached.get(_low(d.get("id")))))

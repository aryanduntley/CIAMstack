"""Azure: backup vaults and backup plans (opsdir.domains.data.backups), rendered as Azure Backup (a Data Protection
backup vault, disk backup policies and backup instances) and read back. Pure.

  each backup vault the stack keeps: an azurerm_data_protection_backup_vault ciam-<env>-<name> (VaultStore;
  GeoRedundant and cross_region_restore_enabled when it restores in another region, LocallyRedundant otherwise;
  immutability Unlocked for a governance lock, Locked for compliance (which can't be undone), Disabled without one),
  its system-assigned identity, tagged Name and Role; its key role a customer-managed key (its identity granted Key
  Vault Crypto Service Encryption User on the key). Azure keeps a locked vault's recovery points as long as each
  policy says: a lock's days are a comment
  each backup plan the stack keeps, for the volumes it protects (its protected roles that are volumes, and the volumes
  naming it as what snapshots them): an azurerm_data_protection_backup_policy_disk named as the plan in its vault
  (disk_interval: every 1, 2, 4, 6, 8 or 12 hours or daily from ciamBackupAt; default_retention_duration its days, at
  most 360), and per disk of those volumes' VMs an azurerm_data_protection_backup_instance_disk (snapshots kept in
  the environment's resource group) after the vault identity's grants: Disk Backup Reader on the disk, Disk Snapshot
  Contributor on the resource group (once per vault). Disk backup keeps snapshots in the disk's region: a copy region
  is a comment, and so is a protected role that isn't a volume
  One someone else keeps is a comment naming them; an adopted one an import block.

Read back from (azurerm type, attributes) pairs, Terraform state as it is or the CLI and ARM normalized to it
(cli_backup.py): Data Protection backup vaults named by their tag Name (else their name), their immutability as their
lock and geo-redundant cross-region restore, their customer-managed key as their key role; disk backup policies as
backup plans named by the policy (schedule, retention, vault), protecting the roles (tag Role) of the disks their
backup instances name, the plan's role their tag SnapshotPolicy; the disks' backup instances link their volumes to
the plan (disk_policies).
"""
from collections import Counter
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class, servers_with_role
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.data.backups import VAULT, plan_vault
from opsdir.domains.data.protection import PLAN, schedule_of
from opsdir.domains.data.volumes import VOLUME, volume_policy
from opsdir.domains.network.plumbing import adopted
from opsdir.domains.network.stack import kept_by, owned
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from .cmk import CMK_ROLE, key_ref, key_sources
from .identities import LOC, RG

ANCHOR = "2024-01-01"                    # the date a repeating interval starts counting from (any past day)
DISK_HOURS = (1, 2, 4, 6, 8, 12, 24)     # the intervals disk backup takes
MAX_DAYS = 360                           # the longest disk backup keeps a snapshot
IMMUTABILITY = {"none": "Disabled", "governance": "Unlocked", "compliance": "Locked"}
_INTERVAL = re.compile(r"^R/\d{4}-\d{2}-\d{2}T(\d{2}):(\d{2}):\d{2}(?:[+-]\d{2}:\d{2}|Z)/(?:PT(\d+)H|P1D)$")


def disk_interval(every, at):
    """Azure Backup's repeating time interval for every hours from at (HH:MM UTC), or None when disk backup doesn't
    take that interval."""
    if every not in DISK_HOURS:
        return None
    return f"R/{ANCHOR}T{at or '00:00'}:00+00:00/{'P1D' if every == 24 else f'PT{every}H'}"


def interval_schedule(interval):
    """(every hours, HH:MM) of an Azure Backup repeating time interval; (None, None) for another."""
    m = _INTERVAL.match(interval or "")
    return ((int(m.group(3)) if m.group(3) else 24), f"{m.group(1)}:{m.group(2)}") if m else (None, None)


def _days(duration):
    m = re.match(r"^P(\d+)D$", duration or "")
    return int(m.group(1)) if m else None


def _name(m, b):
    return f"ciam-{rdn_value(m.env)}-{rdn_value(b)}"


def _tags(b):
    return {"Name": rdn_value(b), "Role": one(b, "ciamBindingRole"), "ManagedBy": "opsdir"}


def _vault(m, v, disks):
    """HCL for a vault the stack keeps; disks: whether its plans back up disks (its identity's grant on the resource
    group's snapshots)."""
    n, mode = tf_name(rdn_value(v)), one(v, "ciamStorageImmutability") or "none"
    geo, address = one(v, "ciamCrossRegionRestore") == "TRUE", f"azurerm_data_protection_backup_vault.{n}"
    sources, key, note = key_sources(m, v, n)
    return (*((f"# Vault '{rdn_value(v)}': a locked vault keeps each recovery point as long as its policy says; "
               f"{one(v, 'ciamStorageLockDays')} days isn't a setting of its own",)
              if mode != "none" and one(v, "ciamStorageLockDays") else ()),
            *((f"# Vault '{rdn_value(v)}': immutability Locked can't be turned off once set",)
              if mode == "compliance" else ()),
            *((f"# Vault '{rdn_value(v)}': {note[1]}",) if note else ()),
            block("resource", ["azurerm_data_protection_backup_vault", n], [
                ("name", _name(m, v)), ("resource_group_name", RG), ("location", LOC),
                ("datastore_type", "VaultStore"), ("redundancy", "GeoRedundant" if geo else "LocallyRedundant"),
                *((("cross_region_restore_enabled", True),) if geo else ()),
                ("immutability", IMMUTABILITY.get(mode, "Disabled")),
                ("identity", Block((("type", "SystemAssigned"),))), ("tags", _tags(v))]),
            *sources,
            *((block("resource", ["azurerm_role_assignment", f"{n}_cmk"], [
                ("scope", ref(f"{key}.resource_versionless_id")), ("role_definition_name", CMK_ROLE),
                ("principal_id", ref(f"{address}.identity[0].principal_id"))]),
               block("resource", ["azurerm_data_protection_backup_vault_customer_managed_key", n], [
                   ("data_protection_backup_vault_id", ref(f"{address}.id")),
                   ("key_vault_key_id", ref(f"{key}.versionless_id")),
                   ("depends_on", [ref(f"azurerm_role_assignment.{n}_cmk")])])) if key else ()),
            *((block("resource", ["azurerm_role_assignment", f"{n}_snapshots"], [
                ("scope", ref("data.azurerm_resource_group.main.id")),
                ("role_definition_name", "Disk Snapshot Contributor"),
                ("principal_id", ref(f"{address}.identity[0].principal_id"))]),) if disks else ()),
            *((import_block(f"azurerm_data_protection_backup_vault.{n}", one(v, "ciamProviderRef")),)
              if adopted(v) else ()))


def _volumes(m, p):
    """The data volumes plan p backs up in environment m: those of the roles it protects, and those naming it."""
    protects = set(values(p, "ciamProtectsRole"))
    return tuple(v for v in of_class(m, VOLUME) if one(v, "ciamVolumeKind") == "data"
                 and (one(v, "ciamBindingRole") in protects or getattr(volume_policy(m, v), "dn", None) == p.dn))


def _disks(m, p):
    """(server, volume) of every managed disk plan p backs up (its volumes on each VM of their role)."""
    return tuple((s, v) for v in _volumes(m, p) if owned(v) for s in servers_with_role(m, one(v, "ciamTargetRole")))


def _plan(m, p):
    n, s, v = tf_name(rdn_value(p)), schedule_of(p), plan_vault(m, p)
    interval = disk_interval(s.every, s.at)
    if v is None or not owned(v):
        return (f"# Backup plan '{rdn_value(p)}': its vault (role {one(p, 'ciamBackupVaultRole')}) isn't one this "
                "environment's stack keeps: not rendered",)
    if interval is None:
        return (f"# Backup plan '{rdn_value(p)}': disk backup runs every 1, 2, 4, 6, 8 or 12 hours or daily, not every "
                f"{s.every} hours: not rendered",)
    vault = f"azurerm_data_protection_backup_vault.{tf_name(rdn_value(v))}"
    volume_roles = {one(x, "ciamBindingRole") for x in _volumes(m, p)}
    others = [r for r in values(p, "ciamProtectsRole") if r not in volume_roles]
    keep = min(s.retention or MAX_DAYS, MAX_DAYS)
    policy = f"azurerm_data_protection_backup_policy_disk.{n}"
    return (*((f"# Backup plan '{rdn_value(p)}': disk backup keeps snapshots in the disk's region; copies to "
               f"{', '.join(s.copies)} aren't rendered",) if s.copies else ()),
            *((f"# Backup plan '{rdn_value(p)}': disk backup keeps a snapshot at most {MAX_DAYS} days, not "
               f"{s.retention}",) if s.retention and s.retention > MAX_DAYS else ()),
            *(f"# Backup plan '{rdn_value(p)}' protects {r}, which isn't a volume: not rendered here" for r in others),
            block("resource", ["azurerm_data_protection_backup_policy_disk", n], [
                ("name", rdn_value(p)), ("vault_id", ref(f"{vault}.id")),
                ("backup_repeating_time_intervals", [interval]), ("default_retention_duration", f"P{keep}D"),
                ("time_zone", "UTC")]),
            *(x for srv, vol in _disks(m, p)
              for dn in (tf_name(f"{rdn_value(srv)}_{rdn_value(vol)}"),)
              for x in (block("resource", ["azurerm_role_assignment", f"{n}_{dn}_reader"], [
                            ("scope", ref(f"azurerm_managed_disk.{dn}.id")),
                            ("role_definition_name", "Disk Backup Reader"),
                            ("principal_id", ref(f"{vault}.identity[0].principal_id"))]),
                        block("resource", ["azurerm_data_protection_backup_instance_disk", f"{n}_{dn}"], [
                            ("name", f"{rdn_value(srv)}-{rdn_value(vol)}"), ("location", LOC),
                            ("vault_id", ref(f"{vault}.id")), ("disk_id", ref(f"azurerm_managed_disk.{dn}.id")),
                            ("snapshot_resource_group_name", RG), ("backup_policy_id", ref(f"{policy}.id")),
                            ("depends_on", [ref(f"azurerm_role_assignment.{n}_{dn}_reader"),
                                            ref(f"azurerm_role_assignment.{tf_name(rdn_value(v))}_snapshots")])]))),
            *((import_block(policy, one(p, "ciamProviderRef")),) if adopted(p) else ()))


def render_backups(m):
    """HCL for environment m's backup vaults and plans: comments naming who keeps the others, then the vaults and plans
    the stack keeps."""
    vaults, plans = of_class(m, VAULT), of_class(m, PLAN)
    with_disks = {plan_vault(m, p).dn for p in plans if owned(p) and plan_vault(m, p) is not None and _disks(m, p)}
    return (*(f"# Backup {'vault' if b in vaults else 'plan'} '{rdn_value(b)}' (role {one(b, 'ciamBindingRole')}) is "
              f"kept by {kept_by(m, b)}: not rendered here" for b in (*vaults, *plans) if not owned(b)),
            *(x for v in vaults if owned(v) for x in _vault(m, v, v.dn in with_disks)),
            *(x for p in plans if owned(p) for x in _plan(m, p)))


# ------------------------------------------------------------------ read back
def _low(v):
    return (v or "").lower()


def _common(values_):
    found = Counter(v for v in values_ if v not in (None, ""))
    return found.most_common(1)[0][0] if found else None


def disk_policies(pairs):
    """{disk id (lower case): the id of the disk backup policy backing it up, as the policy reports it} of the backup
    instances (Azure doesn't keep the case of an id the same everywhere)."""
    ids = {_low(a.get("id")): a.get("id") for a in of_types(pairs, "azurerm_data_protection_backup_policy_disk")}
    return {_low(a.get("disk_id")): ids.get(_low(a.get("backup_policy_id")), a.get("backup_policy_id"))
            for a in of_types(pairs, "azurerm_data_protection_backup_instance_disk") if a.get("disk_id")}


def backup_resources(pairs):
    """(backup vault and plan resources, notices) of (azurerm type, attributes) pairs."""
    keys = {_low(a.get("data_protection_backup_vault_id")): key_ref(a.get("key_vault_key_id"))
            for a in of_types(pairs, "azurerm_data_protection_backup_vault_customer_managed_key")}
    disks = {_low(d.get("id")): d.get("tags") or {} for d in of_types(pairs, "azurerm_managed_disk") if d.get("id")}
    instances = [a for a in of_types(pairs, "azurerm_data_protection_backup_instance_disk") if a.get("disk_id")]
    vaults = [resource("backup-vault", a["id"], {
                  "ciamStorageImmutability": {v: k for k, v in IMMUTABILITY.items()}.get(a.get("immutability"), "none"),
                  "ciamCrossRegionRestore": "TRUE" if a.get("cross_region_restore_enabled") else "FALSE"},
                  links={"ciamEncryptedByRole": keys.get(_low(a.get("id")))},
                  name=(a.get("tags") or {}).get("Name") or a.get("name"), role=tagged_role(a.get("tags") or {}))
              for a in of_types(pairs, "azurerm_data_protection_backup_vault") if a.get("id")]
    plans, notices = [], []
    for a in of_types(pairs, "azurerm_data_protection_backup_policy_disk"):
        if not a.get("id"):
            continue
        backed = [disks.get(_low(i.get("disk_id")), {}) for i in instances if _low(i.get("backup_policy_id")) == _low(a["id"])]
        intervals = a.get("backup_repeating_time_intervals") or []
        every, at = interval_schedule(intervals[0] if intervals else None)
        notices += [*((f"backup policy {a.get('name')}: {len(intervals)} intervals; the first is read",)
                      if len(intervals) > 1 else ()),
                    *((f"backup policy {a.get('name')}: interval {intervals[0]} isn't one this adapter reads; its "
                       "frequency not read",) if intervals and every is None else ())]
        plans.append(resource("backup-plan", a["id"], {
            "ciamBackupEveryHours": every, "ciamBackupAt": at,
            "ciamRetentionDays": _days(a.get("default_retention_duration")),
            "ciamProtectsRole": sorted({tagged_role(t) for t in backed if tagged_role(t)})},
            links={"ciamBackupVaultRole": a.get("vault_id")}, name=a.get("name"),
            role=_common(t.get("SnapshotPolicy") for t in backed)))
    return (*vaults, *plans), tuple(notices)

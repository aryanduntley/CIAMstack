"""Google Cloud: each server role's disks and the snapshot schedules that copy them (opsdir.domains.data.volumes),
rendered as Terraform and read back. Pure.

  the boot disk (the role's boot volume): each instance's boot_disk, its size and type (initialize_params; a boot
  disk of the provisioned class is pd-ssd, said) labelled volume and role, encrypted with its key role's key
  (kms_key_self_link; the disk-encryption key when it names none)
  each data volume of the role, per instance: a google_compute_disk in the instance's zone (size, type, provisioned
  IOPS and throughput where the type takes them, its key as disk_encryption_key) labelled volume, role, server and
  snapshot_policy, and a google_compute_attached_disk with the volume as its device name; the instance mounts it at
  its ciamMountPath itself
  Google Cloud encrypts every disk at rest: a volume recorded unencrypted, or a key role that isn't bound, leaves
  Google's own key (said)
  each snapshot policy the stack keeps: a google_compute_resource_policy with a snapshot schedule (daily every 24
  hours, hourly every 1 to 23, from ciamSnapshotAt on the hour), snapshots kept ciamRetentionDays (and kept when the
  disk is deleted), stored in the first ciamCopyRegion (one storage location: Google Cloud stores a snapshot where
  it says, a copy elsewhere is a second schedule), the guest flushed first when application-consistent, its
  snapshots labelled policy (the record's name: the schedule's own is ciam-<env>-<name>) and role; attached to
  each disk that follows it (boot disks by their instance's name) by google_compute_disk_resource_policy_attachment.
  One someone else keeps is a comment naming them; an adopted one an import block.
Class to type: standard pd-standard, ssd pd-ssd, provisioned hyperdisk-balanced (TYPES; the reader also takes
pd-balanced as ssd, pd-extreme and the other Hyperdisks as provisioned). Hyperdisk needs a machine series that takes
it (a comment says so).

Read back from (google type, attributes) pairs, Terraform state as it is or Cloud Asset Inventory and gcloud
normalized to it (cli.py: compute#disk, ResourcePolicy): google_compute_disk grouped by label volume into one volume
of the role their instances run (the most common size, type, IOPS and throughput; its key as its key role, the
schedule its resource policies or attachments name as its snapshot policy), instances' boot_disk labelled volume as
the role's boot volume, google_compute_resource_policy with a snapshot schedule as snapshot policies (hours,
start, retention days, a storage location outside its region as its copy region, consistency), named by its
snapshots' label policy, else its own name. A disk attached to
the environment's instances without a volume label is named.
"""
from collections import Counter

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.environment import UNBOUND, of_class, secret
from opsdir.core.inventory import of_types, resource
from opsdir.domains.data.volumes import (POLICY, boot_volume, data_volumes, is_encrypted, snapshot_every,
                                         volume_key_role, volume_policy)
from opsdir.domains.network.plumbing import adopted
from opsdir.domains.network.stack import kept_by, owned
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from opsdir_format_terraform.state import blocks, first_block
from .backups import disk_plans
from .names import REGION, label, name_parts, resource_id, state_labels

TYPES = {"standard": "pd-standard", "ssd": "pd-ssd", "provisioned": "hyperdisk-balanced"}
CLASSES = {"pd-standard": "standard", "pd-balanced": "ssd", "pd-ssd": "ssd", "pd-extreme": "provisioned",
           "hyperdisk-balanced": "provisioned", "hyperdisk-extreme": "provisioned",
           "hyperdisk-throughput": "provisioned"}
IOPS = ("pd-extreme", "hyperdisk-balanced", "hyperdisk-extreme")          # the types IOPS are provisioned on
THROUGHPUT = ("hyperdisk-balanced", "hyperdisk-throughput")


def _int(v, attr):
    return int(one(v, attr)) if one(v, attr) else None


def _given(*pairs):
    return tuple((k, v) for k, v in pairs if v is not None)


def _key(m, v):
    """(the volume's key, or None, and comments)."""
    if not is_encrypted(v):
        return None, (f"# {rdn_value(v)}: recorded as not encrypted; Google Cloud encrypts every disk at rest (with "
                      "its own key when none is named)",)
    role = volume_key_role(v)
    uri = secret(m, role)
    if uri is None:
        return None, (f"# {rdn_value(v)}: {UNBOUND}{role}: no key binding for role {role}; Google's own key encrypts "
                      "it",)
    return uri.split("://", 1)[1], ()


def _labels(v, **more):
    return {"volume": label(rdn_value(v)), "role": label(one(v, "ciamBindingRole")),
            **{k: label(x) for k, x in more.items() if x}, "managed_by": "opsdir"}


def boot_disk(m, s, kms):
    """(comments, the boot_disk Block) of instance s: its image, its role's boot volume's size, type, labels and key,
    else encrypted with the disk-encryption key (kms: its reference URI, or None when unbound)."""
    image = _given(("image", one(s, "ciamImageRef")))
    v = boot_volume(m, one(s, "ciamServerRole"))
    if v is None:
        key = (("kms_key_self_link", kms.split("://", 1)[1]) if kms
               else ("#", "UNBOUND: no disk-encryption key binding in this environment"))
        return (), Block((("initialize_params", Block(image)), key))
    kind = TYPES.get(one(v, "ciamVolumeClass"), "pd-balanced")
    key, notes = _key(m, v)
    note = (f"# {rdn_value(v)}: a boot disk here is pd-ssd, not {kind}",) if kind not in ("pd-standard", "pd-ssd") \
        else ()
    return (*notes, *note), Block((
        ("initialize_params", Block((*image, *_given(("size", _int(v, "ciamVolumeSizeGb"))),
                                     ("type", kind if kind in ("pd-standard", "pd-ssd") else "pd-ssd"),
                                     ("labels", _labels(v))))),
        *((("kms_key_self_link", key),) if key else ())))


def _scheduled(m, p):
    """Whether a disk's policy is a snapshot schedule this stack renders (a backup plan backs disks up its own way:
    backups.py)."""
    return p is not None and owned(p) and is_kind(m.d, p, POLICY)


def _attach_policy(p, n, disk, zone):
    return block("resource", ["google_compute_disk_resource_policy_attachment", n], [
        ("name", ref(f"google_compute_resource_policy.{tf_name(rdn_value(p))}.name")), ("disk", disk),
        ("zone", zone)])


def server_volumes(m, s):
    """HCL for instance s's data volumes (each a disk in its zone, attached) and the snapshot schedules its disks
    follow (attachments; the boot disk by the instance's name)."""
    n, zone, out = tf_name(rdn_value(s)), one(s, "ciamZone"), []
    boot = boot_volume(m, one(s, "ciamServerRole"))
    boot_policy = volume_policy(m, boot) if boot is not None else None
    if _scheduled(m, boot_policy):
        out.append(_attach_policy(boot_policy, f"{n}_boot", ref(f"google_compute_instance.{n}.name"), zone))
    for v in data_volumes(m, one(s, "ciamServerRole")):
        if not owned(v):
            out.append(f"# Volume '{rdn_value(v)}' of {rdn_value(s)} is kept by {kept_by(m, v)}: not rendered here")
            continue
        dn, kind, policy = tf_name(f"{rdn_value(s)}_{rdn_value(v)}"), TYPES.get(one(v, "ciamVolumeClass"),
                                                                              "pd-balanced"), volume_policy(m, v)
        policy_role = one(policy, "ciamBindingRole") if policy is not None else None
        key, notes = _key(m, v)
        out += [*notes,
                *((f"# {rdn_value(v)}: {kind} needs a machine series that takes Hyperdisk",)
                  if kind.startswith("hyperdisk") else ()),
                *((f"# {rdn_value(s)} mounts {rdn_value(v)} at {one(v, 'ciamMountPath')} (its own configuration, not "
                   "Terraform)",) if one(v, "ciamMountPath") else ()),
                block("resource", ["google_compute_disk", dn], [
                    ("name", f"{rdn_value(s)}-{rdn_value(v)}"), ("zone", zone), ("type", kind),
                    *_given(("size", _int(v, "ciamVolumeSizeGb")),
                            ("provisioned_iops", _int(v, "ciamIops") if kind in IOPS else None),
                            ("provisioned_throughput", _int(v, "ciamThroughputMb") if kind in THROUGHPUT else None)),
                    *((("disk_encryption_key", Block((("kms_key_self_link", key),))),) if key else ()),
                    ("labels", _labels(v, server=rdn_value(s), snapshot_policy=policy_role))]),
                block("resource", ["google_compute_attached_disk", dn], [
                    ("disk", ref(f"google_compute_disk.{dn}.id")), ("instance", ref(f"google_compute_instance.{n}.id")),
                    ("device_name", label(rdn_value(v)))]),
                *((_attach_policy(policy, dn, ref(f"google_compute_disk.{dn}.name"), zone),)
                  if _scheduled(m, policy) else ())]
    return tuple(out)


def _schedule(p):
    """(the snapshot schedule's Block, comments) of a policy: daily every 24 hours, hourly every 1 to 23."""
    every, at = snapshot_every(p), one(p, "ciamSnapshotAt") or "00:00"
    start = f"{at[:2]}:00"
    notes = (f"# Snapshot policy '{rdn_value(p)}': Google Cloud starts schedules on the hour: {start}, not {at}",) \
        if at != start else ()
    if every == 24:
        return Block((("daily_schedule", Block((("days_in_cycle", 1), ("start_time", start)))),)), notes
    return Block((("hourly_schedule", Block((("hours_in_cycle", every), ("start_time", start)))),)), notes


def _policy(m, p):
    n, every, regions = tf_name(rdn_value(p)), snapshot_every(p), values(p, "ciamCopyRegion")
    if every > 24:
        return (f"# Snapshot policy '{rdn_value(p)}': Google Cloud schedules snapshots every 1 to 23 hours or "
                f"daily, not every {every} hours: not rendered",)
    schedule, notes = _schedule(p)
    return (*notes,
            *((f"# Snapshot policy '{rdn_value(p)}': snapshots are stored in one location, {regions[0]}; "
               f"{', '.join(regions[1:])} not rendered: a disk follows one schedule, so copies to more regions are a "
               "backup plan's (Backup and DR, its vault there)",) if len(regions) > 1 else ()),
            block("resource", ["google_compute_resource_policy", n], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(p)}"), ("region", REGION),
                ("description", f"CIAM snapshots {one(p, 'ciamBindingRole')} ({m.label})"),
                ("snapshot_schedule_policy", Block((
                    ("schedule", schedule),
                    ("retention_policy", Block((("max_retention_days", int(one(p, "ciamRetentionDays"))),
                                                ("on_source_disk_delete", "KEEP_AUTO_SNAPSHOTS")))),
                    ("snapshot_properties", Block((
                        *((("storage_locations", [regions[0]]),) if regions else ()),
                        ("guest_flush", one(p, "ciamSnapshotConsistency") == "application"),
                        ("labels", {"policy": label(rdn_value(p)), "role": label(one(p, "ciamBindingRole")),
                                    "managed_by": "opsdir"})))))))]),
            *((import_block(f"google_compute_resource_policy.{n}", resource_id(one(p, "ciamProviderRef"))),)
              if adopted(p) else ()))


def render_snapshot_policies(m):
    """HCL for environment m's snapshot policies: comments naming who keeps the others, then those the stack keeps."""
    policies = of_class(m, POLICY)
    return (*(f"# Snapshot policy '{rdn_value(p)}' (role {one(p, 'ciamBindingRole')}) is kept by {kept_by(m, p)}: "
              "not rendered here" for p in policies if not owned(p)),
            *(x for p in policies if owned(p) for x in _policy(m, p)))


# ------------------------------------------------------------------ read back
def _common(values_):
    found = Counter(v for v in values_ if v not in (None, ""))
    return found.most_common(1)[0][0] if found else None


def _type(t):
    return (t or "").rsplit("/", 1)[-1] or None


def _key_path(k):
    """A KMS key's resource name (projects/.../cryptoKeys/<key>), its version left out."""
    return resource_id(k).split("/cryptoKeyVersions/", 1)[0] if k else None


def disk_attributes(d):
    """A disk as Cloud Asset Inventory (compute#disk) or `gcloud compute disks list` prints it, as google_compute_disk's
    attributes (the instances using it, its resource policies)."""
    return {"id": resource_id(d.get("selfLink") or d.get("name")), "name": d.get("name"),
            "zone": (d.get("zone") or "").rsplit("/", 1)[-1] or None,
            "size": int(d["sizeGb"]) if d.get("sizeGb") else None, "type": _type(d.get("type")),
            "provisioned_iops": d.get("provisionedIops"), "provisioned_throughput": d.get("provisionedThroughput"),
            "disk_encryption_key": [{"kms_key_self_link": (d.get("diskEncryptionKey") or {}).get("kmsKeyName")}]
            if (d.get("diskEncryptionKey") or {}).get("kmsKeyName") else [],
            "labels": d.get("labels") or {}, "users": [resource_id(u) for u in d.get("users") or ()],
            "resource_policies": [resource_id(x) for x in d.get("resourcePolicies") or ()]}


def policy_attributes(d):
    """A resource policy as Cloud Asset Inventory (compute#resourcePolicy) or `gcloud compute resource-policies list`
    prints it, as google_compute_resource_policy's attributes (its snapshot schedule)."""
    sched = d.get("snapshotSchedulePolicy") or {}
    when, props = sched.get("schedule") or {}, sched.get("snapshotProperties") or {}
    daily, hourly = when.get("dailySchedule") or {}, when.get("hourlySchedule") or {}
    return {"id": resource_id(d.get("selfLink") or d.get("name")), "name": d.get("name"),
            "region": (d.get("region") or "").rsplit("/", 1)[-1] or None,
            "snapshot_schedule_policy": [{
                "schedule": [{"daily_schedule": [{"days_in_cycle": daily.get("daysInCycle"),
                                                  "start_time": daily.get("startTime")}] if daily else [],
                              "hourly_schedule": [{"hours_in_cycle": hourly.get("hoursInCycle"),
                                                   "start_time": hourly.get("startTime")}] if hourly else []}],
                "retention_policy": [{"max_retention_days": (sched.get("retentionPolicy") or {}).get(
                    "maxRetentionDays")}],
                "snapshot_properties": [{"storage_locations": props.get("storageLocations") or [],
                                         "guest_flush": props.get("guestFlush"), "labels": props.get("labels") or {}}]}]
            if sched else []}


def _policies(pairs):
    """(snapshot policy resources, {policy id or name: ref})."""
    out, refs = [], {}
    for a in of_types(pairs, "google_compute_resource_policy"):
        sched = first_block(a.get("snapshot_schedule_policy"))
        if not sched or not (a.get("id") or a.get("self_link")):
            continue
        ref_ = resource_id(a.get("id") or a.get("self_link"))
        when = first_block(sched.get("schedule"))
        daily, hourly = first_block(when.get("daily_schedule")), first_block(when.get("hourly_schedule"))
        props = first_block(sched.get("snapshot_properties"))
        region = name_parts(ref_).get("regions") or a.get("region")
        labels = props.get("labels") or {}
        out.append(resource("snapshot-policy", ref_, {
            "ciamRetentionDays": first_block(sched.get("retention_policy")).get("max_retention_days"),
            "ciamSnapshotEveryHours": 24 if daily else hourly.get("hours_in_cycle"),
            "ciamSnapshotAt": (daily or hourly).get("start_time"),
            "ciamCopyRegion": [x for x in props.get("storage_locations") or () if x != region],
            "ciamSnapshotConsistency": "application" if props.get("guest_flush") is True else "crash"},
            name=labels.get("policy") or a.get("name"), role=labels.get("role")))
        refs.update({ref_: ref_, a.get("name"): ref_})
    return tuple(out), refs


def _is_boot(d, instances):
    """Whether a disk is an instance's boot disk (its boot_disk source, else named as the instance)."""
    did = resource_id(d.get("id") or d.get("self_link") or "")
    return any(resource_id(first_block(i.get("boot_disk")).get("source") or "") == did or d.get("name") == i.get("name")
               for i in instances.values())


def volume_resources(pairs):
    """(volume and snapshot policy resources, notices) of (google type, attributes) pairs: disks grouped by their
    label volume (an instance's boot disk as its role's boot volume), instances' boot_disk labelled volume where no
    disk of its own is reported (Terraform state), snapshot schedules."""
    policies, refs = _policies(pairs)
    instances = {resource_id(i.get("id") or i.get("self_link")): i for i in of_types(pairs, "google_compute_instance")}
    by_name = {i.get("name"): i for i in instances.values()}
    attached = {resource_id(a.get("disk")): instances.get(resource_id(a.get("instance")), by_name.get(
                    (a.get("instance") or "").rsplit("/", 1)[-1], {}))
                for a in of_types(pairs, "google_compute_attached_disk")}
    planned = disk_plans(pairs)                     # disks a Backup and DR plan backs up (backups.py)
    followed = {resource_id(a.get("disk")).rsplit("/", 1)[-1]: refs.get(a.get("name")) or refs.get(
                    resource_id(a.get("name")))
                for a in of_types(pairs, "google_compute_disk_resource_policy_attachment")}
    disks = [d for d in of_types(pairs, "google_compute_disk") if d.get("id") or d.get("self_link")]

    def disk_id(d):
        return resource_id(d.get("id") or d.get("self_link"))

    def users(d):
        found = [instances.get(resource_id(u)) or by_name.get(u.rsplit("/", 1)[-1]) for u in d.get("users") or ()]
        return [u for u in found if u] or ([attached[disk_id(d)]] if attached.get(disk_id(d)) else []) or \
            [i for i in instances.values() if i.get("name") == d.get("name")]

    def policy_of(d):
        named = [refs.get(resource_id(x)) or refs.get(x.rsplit("/", 1)[-1]) for x in d.get("resource_policies") or ()]
        return next((x for x in (*named, followed.get(d.get("name")), planned.get(d.get("name"))) if x), None)

    def key_of(d):
        return _key_path(first_block(d.get("disk_encryption_key")).get("kms_key_self_link"))
    grouped = {}
    for d in disks:
        grouped.setdefault(((d.get("labels") or {}).get("volume"), _is_boot(d, instances)), []).append(d)

    def volume(name, boot, found):
        kinds = [_type(d.get("type")) for d in found]
        return resource("volume", name, {
            "ciamVolumeKind": "boot" if boot else "data", "ciamVolumeSizeGb": _common(d.get("size") for d in found),
            "ciamVolumeClass": _common(CLASSES.get(k) for k in kinds),
            "ciamIops": _common(d.get("provisioned_iops") for d in found if _type(d.get("type")) in IOPS),
            "ciamThroughputMb": _common(d.get("provisioned_throughput") for d in found
                                        if _type(d.get("type")) in THROUGHPUT),
            "ciamVolumeEncrypted": "TRUE",
            "ciamTargetRole": _common((u.get("labels") or {}).get("role") for d in found for u in users(d))},
            links={"ciamEncryptedByRole": _common(key_of(d) for d in found),
                   "ciamSnapshotPolicyRole": _common(policy_of(d) for d in found)},
            name=name, role=_common((d.get("labels") or {}).get("role") for d in found), tags=state_labels(found[0]))
    from_disks = {name for (name, boot), _ in grouped.items() if name and boot}
    booted = {}
    for i in instances.values():
        params = first_block(first_block(i.get("boot_disk")).get("initialize_params"))
        name = (params.get("labels") or {}).get("volume")
        if name and name not in from_disks:
            booted.setdefault(name, []).append((i, params))

    def boot(name, found):
        return resource("volume", name, {
            "ciamVolumeKind": "boot", "ciamVolumeSizeGb": _common(p.get("size") for _, p in found),
            "ciamVolumeClass": _common(CLASSES.get(_type(p.get("type"))) for _, p in found),
            "ciamVolumeEncrypted": "TRUE",
            "ciamTargetRole": _common((i.get("labels") or {}).get("role") for i, _ in found)},
            links={"ciamEncryptedByRole": _common(_key_path(first_block(i.get("boot_disk")).get("kms_key_self_link"))
                                                  for i, _ in found),
                   "ciamSnapshotPolicyRole": _common(followed.get(i.get("name")) for i, _ in found)},
            name=name, role=_common((p.get("labels") or {}).get("role") for _, p in found),
            tags=found[0][1].get("labels") or {})
    return ((*policies, *(volume(name, b, found) for (name, b), found in grouped.items() if name),
             *(boot(name, found) for name, found in booted.items())),
            tuple(f"disk {d.get('name')} ({users(d)[0].get('name')}) carries no label volume: which of the record's "
                  "volumes it is can't be told; not recorded"
                  for d in grouped.get((None, False), ()) if users(d)))

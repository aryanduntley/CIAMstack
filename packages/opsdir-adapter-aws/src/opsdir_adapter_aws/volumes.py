"""AWS: each server role's disks and the snapshot policies that copy them (opsdir.domains.data.volumes), rendered as
Terraform. Pure.

  the boot disk (the role's boot volume): its size, type, IOPS and throughput on each instance's root_block_device,
  encrypted with its key role's KMS key (the disk-encryption key when it names none), tagged Volume and Role
  each data volume of the role, per server: an aws_ebs_volume in the server's zone (size, type, IOPS, throughput,
  encryption) tagged Name, Volume, Role, Server and SnapshotPolicy, and an aws_volume_attachment at /dev/sdf, /dev/sdg
  ... in the volumes' order; the server mounts it at its ciamMountPath itself (a comment says so)
  each snapshot policy the stack keeps: an aws_dlm_lifecycle_policy snapshotting the volumes tagged with its role
  (SnapshotPolicy) every ciamSnapshotEveryHours (1, 2, 3, 4, 6, 8, 12 or 24) from ciamSnapshotAt, keeping each
  snapshot ciamRetentionDays and copying it, encrypted, to each ciamCopyRegion (at most three; the copy's key is the
  disk key's replica there when it is a multi-region key replicated to that region, else an input). Lifecycle
  Manager's role is an input. One someone else keeps is a comment naming them; an adopted one an import block.
Class to type: standard st1, ssd gp3, provisioned io2 (VOLUME_TYPES; the reader also takes gp2, io1, sc1, standard).

Read back from (Terraform type, attributes) pairs, Terraform state as it is or the CLI normalized to it (cli.py):
aws_ebs_volume (+ aws_volume_attachment) grouped by their tag Volume into one volume of the role their instances run
(the most common size, type, IOPS and throughput: a server that differs is named; encrypted only when all are), each
instance's root_block_device tagged Volume as its role's boot volume, and aws_dlm_lifecycle_policy as snapshot
policies (interval in hours, start, retention in days, copy regions; consistency crash), linked to the volumes its
target tag SnapshotPolicy names. An EBS volume attached to one of the environment's instances without a Volume tag,
an untagged root disk that isn't encrypted, a policy that keeps snapshots by count or is disabled: named, not
recorded.
"""
from collections import Counter
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, of_class, secret
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.data.volumes import (POLICY, boot_volume, data_volumes, is_encrypted, snapshot_every,
                                         volume_key_role, volume_policy)
from opsdir.domains.network.plumbing import adopted
from opsdir.domains.network.stack import kept_by, owned
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from opsdir_format_terraform.state import blocks, first_block
from .tags import state_tags as _cloud_tags

VOLUME_TYPES = {"standard": "st1", "ssd": "gp3", "provisioned": "io2"}
CLASSES = {"st1": "standard", "sc1": "standard", "standard": "standard", "gp2": "ssd", "gp3": "ssd",
           "io1": "provisioned", "io2": "provisioned"}
_DAYS = {"DAYS": 1, "WEEKS": 7, "MONTHS": 30, "YEARS": 365}
DLM_HOURS = (1, 2, 3, 4, 6, 8, 12, 24)             # the intervals Lifecycle Manager takes
DEVICES = "fghijklmnop"                            # /dev/sd<letter> for a server's data volumes, in order
DLM_ROLE = "dlm_execution_role_arn"
_DLM_TEXT = re.compile(r"[^0-9A-Za-z _-]")         # what a Lifecycle Manager description may hold


def _int(v, attr):
    return int(one(v, attr)) if one(v, attr) else None


def _given(*pairs):
    return tuple((k, v) for k, v in pairs if v is not None)


def _key(m, v):
    """(the volume's encryption arguments, a comment when its key isn't bound)."""
    if not is_encrypted(v):
        return (("encrypted", False),), ()
    role = volume_key_role(v)
    uri = secret(m, role)
    if uri is None:
        return (("encrypted", True),), (f"# {rdn_value(v)}: {UNBOUND}{role}: no key binding for role {role} in this "
                                        "environment",)
    return (("encrypted", True), ("kms_key_id", uri.split("://", 1)[1])), ()


def _disk(v):
    """The size, type, IOPS and throughput a volume records (each where it records it)."""
    return _given(("volume_size" if one(v, "ciamVolumeKind") == "boot" else "size", _int(v, "ciamVolumeSizeGb")),
                  ("volume_type" if one(v, "ciamVolumeKind") == "boot" else "type",
                   VOLUME_TYPES.get(one(v, "ciamVolumeClass"))),
                  ("iops", _int(v, "ciamIops")), ("throughput", _int(v, "ciamThroughputMb")))


def _tags(v, **more):
    return {"Volume": rdn_value(v), "Role": one(v, "ciamBindingRole"), **{k: x for k, x in more.items() if x},
            "ManagedBy": "opsdir"}


def root_block_device(m, s, kms):
    """The root_block_device of server s: its role's boot volume (size, type, IOPS, throughput, its key), else
    encrypted with the environment's disk key (kms: its reference URI, or None when unbound)."""
    v = boot_volume(m, one(s, "ciamServerRole"))
    if v is None:
        key = (("kms_key_id", kms.split("://", 1)[1]) if kms
               else ("#", "UNBOUND: no disk-encryption key binding in this environment"))
        return ("root_block_device", Block((("encrypted", True), key)))
    encryption, notes = _key(m, v)
    return ("root_block_device", Block((*_disk(v), *encryption, *(("#", n[2:]) for n in notes),
                                        ("tags", _tags(v)))))


def server_volumes(m, s):
    """HCL for server s's data volumes: each an EBS volume in its zone and its attachment."""
    n = tf_name(rdn_value(s))
    out = []
    for i, v in enumerate(data_volumes(m, one(s, "ciamServerRole"))):
        vn, policy = tf_name(f"{rdn_value(s)}_{rdn_value(v)}"), volume_policy(m, v)
        policy_role = one(policy, "ciamBindingRole") if policy is not None else None
        if not owned(v):
            out.append(f"# Volume '{rdn_value(v)}' of {rdn_value(s)} is kept by {kept_by(m, v)}: not rendered here")
            continue
        if i >= len(DEVICES):
            out.append(f"# Volume '{rdn_value(v)}' of {rdn_value(s)}: no device name left to attach it at")
            continue
        encryption, notes = _key(m, v)
        out += [*notes,
                *((f"# {rdn_value(s)} mounts {rdn_value(v)} at {one(v, 'ciamMountPath')} (its own configuration, not "
                   "Terraform)",) if one(v, "ciamMountPath") else ()),
                block("resource", ["aws_ebs_volume", vn], [
                    ("availability_zone", one(s, "ciamZone")), *_disk(v), *encryption,
                    ("tags", {"Name": f"{rdn_value(s)}-{rdn_value(v)}",
                              **_tags(v, Server=rdn_value(s), SnapshotPolicy=policy_role)})]),
                block("resource", ["aws_volume_attachment", vn], [
                    ("device_name", f"/dev/sd{DEVICES[i]}"), ("volume_id", ref(f"aws_ebs_volume.{vn}.id")),
                    ("instance_id", ref(f"aws_instance.{n}.id"))])]
    return tuple(out)


def _copy_key(m, p, region):
    """The KMS key a snapshot copy in region is encrypted with: the disk key's replica there (a multi-region key
    replicated to region), else an input."""
    uri = secret(m, "disk-encryption")
    keys = [k for k in of_class(m, "ciamKeyRef") if one(k, "ciamBindingRole") == "disk-encryption"]
    arn = uri.split("://", 1)[1] if uri else ""
    if keys and region in values(keys[0], "ciamReplicaRegion") and "/mrk-" in arn:
        parts = arn.split(":")
        return ":".join((*parts[:3], region, *parts[4:])), None
    var = f"{tf_name(rdn_value(p))}_{tf_name(region)}_kms_key_arn"
    return ref(f"var.{var}"), block("variable", [var], [
        ("type", ref("string")),
        ("description", f"The KMS key snapshots of {rdn_value(p)} are copied with in {region}")])


def _days(p):
    return Block((("interval", int(one(p, "ciamRetentionDays"))), ("interval_unit", "DAYS")))


def _policy(m, p):
    n, role, every = tf_name(rdn_value(p)), one(p, "ciamBindingRole"), snapshot_every(p)
    if every not in DLM_HOURS:
        return (f"# Snapshot policy '{rdn_value(p)}': Lifecycle Manager snapshots every 1, 2, 3, 4, 6, 8, 12 or 24 "
                f"hours, not {every}: not rendered",)
    regions = values(p, "ciamCopyRegion")
    copies = [(r, *_copy_key(m, p, r)) for r in regions[:3]]
    return (*((f"# Snapshot policy '{rdn_value(p)}': Lifecycle Manager copies to at most three regions; "
               f"{', '.join(regions[3:])} not rendered",) if len(regions) > 3 else ()),
            *(var for _, _, var in copies if var),
            block("resource", ["aws_dlm_lifecycle_policy", n], [
                ("description", _DLM_TEXT.sub(" ", f"CIAM snapshots {role} {m.label}")),
                ("execution_role_arn", ref(f"var.{DLM_ROLE}")),
                ("state", "ENABLED"),
                ("policy_details", Block((
                    ("resource_types", ["VOLUME"]), ("target_tags", {"SnapshotPolicy": role}),
                    ("schedule", Block((
                        ("name", role),
                        ("create_rule", Block((("interval", every), ("interval_unit", "HOURS"),
                                               *((("times", [one(p, "ciamSnapshotAt")]),)
                                                 if one(p, "ciamSnapshotAt") else ())))),
                        ("retain_rule", _days(p)), ("copy_tags", True),
                        *(("cross_region_copy_rule", Block((
                            ("target", region), ("encrypted", True), ("cmk_arn", key), ("copy_tags", True),
                            ("retain_rule", _days(p))))) for region, key, _ in copies))))))),
                ("tags", {"Name": rdn_value(p), "Role": role, "ManagedBy": "opsdir"})]),
            *((import_block(f"aws_dlm_lifecycle_policy.{n}", one(p, "ciamProviderRef")),) if adopted(p) else ()))


def render_snapshot_policies(m):
    """HCL for environment m's snapshot policies: comments naming who keeps the others, then those the stack keeps
    (with Lifecycle Manager's role an input)."""
    policies = of_class(m, POLICY)
    kept = [p for p in policies if owned(p)]
    return (*(f"# Snapshot policy '{rdn_value(p)}' (role {one(p, 'ciamBindingRole')}) is kept by {kept_by(m, p)}: "
              "not rendered here" for p in policies if not owned(p)),
            *((block("variable", [DLM_ROLE], [
                ("type", ref("string")),
                ("description", "The IAM role Data Lifecycle Manager snapshots with "
                                "(AWSDataLifecycleManagerDefaultRole)")]),)
              if kept else ()),
            *(x for p in kept for x in _policy(m, p)))


# ------------------------------------------------------------------ read back
def _common(values_):
    """The most common of the values given (None left out), or None."""
    found = Counter(v for v in values_ if v not in (None, ""))
    return found.most_common(1)[0][0] if found else None


def _disk_attrs(disks, kind, size, kind_of):
    """A volume's attributes from the disks that are it (one per server): what most of them have."""
    return {"ciamVolumeKind": kind, "ciamVolumeSizeGb": _common(d.get(size) for d in disks),
            "ciamVolumeClass": _common(CLASSES.get(d.get(kind_of)) for d in disks),
            "ciamIops": _common(d.get("iops") for d in disks if d.get(kind_of) in ("io1", "io2")),
            "ciamThroughputMb": _common(d.get("throughput") for d in disks if d.get(kind_of) == "gp3"),
            "ciamVolumeEncrypted": "TRUE" if all(d.get("encrypted") is True for d in disks) else "FALSE"}


def _differ(name, disks, size, owner):
    """Notices for the servers whose disk differs in size from the volume's most common."""
    usual = _common(d.get(size) for d in disks)
    return tuple(f"volume {name}: {owner(d)}'s disk is {d.get(size)} GB, the others' {usual}; recorded as {usual}"
                 for d in disks if d.get(size) not in (None, usual))


def _policies(pairs):
    """(snapshot policy resources, {SnapshotPolicy tag value: policy ref}, notices) of the Lifecycle Manager
    policies."""
    out, targets, notices = [], {}, []
    for a in of_types(pairs, "aws_dlm_lifecycle_policy"):
        ref_, details = a.get("id") or a.get("arn"), first_block(a.get("policy_details"))
        schedules = blocks(details.get("schedule"))
        name = _cloud_tags(a).get("Name") or (schedules[0].get("name") if schedules else None) or ref_
        if not ref_ or not schedules:
            continue
        if (a.get("state") or "ENABLED") != "ENABLED":
            notices.append(f"snapshot policy {name}: disabled; not read")
            continue
        create, retain = first_block(schedules[0].get("create_rule")), first_block(schedules[0].get("retain_rule"))
        days = int(retain["interval"]) * _DAYS[retain.get("interval_unit") or "DAYS"] \
            if retain.get("interval") and (retain.get("interval_unit") or "DAYS") in _DAYS else None
        notices += [*((f"snapshot policy {name}: keeps {retain.get('count')} snapshots, not a number of days; "
                       "retention not read",) if days is None and retain.get("count") else ()),
                    *((f"snapshot policy {name}: {len(schedules)} schedules; the first is read",)
                      if len(schedules) > 1 else ())]
        hours = create.get("interval") if (create.get("interval_unit") or "HOURS") == "HOURS" else None
        out.append(resource("snapshot-policy", ref_, {
            "ciamRetentionDays": days, "ciamSnapshotEveryHours": hours,
            "ciamSnapshotAt": (create.get("times") or (None,))[0],
            "ciamCopyRegion": [c.get("target") or c.get("target_region")
                               for c in blocks(schedules[0].get("cross_region_copy_rule"))],
            "ciamSnapshotConsistency": "crash"}, name=name, role=tagged_role(_cloud_tags(a)), tags=_cloud_tags(a)))
        targets.update({v: ref_ for k, v in (details.get("target_tags") or {}).items() if k == "SnapshotPolicy"})
    return tuple(out), targets, tuple(notices)


def volume_resources(pairs):
    """(volume and snapshot policy resources, notices) of (Terraform type, attributes) pairs."""
    policies, targets, notices = _policies(pairs)
    instances = {i.get("id"): i for i in of_types(pairs, "aws_instance") if i.get("id")}
    attached = {a.get("volume_id"): instances.get(a.get("instance_id"), {})
                for a in of_types(pairs, "aws_volume_attachment")}
    ebs = [v for v in of_types(pairs, "aws_ebs_volume") if v.get("id")]
    named = {}
    for v in ebs:
        named.setdefault(_cloud_tags(v).get("Volume"), []).append(v)

    def server(v):
        return _cloud_tags(attached.get(v.get("id"), {})).get("Name") or v.get("id")

    def data(name, disks):
        role = _common(_cloud_tags(attached.get(d.get("id"), {})).get("Role") for d in disks) or _common(
            _cloud_tags(d).get("ServerRole") for d in disks)
        policy = _common(_cloud_tags(d).get("SnapshotPolicy") for d in disks)
        return resource("volume", name, {**_disk_attrs(disks, "data", "size", "type"), "ciamTargetRole": role},
                        links={"ciamEncryptedByRole": _common(d.get("kms_key_id") for d in disks),
                               "ciamSnapshotPolicyRole": targets.get(policy)},
                        name=name, role=_common(_cloud_tags(d).get("Role") for d in disks), tags=_cloud_tags(disks[0]))
    roots = [(i, first_block(i.get("root_block_device"))) for i in instances.values()]
    booted = {}
    for i, r in roots:
        if (r.get("tags") or {}).get("Volume"):
            booted.setdefault(r["tags"]["Volume"], []).append((i, r))

    def boot(name, found):
        disks = [r for _, r in found]
        return resource("volume", name, {**_disk_attrs(disks, "boot", "volume_size", "volume_type"),
                                         "ciamTargetRole": _common(_cloud_tags(i).get("Role") for i, _ in found)},
                        links={"ciamEncryptedByRole": _common(r.get("kms_key_id") for r in disks)},
                        name=name, role=_common((r.get("tags") or {}).get("Role") for r in disks),
                        tags=disks[0].get("tags") or {})
    volumes = (*(data(name, disks) for name, disks in named.items() if name),
               *(boot(name, found) for name, found in booted.items()))
    return ((*policies, *volumes),
            (*notices,
             *(f"EBS volume {v.get('id')} ({server(v)}) carries no tag Volume: which of the record's volumes it is "
               "can't be told; not recorded" for v in named.get(None, ()) if attached.get(v.get("id"))),
             *(n for name, disks in named.items() if name for n in _differ(name, disks, "size", server)),
             *(f"root disk of {_cloud_tags(i).get('Name') or i.get('id')} is not encrypted" for i, r in roots
               if r and not (r.get("tags") or {}).get("Volume") and r.get("encrypted") is False)))

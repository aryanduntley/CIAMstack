"""Disks and snapshot policies: each server role's disks in each environment (its boot disk and the volumes it keeps
data on, its compute groups' included), the snapshot policies that copy them, the volumes report, and the planner
check comparing the volumes the source and the target both bind by role. A move keeps a disk no smaller, encrypted,
snapshotted as often and as long, and copied to another region where the source copies it. The helpers the cloud
adapters share: a role's volumes, a volume's key and snapshot policy. Pure."""
from ...core.changeset import set_values
from ...core.directory import is_kind, make_entry, one, rdn_value, subtree, values
from ...core.environment import bound_nowhere, environment_of, of_class, one_role, servers_with_role
from ...core.findings import (Fix, bindings_container, choice_fix, findings, merge_findings, responsible,
                              templated_entry)
from ...core.naming import branch, env_label
from ..compute.hosts import compute_groups
from .kept import carry_fix, key_choice_fix
from .protection import PLAN, compare_protection, schedule_of

VOLUME, POLICY = "ciamVolume", "ciamSnapshotPolicy"
DEFAULT_KEY = "disk-encryption"          # the key a volume naming none is encrypted with (infrastructure's role)
AREA = "Volumes"
VOLUME_HEADERS = ("environment", "volume", "server role", "kind", "mount", "size gb", "class", "iops", "throughput",
                  "encrypted by", "snapshot policy", "every hours", "at", "retention days", "copies to")


# ------------------------------------------------------------------ what the adapters share
def role_volumes(m, role):
    """Environment m's volumes of a server role: its boot disk first, then its data volumes by name."""
    found = [v for v in of_class(m, VOLUME) if one(v, "ciamTargetRole") == role]
    return tuple(sorted(found, key=lambda v: (one(v, "ciamVolumeKind") != "boot", rdn_value(v))))


def boot_volume(m, role):
    """The boot disk environment m records for a server role, or None."""
    return next((v for v in role_volumes(m, role) if one(v, "ciamVolumeKind") == "boot"), None)


def data_volumes(m, role):
    """The data volumes environment m records for a server role, by name."""
    return tuple(v for v in role_volumes(m, role) if one(v, "ciamVolumeKind") == "data")


def volume_key_role(v):
    """The binding role of the key a volume is encrypted with: its own, else the environment's disk-encryption key."""
    return one(v, "ciamEncryptedByRole") or DEFAULT_KEY


def is_encrypted(v):
    """Whether a volume is encrypted at rest (it is unless the record says it isn't)."""
    return one(v, "ciamVolumeEncrypted") != "FALSE"


def volume_policy(m, v):
    """What environment m binds for a volume's ciamSnapshotPolicyRole (a snapshot policy, or a backup plan where the
    environment snapshots disks with a backup service), or None."""
    role = one(v, "ciamSnapshotPolicyRole")
    p = one_role(m, role) if role else None
    return p if p is not None and (is_kind(m.d, p, POLICY) or is_kind(m.d, p, PLAN)) else None


def snapshot_every(p):
    """The hours between a snapshot policy's (or backup plan's) copies."""
    return schedule_of(p).every


# ------------------------------------------------------------------ report
def _policies(d, env):
    """{binding role: snapshot policy or backup plan} of an environment's own subtree (env: its DN)."""
    return {one(p, "ciamBindingRole"): p for oc in (POLICY, PLAN) for p in subtree(d, env, oc)}


def volume_rows(d, dn=None):
    """One row per volume of every environment, with the snapshot policy its environment binds for it."""
    def row(v):
        env = environment_of(v)
        p = _policies(d, env).get(one(v, "ciamSnapshotPolicyRole"))
        return (env_label(env), one(v, "ciamBindingRole"), one(v, "ciamTargetRole"), one(v, "ciamVolumeKind"),
                one(v, "ciamMountPath") or "", one(v, "ciamVolumeSizeGb") or "", one(v, "ciamVolumeClass") or "",
                one(v, "ciamIops") or "", one(v, "ciamThroughputMb") or "",
                volume_key_role(v) if is_encrypted(v) else "not encrypted", one(v, "ciamSnapshotPolicyRole") or "",
                str(schedule_of(p).every) if p is not None else "", (schedule_of(p).at or "") if p else "",
                (one(p, "ciamRetentionDays") or "") if p else "", ", ".join(values(p, "ciamCopyRegion")) if p else "")
    return sorted((row(v) for v in subtree(d, branch("environments"), VOLUME)), key=lambda r: r[:2])


# ------------------------------------------------------------------ check
def runs_role(m, role):
    """Whether environment m runs servers of a role (its own, or a compute group's)."""
    return bool(servers_with_role(m, role)) or any(one(g, "ciamTargetRole") == role for g in compute_groups(m))


def _apply(ctx):
    return (f"Apply the rendered volumes in {ctx.dst.label} (its keeper's root when someone else keeps them).",)


def _missing(ctx, role, s, owner):
    """A volume the source's servers of a role have and the target's don't."""
    target = one(s, "ciamTargetRole")
    if not runs_role(ctx.dst, target):
        return findings()
    dn = f"cn={rdn_value(s)},ou=bindings,{ctx.dst.dn}"
    where = f" mounted at {one(s, 'ciamMountPath')}" if one(s, "ciamMountPath") else ""
    return findings(actions=[(AREA, f"Volume `{role}` ({one(s, 'ciamVolumeKind')} disk of the {target} servers{where}) "
                              f"is recorded in {ctx.src.label} but not in {ctx.dst.label}: nothing says what disk the "
                              "servers there keep that on.", owner, ctx.cutover)],
                    fixes=[Fix(f"volume:{role}", AREA, f"Give the {target} servers in {ctx.dst.label} volume `{role}`, "
                               f"as {ctx.src.label} has it", (*bindings_container(ctx.d, ctx.dst.dn),
                                                              templated_entry(ctx.d, s, dn, ctx.src.dn)),
                               _apply(ctx), ())])


def _size(ctx, role, s, t, owner):
    ss, ts = one(s, "ciamVolumeSizeGb"), one(t, "ciamVolumeSizeGb")
    if not ss or not ts or int(ts) >= int(ss):
        return findings()
    return findings(blockers=[(AREA, f"Volume `{role}` is {ss} GB in {ctx.src.label} but {ts} GB in "
                               f"{ctx.dst.label}: what the source keeps on it doesn't fit.", owner)],
                    fixes=[carry_fix(f"volume:{role}:ciamVolumeSizeGb", AREA, f"Make `{role}` {ss} GB in "
                                     f"{ctx.dst.label}, as in {ctx.src.label}", s, t, ("ciamVolumeSizeGb",),
                                     _apply(ctx), ("A disk can grow in place; the file system on it is grown by "
                                                   "hand afterwards.",))])


def _encryption(ctx, role, s, t, owner):
    if is_encrypted(s) and not is_encrypted(t):
        return findings(actions=[(AREA, f"Volume `{role}` is encrypted in {ctx.src.label} but not in "
                                  f"{ctx.dst.label}: what the servers keep on it is readable to anyone who gets the "
                                  "disk or a snapshot of it.", owner, ctx.cutover)],
                        fixes=[Fix(f"volume:{role}:ciamVolumeEncrypted", AREA, f"Encrypt `{role}` in "
                                   f"{ctx.dst.label}", (set_values(t, "ciamVolumeEncrypted", ("TRUE",)),),
                                   (f"A disk is encrypted when created: in {ctx.dst.label}, snapshot it, copy the "
                                    "snapshot encrypted and replace the disk with one made from the copy.",), ())])
    key = volume_key_role(t)
    if not is_encrypted(t) or not bound_nowhere((key,), ctx.dst):
        return findings()
    fix = key_choice_fix(ctx.dst, f"volume:{role}:ciamEncryptedByRole", AREA, f"Encrypt `{role}` in "
                         f"{ctx.dst.label} with a key it binds", t, _apply(ctx))
    return findings(actions=[(AREA, f"Volume `{role}` is encrypted with key role `{key}`, which {ctx.dst.label} "
                              "doesn't bind: nothing says which key encrypts it there.", owner, ctx.cutover)],
                    fixes=[fix] if fix else [])


def _no_policy(ctx, role, s, t, sp, owner):
    """A volume the source snapshots and the target doesn't."""
    named = one(t, "ciamSnapshotPolicyRole")
    what = (f"names snapshot policy `{named}`, which {ctx.dst.label} doesn't bind" if named
            else f"has no snapshot policy in {ctx.dst.label}")
    text = (f"Volume `{role}` is snapshotted by `{one(sp, 'ciamBindingRole')}` (every {schedule_of(sp).every} hours, "
            f"kept {one(sp, 'ciamRetentionDays')} days) in {ctx.src.label} but {what}: a lost or damaged disk there "
            "can't be restored from a snapshot.")
    policies = sorted({one(p, "ciamBindingRole") for oc in (POLICY, PLAN) for p in of_class(ctx.dst, oc)})
    if policies and not named:
        fix = choice_fix(f"volume:{role}:ciamSnapshotPolicyRole", AREA, f"Snapshot `{role}` in {ctx.dst.label} "
                         "with one of its policies", t, "ciamSnapshotPolicyRole",
                         [(p, f"policy `{p}`", ()) for p in policies], _apply(ctx))
    else:
        new = named or one(sp, "ciamBindingRole")
        like = make_entry(sp.dn, sp.classes, {**sp.attrs, "ciamBindingRole": (new,)})
        added = templated_entry(ctx.d, like, f"cn={new},ou=bindings,{ctx.dst.dn}", ctx.src.dn)
        fix = Fix(f"volume:{role}:ciamSnapshotPolicyRole", AREA, f"Snapshot `{role}` in {ctx.dst.label} with a "
                  f"policy like `{one(sp, 'ciamBindingRole')}` of {ctx.src.label}",
                  (*bindings_container(ctx.d, ctx.dst.dn), added,
                   *(() if named else (set_values(t, "ciamSnapshotPolicyRole", (new,)),))), _apply(ctx), ())
    return findings(actions=[(AREA, text, owner, ctx.cutover)], fixes=[fix])


def _policy(ctx, sp, tp, owner):
    """What the target's snapshot policy (or backup plan) loses of the source's: frequency, retention, copies to
    another region."""
    return compare_protection(ctx, sp, tp, owner, AREA, _apply(ctx))


def _owner(ctx, e):
    return responsible(ctx.d, e, ctx.dst.env)


def check_volumes(ctx):
    """Each volume the source records: recorded in the target too where its servers run (an action), no smaller (a
    blocker), encrypted with a key the target binds, and snapshotted as often and as long, and copied to another
    region, as the source does (actions)."""
    src = {one(b, "ciamBindingRole"): b for b in of_class(ctx.src, VOLUME)}
    dst = {one(b, "ciamBindingRole"): b for b in of_class(ctx.dst, VOLUME)}
    pairs = [(role, s, dst[role]) for role, s in sorted(src.items()) if role in dst]
    snapshotted = [(role, s, t, volume_policy(ctx.src, s), volume_policy(ctx.dst, t)) for role, s, t in pairs]
    policies = {(sp.dn, tp.dn): (sp, tp) for *_, sp, tp in snapshotted if sp is not None and tp is not None}
    parts = merge_findings([
        *(_missing(ctx, role, s, responsible(ctx.d, ctx.dst.env)) for role, s in sorted(src.items())
          if role not in dst),
        *(f(ctx, role, s, t, _owner(ctx, t)) for role, s, t in pairs for f in (_size, _encryption)),
        *(_no_policy(ctx, role, s, t, sp, _owner(ctx, t)) for role, s, t, sp, tp in snapshotted
          if sp is not None and tp is None),
        *(_policy(ctx, sp, tp, _owner(ctx, tp)) for sp, tp in policies.values())])
    if pairs and not (parts.blockers or parts.actions):
        return parts._replace(ok=(*parts.ok, f"{len(pairs)} volume(s) keep their size, encryption and snapshots in "
                                             f"{ctx.dst.label}."))
    return parts

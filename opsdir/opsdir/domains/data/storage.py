"""Object stores: how a bucket or container keeps what it holds (versioning, immutability, encryption, lifecycle, public
access, replication), the object-stores report, and the planner check comparing each object store the source and the
target both bind by role (backup targets among them). A move keeps a store as protected as it was; a lifecycle rule
deleting backups before their retention is named in either environment. Pure."""
from typing import NamedTuple

from ...core.changeset import set_values
from ...core.directory import get, is_kind, one, rdn_value, subtree, values
from ...core.environment import environment_of, of_class
from ...core.findings import Fix, Input, findings, merge_findings, responsible
from ...core.naming import branch, env_label
from ..network.stack import owned
from .kept import carry_fix, key_dropped, lock_text, lock_weakened
from .naming import LIFECYCLE_ACTIONS

STORE = "ciamObjectStore"
DEPTH = ("ciamStorageVersioning", "ciamStorageImmutability", "ciamStorageLockDays", "ciamStorageLifecycle",
         "ciamStoragePublicBlocked", "ciamStorageReplicaRef", "ciamEncryptedByRole")
OBJECT_STORE_HEADERS = ("environment", "object store", "kind", "location", "versioning", "immutability",
                        "encrypted by", "lifecycle", "public blocked", "replica", "retention days", "kept by")
AREA = "Object stores"
# One lifecycle rule: after days, move objects (their noncurrent versions when noncurrent) to a tier, or delete them.
LifecycleRule = NamedTuple("LifecycleRule", [("noncurrent", bool), ("days", int), ("action", str)])


def parse_lifecycle(value):
    """The LifecycleRule of a ciamStorageLifecycle value ('[noncurrent ]<days> <action>'), None if it isn't one."""
    parts = value.split()
    noncurrent = parts[:1] == ["noncurrent"]
    rest = parts[1:] if noncurrent else parts
    if len(rest) != 2 or not rest[0].isdigit() or rest[1] not in LIFECYCLE_ACTIONS:
        return None
    return LifecycleRule(noncurrent, int(rest[0]), rest[1])


def lifecycle_value(rule):
    """The ciamStorageLifecycle value of a LifecycleRule."""
    return f"{'noncurrent ' if rule.noncurrent else ''}{rule.days} {rule.action}"


def lifecycle_rules(e):
    """An object store's lifecycle rules, in the order a store applies them (current objects first, by days)."""
    rules = (parse_lifecycle(v) for v in values(e, "ciamStorageLifecycle"))
    return tuple(sorted((r for r in rules if r), key=lambda r: (r.noncurrent, r.days,
                                                                 LIFECYCLE_ACTIONS.index(r.action))))


def has_depth(e):
    """Whether the record says how an object store keeps what it holds: a renderer then keeps its settings, else it
    only references the store."""
    return any(values(e, a) for a in DEPTH)


def kept_store(e):
    """Whether the stack keeps an object store itself: the record describes it and names no one else keeping it (its
    renderer then creates it, so what refers to it refers to the resource, not a data source)."""
    return has_depth(e) and owned(e)


def depth_summary(e):
    """What an object store's record asks of it, in words (versioning; compliance lock 35 days; key disk-encryption;
    lifecycle 30 cold, 400 delete; public access blocked; copied to s3://x): what to ask its keeper for."""
    lock = lock_text(e)
    parts = ("versioning" if one(e, "ciamStorageVersioning") == "TRUE" else "",
             f"{lock.split(' ', 1)[0]} lock {lock.split(' ', 1)[1]}" if " " in lock else "",
             f"key {one(e, 'ciamEncryptedByRole')}" if one(e, "ciamEncryptedByRole") else "",
             f"lifecycle {', '.join(lifecycle_value(r) for r in lifecycle_rules(e))}" if lifecycle_rules(e) else "",
             "public access blocked" if one(e, "ciamStoragePublicBlocked") == "TRUE" else "",
             f"copied to {one(e, 'ciamStorageReplicaRef')}" if one(e, "ciamStorageReplicaRef") else "")
    return "; ".join(p for p in parts if p) or "nothing beyond the store itself"


# ------------------------------------------------------------------ report
def _yes(e, attr):
    return {"TRUE": "yes", "FALSE": "no"}.get(one(e, attr) or "", "")


def object_store_rows(d, dn=None):
    """One row per object store of every environment (backup targets among them)."""
    def kept_by(e):
        dn_ = one(e, "ciamManagedBy")
        party = get(d, dn_) if dn_ else None
        return rdn_value(party) if party is not None else dn_ or ""
    return sorted(((env_label(environment_of(e)), one(e, "ciamBindingRole"),
                    "backup target" if "ciamBackupTarget" in e.classes else "object store", one(e, "ciamStorageRef"),
                    _yes(e, "ciamStorageVersioning"), lock_text(e), one(e, "ciamEncryptedByRole") or "",
                    "; ".join(lifecycle_value(r) for r in lifecycle_rules(e)), _yes(e, "ciamStoragePublicBlocked"),
                    one(e, "ciamStorageReplicaRef") or "", one(e, "ciamRetentionDays") or "", kept_by(e))
                   for e in subtree(d, branch("environments")) if is_kind(d, e, STORE)), key=lambda row: row[:2])


# ------------------------------------------------------------------ check
def _apply(ctx):
    return (f"Apply the rendered object store in {ctx.dst.label} (its keeper's root when someone else keeps it).",)


def _carry(ctx, role, s, t, attrs, title, risks=()):
    return carry_fix(f"object-store:{role}:{attrs[0]}", AREA, title, s, t, attrs, _apply(ctx), risks)


def _kept(ctx, role, s, t, owner):
    """Versioning and blocked public access the source has and the target doesn't."""
    lost = [(a, what, why) for a, what, why in (
        ("ciamStorageVersioning", "versioning", "an overwritten or deleted object can't be got back"),
        ("ciamStoragePublicBlocked", "public access blocked", "a policy or ACL could make it public"))
        if one(s, a) == "TRUE" and one(t, a) != "TRUE"]
    return findings(actions=[(AREA, f"Object store `{role}` has {what} in {ctx.src.label} but not in "
                              f"{ctx.dst.label}: {why}.", owner, ctx.cutover) for _, what, why in lost],
                    fixes=[_carry(ctx, role, s, t, (a,), f"Give `{role}` {what} in {ctx.dst.label}, as "
                                  f"{ctx.src.label} has it") for a, what, _ in lost])


def _immutable(ctx, role, s, t, owner):
    """The target's lock weaker than the source's, or as strong but shorter."""
    return lock_weakened(ctx, role, s, t, owner, AREA, "Object store", "object-store", "objects", _apply(ctx))


def _encryption(ctx, role, s, t, owner):
    return key_dropped(ctx, role, s, t, owner, AREA, "Object store", "object-store",
                       (*_apply(ctx), "Objects already stored keep their old encryption until rewritten."))


def _replication(ctx, role, s, t, owner):
    """A copy the source keeps elsewhere that the target doesn't: its own replica is the operator's to name."""
    if not one(s, "ciamStorageReplicaRef") or one(t, "ciamStorageReplicaRef"):
        return findings()
    replica = Input("ciamStorageReplicaRef", f"the object store {ctx.dst.label}'s `{role}` is copied to",
                    (), (one(s, "ciamStorageReplicaRef"),))
    return findings(actions=[(AREA, f"Object store `{role}` is copied to `{one(s, 'ciamStorageReplicaRef')}` from "
                              f"{ctx.src.label}; nothing copies {ctx.dst.label}'s: losing its region loses what it "
                              "holds.", owner, ctx.cutover)],
                    fixes=[Fix(f"object-store:{role}:ciamStorageReplicaRef", AREA, f"Copy `{role}` in "
                               f"{ctx.dst.label} to an object store of its own",
                               (set_values(t, "ciamStorageReplicaRef", (replica,)),),
                               (*_apply(ctx), "Replication needs versioning on both stores; it copies new objects "
                                              "only, so copy what is already there once."), ())])


def _early_deletes(ctx, m, owner_of):
    """Backup targets of environment m whose lifecycle deletes current objects before their retention ends."""
    out = []
    for b in of_class(m, "ciamBackupTarget"):
        keep = one(b, "ciamRetentionDays")
        early = [r for r in lifecycle_rules(b) if r.action == "delete" and not r.noncurrent and keep
                 and r.days < int(keep)]
        out += [(AREA, f"Object store `{one(b, 'ciamBindingRole')}` in {m.label} deletes backups after {r.days} days "
                 f"but must keep them {keep}: its lifecycle undoes its retention.", owner_of(b), ctx.cutover)
                for r in early[:1]]
    return out


def check_object_stores(ctx):
    """Each object store the source and the target both bind: kept as versioned, locked, encrypted, private and copied
    as it was (actions with fixes); and in either environment, backups deleted before their retention (an action)."""
    dst = {one(b, "ciamBindingRole"): b for b in of_class(ctx.dst, STORE)}
    pairs = [(role, s, dst[role]) for role, s in sorted((one(b, "ciamBindingRole"), b)
                                                        for b in of_class(ctx.src, STORE)) if role in dst
             and (has_depth(s) or has_depth(dst[role]))]
    parts = merge_findings([
        *(f(ctx, role, s, t, responsible(ctx.d, t, ctx.dst.env)) for role, s, t in pairs
          for f in (_kept, _immutable, _encryption, _replication)),
        findings(actions=[x for m in (ctx.src, ctx.dst)
                          for x in _early_deletes(ctx, m, lambda b, m=m: responsible(ctx.d, b, m.env))])])
    if pairs and not (parts.blockers or parts.actions):
        return parts._replace(ok=(*parts.ok, f"{len(pairs)} object store(s) keep their versioning, locks, encryption, "
                                             f"public access block and copies in {ctx.dst.label}."))
    return parts

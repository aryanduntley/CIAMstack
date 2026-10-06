"""What a move keeps of a data service: the fixes giving the target's binding what the source's has, and the
comparisons several kinds share (how a store locks what it keeps, whether its key is named). Shared by the managed
database, object store and backup checks. Pure."""
from ...core.changeset import set_values
from ...core.directory import one, values
from ...core.environment import of_class
from ...core.findings import Fix, choice_fix, findings
from .naming import IMMUTABILITY


def carry_fix(key, area, title, s, t, attrs, manual, risks=()):
    """The Fix giving the target's binding t the source's (s) values of attrs."""
    return Fix(key, area, title, tuple(set_values(t, a, values(s, a)) for a in attrs), tuple(manual), tuple(risks))


def key_choice_fix(m, key, area, title, t, manual):
    """The Fix encrypting the target's binding t with one of environment m's keys (a choice by key role), or None
    when m binds no key."""
    keys = sorted({one(k, "ciamBindingRole") for k in of_class(m, "ciamKeyRef")})
    return choice_fix(key, area, title, t, "ciamEncryptedByRole", [(k, f"key `{k}`", ()) for k in keys], manual)


def lock_rank(e):
    """How strongly a store (an object store, a backup vault) locks what it keeps: IMMUTABILITY's order, 0 for none."""
    mode = one(e, "ciamStorageImmutability") or "none"
    return IMMUTABILITY.index(mode) if mode in IMMUTABILITY else 0


def lock_text(e):
    """A store's lock as text: 'compliance 35 days', 'none', or ''."""
    mode, days = one(e, "ciamStorageImmutability"), one(e, "ciamStorageLockDays")
    return f"{mode} {days} days" if mode and mode != "none" and days else mode or ""


def lock_weakened(ctx, role, s, t, owner, area, label, key, things, manual):
    """The target's lock on what a store keeps (things: objects, recovery points) weaker than the source's, or as strong
    but shorter: an action whose fix locks it as the source does (manual: the steps applying it). label names the
    kind ('Object store'), key starts the fix key."""
    sr, tr = lock_rank(s), lock_rank(t)
    sd, td = int(one(s, "ciamStorageLockDays") or 0), int(one(t, "ciamStorageLockDays") or 0)
    if sr == 0 or (tr > sr) or (tr == sr and td >= sd):
        return findings()
    held = f"locks {things} ({lock_text(s)})"
    there = f"{lock_text(t)}" if tr else "doesn't lock them"
    risks = ("A compliance lock can't be shortened or removed once set, not even by the account's root: check the "
             "days before applying.",) if one(s, "ciamStorageImmutability") == "compliance" else ()
    return findings(actions=[(area, f"{label} `{role}` {held} in {ctx.src.label}; {ctx.dst.label} {there}: "
                              "ransomware or a mistake could delete or change what it holds.", owner, ctx.cutover)],
                    fixes=[carry_fix(f"{key}:{role}:ciamStorageImmutability", area, f"Lock `{role}`'s {things} in "
                                     f"{ctx.dst.label} as {ctx.src.label} does ({lock_text(s)})", s, t,
                                     ("ciamStorageImmutability", "ciamStorageLockDays"), manual, risks)])


def key_dropped(ctx, role, s, t, owner, area, label, key, manual):
    """A key the source's binding names and the target's doesn't (the provider's own key encrypts it there): an action
    whose fix chooses one of the target's keys."""
    if not one(s, "ciamEncryptedByRole") or one(t, "ciamEncryptedByRole"):
        return findings()
    fix = key_choice_fix(ctx.dst, f"{key}:{role}:ciamEncryptedByRole", area, f"Encrypt `{role}` in "
                         f"{ctx.dst.label} with a key of its own", t, manual)
    return findings(actions=[(area, f"{label} `{role}` is encrypted with key `{one(s, 'ciamEncryptedByRole')}` "
                              f"in {ctx.src.label}; in {ctx.dst.label} nothing names its key, so the provider's own "
                              "default key encrypts it, which nobody here controls or can revoke.", owner,
                              ctx.cutover)], fixes=[fix] if fix else [])

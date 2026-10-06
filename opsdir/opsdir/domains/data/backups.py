"""Backup vaults and plans: what a backup service backs up in each environment (the roles a plan protects: volumes,
databases, the servers of a role), where it keeps the recovery points (a vault: its lock, key and whether it restores
in another region), how often and how long; the backups report, and the planner check comparing the source's with
the target's by role. A move keeps every role the source backs up backed up in the target, as often and as long and
copied to another region (protection.compare_protection), into a vault locked, keyed and restorable as well. Pure."""
from ...core.changeset import add_values
from ...core.directory import is_kind, one, rdn_value, subtree, values
from ...core.environment import environment_of, of_class, one_role
from ...core.findings import Fix, bindings_container, findings, merge_findings, responsible, templated_entry
from ...core.naming import branch, env_label
from .kept import carry_fix, key_dropped, lock_text, lock_weakened
from .protection import PLAN, compare_protection, schedule_of
from .volumes import VOLUME, runs_role, volume_policy

VAULT = "ciamBackupVault"
AREA = "Backups"
BACKUP_HEADERS = ("environment", "plan", "protects", "vault", "every hours", "at", "window hours", "retention days",
                  "copies to", "vault lock", "vault key", "restores in another region", "restore test every")


def protected_roles(m):
    """{role: (what protects it, ...)} of environment m: the roles its backup plans protect, and its volumes'
    roles where it binds what their ciamSnapshotPolicyRole names (a snapshot policy or a backup plan)."""
    found = {}
    for p in of_class(m, PLAN):
        for role in values(p, "ciamProtectsRole"):
            found.setdefault(role, {})[p.dn] = p
    for v in of_class(m, VOLUME):
        p = volume_policy(m, v)
        if p is not None:
            found.setdefault(one(v, "ciamBindingRole"), {})[p.dn] = p
    return {role: tuple(by_dn.values()) for role, by_dn in sorted(found.items())}


def plan_vault(m, p):
    """The backup vault environment m binds for a plan's ciamBackupVaultRole, or None."""
    role = one(p, "ciamBackupVaultRole")
    v = one_role(m, role) if role else None
    return v if v is not None and is_kind(m.d, v, VAULT) else None


# ------------------------------------------------------------------ report
def backup_rows(d, dn=None):
    """One row per backup plan of every environment: what it protects, its vault, schedule, retention and copies."""
    def row(p):
        env = environment_of(p)
        vaults = {one(v, "ciamBindingRole"): v for v in subtree(d, env, VAULT)}
        v, s = vaults.get(one(p, "ciamBackupVaultRole")), schedule_of(p)
        return (env_label(env), one(p, "ciamBindingRole"), ", ".join(values(p, "ciamProtectsRole")),
                one(p, "ciamBackupVaultRole"), str(s.every), s.at or "", one(p, "ciamBackupWindowHours") or "",
                str(s.retention or ""), ", ".join(s.copies), lock_text(v) if v is not None else "not bound",
                (one(v, "ciamEncryptedByRole") or "the provider's") if v is not None else "",
                (one(v, "ciamCrossRegionRestore") or "") if v is not None else "", one(p, "ciamRestoreTestDays") or "")
    return sorted((row(p) for p in subtree(d, branch("environments"), PLAN)), key=lambda r: r[:2])


# ------------------------------------------------------------------ check
def _apply(ctx):
    return (f"Apply the rendered backups in {ctx.dst.label} (its keeper's root when someone else keeps them).",)


def holds_role(m, role):
    """Whether environment m binds a role or runs servers of it (its own, or a compute group's): what a backup plan
    may protect there."""
    return one_role(m, role) is not None or runs_role(m, role)


def _unprotected(ctx, role, sp):
    """A role a source backup plan protects that nothing protects in the target: the fix adds it to the target's plan
    of the same role, or copies the source's plan."""
    plan_role, s = one(sp, "ciamBindingRole"), schedule_of(sp)
    tp = one_role(ctx.dst, plan_role)
    if tp is not None and is_kind(ctx.d, tp, PLAN):
        fix = Fix(f"backup:{role}", AREA, f"Back up `{role}` with `{plan_role}` in {ctx.dst.label}",
                  (add_values(tp, "ciamProtectsRole", (role,)),), _apply(ctx), ())
    else:
        fix = Fix(f"backup:{role}", AREA, f"Back up `{role}` in {ctx.dst.label} with a plan like `{plan_role}` of "
                  f"{ctx.src.label}", (*bindings_container(ctx.d, ctx.dst.dn),
                                       templated_entry(ctx.d, sp, f"cn={rdn_value(sp)},ou=bindings,{ctx.dst.dn}",
                                                       ctx.src.dn)),
                  (*_apply(ctx), f"Bind the plan's vault role in {ctx.dst.label} too: a backup vault there."), ())
    return findings(actions=[(AREA, f"Role `{role}` is backed up by `{plan_role}` (every {s.every} hours, kept "
                              f"{s.retention} days) in {ctx.src.label}, but nothing backs it up in {ctx.dst.label}: "
                              "what it holds can't be restored there.", responsible(ctx.d, ctx.dst.env),
                              ctx.cutover)], fixes=[fix])


def _vault(ctx, role, s, t, owner):
    """What the target's vault loses of the source's: its lock, its key, restores in another region."""
    restorable = one(s, "ciamCrossRegionRestore") == "TRUE" and one(t, "ciamCrossRegionRestore") != "TRUE"
    return merge_findings([
        lock_weakened(ctx, role, s, t, owner, AREA, "Backup vault", "backup-vault", "recovery points", _apply(ctx)),
        key_dropped(ctx, role, s, t, owner, AREA, "Backup vault", "backup-vault",
                    (*_apply(ctx), "Recovery points already in it keep their old key; a vault's key can't be "
                                   "changed once it holds any, so this may mean a new vault.")),
        findings(actions=[(AREA, f"Backup vault `{role}` restores in another region in {ctx.src.label} but not in "
                                 f"{ctx.dst.label}: losing its region loses the recovery points too.", owner,
                           ctx.cutover)],
                 fixes=[carry_fix(f"backup-vault:{role}:ciamCrossRegionRestore", AREA, f"Make `{role}` restorable "
                                  f"in another region in {ctx.dst.label}", s, t, ("ciamCrossRegionRestore",),
                                  _apply(ctx))]) if restorable else findings()])


def _pairs(ctx, oc):
    dst = {one(b, "ciamBindingRole"): b for b in of_class(ctx.dst, oc)}
    return [(role, s, dst[role]) for role, s in sorted((one(b, "ciamBindingRole"), b) for b in of_class(ctx.src, oc))
            if role in dst]


def check_backups(ctx):
    """Each role a source backup plan protects: backed up in the target too where the target binds it or runs its
    servers (an action with a fix); each plan both bind as often, as long and copied to another region; each vault
    both bind locked, keyed and restorable in another region as well (actions with fixes)."""
    src = protected_roles(ctx.src)
    dst = protected_roles(ctx.dst)
    plans, vaults = _pairs(ctx, PLAN), _pairs(ctx, VAULT)
    parts = merge_findings([
        *(_unprotected(ctx, role, plan) for role, by in src.items() for plan in by[:1]
          if is_kind(ctx.d, plan, PLAN) and role not in dst and holds_role(ctx.dst, role)),
        *(compare_protection(ctx, s, t, responsible(ctx.d, t, ctx.dst.env), AREA, _apply(ctx)) for _, s, t in plans),
        *(_vault(ctx, role, s, t, responsible(ctx.d, t, ctx.dst.env)) for role, s, t in vaults)])
    if (plans or vaults) and not (parts.blockers or parts.actions):
        return parts._replace(ok=(*parts.ok, f"{len(plans)} backup plan(s) and {len(vaults)} vault(s) back up as "
                                             f"often and as long, locked and keyed, in {ctx.dst.label}."))
    return parts

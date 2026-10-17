"""The planner's managed directory check: the target's cloud-managed directory services (ciamManagedDirectory
bindings, domains/directory/managed.py) against what the adapters rendering it declare of them
(Adapter.managed_directory). A connector: the descriptors come from the adapters. Pure.

A target binding (it holds the platform's user directory) must exist in the environment's partition and do what the
record needs of it: take the record's own schema, apply its password policies, serve secure LDAP, replicate to its
further regions and keep its trusts, within the service's limits and on an edition that has them. A neighbour (the
partner side of ldap integrations) must exist there, serve LDAP and keep its trusts. Documented unsupported is a
blocker with no confirmation path; what no vendor documentation establishes blocks until the operator records the
vendor's confirmation (connectors.managed_service). A capability supported on a condition, the record's base DNs
moving under the OU the platform writes in (with the consumers whose binds change), ACIs, consumers that connect only
with TLS where secure LDAP is off, what a target in its partition must know, and how users and passwords move are
actions.
"""
from ..core.directory import get, one, rdn_value, values
from ..core.findings import findings, merge_findings, responsible
from ..domains.directory.managed import (acis, is_target, managed_directories, moved_bases, neighbour_needs,
                                         password_policies, realizes_directory, slug, target_needs,
                                         tls_only_consumers, trusts, words)
from ..domains.directory.naming import DIRECTORY_SERVER_ROLE
from . import managed_service

AREA = "Managed directory"
VOICE = managed_service.Voice(AREA, words, "the directory's record, or where the user directory is held",
                              "Hold the user directory elsewhere (keep it on its current product, or choose a service "
                              "the partition has)")
COUNTED = {"password-policies": ("password-policies", lambda d, b: len(password_policies(d)), "password policies"),
           "multi-region": ("regions", lambda d, b: 1 + len(values(b, "ciamReplicaRegion")), "regions")}


def _listed(names):
    return ", ".join(f"`{n}`" for n in names) or "none"


def _edition(ctx, m, b, spec, need):
    """The finding for a capability only some editions have: a blocker when the binding records another edition, an
    action when it records none."""
    kind = need.capability.split(":", 1)[0]
    editions, source = spec.editions.get(need.capability) or spec.editions.get(kind) or ((), None)
    edition, label = one(b, "ciamDirectoryEdition"), rdn_value(b)
    if not editions or edition in editions:
        return findings()
    what = f"{need.cause}, so `{label}` in {m.label} must {words(need.capability)}, which {spec.title} does only " \
           f"on the {' or '.join(editions)} edition ({source})"
    if edition is None:
        return findings(actions=[(AREA, f"{what}: record the edition it runs (ciamDirectoryEdition).",
                                  responsible(ctx.d, b, m.env), None)])
    return findings(blockers=[(AREA, f"{what}, and it records {edition}: record the edition it needs, or drop what "
                               "needs it from the record.", responsible(ctx.d, b, m.env))])


def _limit(ctx, m, b, spec, key, count, what):
    """The blocker for a binding needing more of something than the service takes (spec.limits), else nothing."""
    most, source = spec.limits.get(key, (None, None))
    if most is None or count <= most:
        return findings()
    return findings(blockers=[(AREA, f"`{rdn_value(b)}` in {m.label} needs {count} {what}, and {spec.title} takes "
                               f"at most {most} ({source}): reduce them in the record, or hold the user directory "
                               "elsewhere.", responsible(ctx.d, b, m.env))])


TARGET_CHANGE = "Change the record (what needs it), or hold the user directory where it can be kept."
NEIGHBOUR_CHANGE = ("Correct the record (the trust or the integration, as its keeper has it), or keep the platform's "
                    "use of the directory to what it can do.")


def _need(ctx, m, b, spec, partition, need, change):
    """The findings for one need: the capability's gap (change: what to do instead), the edition it takes and the
    service's limit on it."""
    label = rdn_value(b)
    gap = managed_service.gap(ctx, VOICE, m, b, spec, partition, need.capability, slug(need.capability),
                              f"{need.cause}, so `{label}` ({spec.title}) in {m.label} must", need.concerns,
                              (b, m.env), change)
    counted = COUNTED.get(need.capability)
    limit = _limit(ctx, m, b, spec, counted[0], counted[1](ctx.d, b), counted[2]) if counted else findings()
    return merge_findings([gap, _edition(ctx, m, b, spec, need), limit])


def _bases(ctx, m, b, spec):
    """Actions for the record's base DNs moving under the OU the platform writes in, with the consumers whose binds
    or searches name them; an action to record that OU when neither the binding nor the service names it."""
    label, base = rdn_value(b), one(b, "ciamWritableBase") or spec.default_base(b)
    owner = responsible(ctx.d, b, m.env)
    if base is None:
        return findings(actions=[(AREA, f"`{label}` ({spec.title}) in {m.label} records no OU the platform writes in: "
                                  "record it (ciamWritableBase), the OU created for the user directory's entries.",
                                  owner, None)])
    return findings(actions=[(AREA, f"The user directory's entries under `{old}` land under `{base}` on `{label}` "
                              f"({spec.title}) in {m.label}: {spec.title} keeps the customer's entries in that OU. "
                              f"Consumers whose binds or searches name `{old}` change them: "
                              f"{_listed(rdn_value(c) for c in consumers)}.", owner, None)
                             for old, consumers in moved_bases(ctx.d, base)])


def _carried(ctx, m, b, spec):
    """Actions for what doesn't carry onto a managed directory as the record holds it: ACIs, and TLS-only consumers
    where secure LDAP is off."""
    label, owner, granted = rdn_value(b), responsible(ctx.d, b, m.env), acis(ctx.d)
    tls_only = tls_only_consumers(ctx.d) if one(b, "ciamLdapsMode") not in ("private", "internet") else ()
    aci = (AREA, f"The record's ACIs ({_listed(rdn_value(a) for a in granted)}) don't carry onto `{label}` "
                 f"({spec.title}) in {m.label}: Active Directory grants by delegated permissions on the OU. Re-create "
                 "each one's access as a delegation, and record where.", owner, None)
    tls = (AREA, f"{_listed(rdn_value(c) for c in tls_only)} connect only with TLS, and `{label}` in {m.label} "
                 "records no secure LDAP: turn it on (ciamLdapsMode) with the certificate it presents "
                 "(ciamTlsCertificate), or confirm those consumers can do without.", owner, None)
    return findings(actions=[*((aci,) if granted else ()), *((tls,) if tls_only else ())])


def _target(ctx, m, b, spec):
    """Findings for a binding holding the platform's user directory on a managed directory service."""
    label, partition = rdn_value(b), spec.partition(m)
    if not realizes_directory(b):
        return findings(blockers=[(AREA, f"`{label}` in {m.label} realizes `{one(b, 'ciamRealizes')}`: a managed "
                                   f"directory holds the user directory (ciamRealizes {DIRECTORY_SERVER_ROLE}). "
                                   "Correct ciamRealizes.", responsible(ctx.d, b, m.env))])
    owner = responsible(ctx.d, b, m.env)
    notes = [findings(actions=[(AREA, f"{spec.title} in {m.label} ({partition}): {text} {how}", owner, None)])
             for _, text, how in (*spec.notes.get("*", ()), *spec.notes.get(partition, ()))]
    users = findings(actions=[(AREA, f"User accounts and passwords don't move with the directory's configuration onto "
                               f"`{label}` ({spec.title}) in {m.label}: {spec.users}", owner, None)])
    held = (one(b, "ciamFqdn") or "no domain recorded", one(b, "ciamDirectoryEdition"),
            ", ".join(x for x in (one(b, "ciamRegion"), *values(b, "ciamReplicaRegion")) if x))
    ok = findings(ok=[f"`{label}` holds the user directory on {spec.title} in {m.label}: "
                      f"{', '.join(x for x in held if x)}; trusts: "
                      f"{_listed(one(t, 'ciamFqdn') for t in trusts(ctx.d, b))}."])
    return merge_findings([managed_service.available(ctx, VOICE, m, b, spec, partition),
                           *(_need(ctx, m, b, spec, partition, n, TARGET_CHANGE) for n in target_needs(ctx.d, b)),
                           _limit(ctx, m, b, spec, "trusts", len(trusts(ctx.d, b)), "trusts"),
                           _bases(ctx, m, b, spec), _carried(ctx, m, b, spec), *notes, users, ok])


def _neighbour(ctx, m, b, spec):
    """Findings for a neighbour: it exists in its partition, serves LDAP to its partner integrations and keeps its
    trusts."""
    label, partition = rdn_value(b), spec.partition(m)
    keeper = get(ctx.d, one(b, "ciamManagedBy")) if one(b, "ciamManagedBy") else None
    kept_by = f", kept by {rdn_value(keeper)}" if keeper is not None else ""
    ok = findings(ok=[f"`{label}` ({spec.title}{kept_by}) in {m.label} is a neighbour directory: partner of "
                      f"{_listed(rdn_value(i) for i in (get(ctx.d, x) for x in values(b, 'ciamPartnerOf')) if i)}; "
                      f"trusts: {_listed(one(t, 'ciamFqdn') for t in trusts(ctx.d, b))}."])
    return merge_findings([managed_service.available(ctx, VOICE, m, b, spec, partition),
                           *(_need(ctx, m, b, spec, partition, n, NEIGHBOUR_CHANGE)
                             for n in neighbour_needs(ctx.d, b)),
                           _limit(ctx, m, b, spec, "trusts", len(trusts(ctx.d, b)), "trusts"), ok])


def managed_directory_check(dst_adapters):
    """The planner check of the target's managed directory services, given the adapters rendering it."""
    specs = {s.name: s for a in dst_adapters for s in a.managed_directory}

    def check_managed_directory(ctx):
        m = ctx.dst
        return merge_findings([
            managed_service.undeclared(ctx, AREA, m, b) if one(b, "ciamManagedService") not in specs else
            (_target if is_target(b) else _neighbour)(ctx, m, b, specs[one(b, "ciamManagedService")])
            for b in managed_directories(m)])
    return check_managed_directory

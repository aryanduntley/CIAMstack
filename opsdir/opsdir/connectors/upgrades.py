"""Product upgrades across a move (decision 2375): a migration carries each product's version unless the target records
another, and may upgrade within the range the product's adapter supports.

Per server role both environments run, and per adapter lineage (an adapter's products, compared by version number:
ForgeRock AM 7.5 -> PingAM 8.1), the jump is from the oldest version the source runs to the newest the target runs. A
target version outside the adapter's range blocks (the adapter can't render or read it); a source one is an action
(what was read from it may be incomplete). A downgrade is an action, with the changes the target loses named. An
upgrade names every change the adapter declares between the two versions (contract.VersionChange) that touches what
the record holds, at the change's effect; the changes touching nothing are counted. Same versions are a re-host (the
infrastructure domain's version check says so). A connector: the changes come from the installed adapters, which the
planner gives it. Pure.
"""
from ..core.directory import one
from ..core.findings import findings, merge_findings, responsible
from ..core.versions import crossed, in_range, parsed, product_version

from ..domains.compute.workloads import kubernetes_roles, recorded_versions

AREA = "Upgrade"


def _roles(m):
    """The server roles environment m runs, on servers or on Kubernetes, in the record's order."""
    return tuple(dict.fromkeys((*(one(s, "ciamServerRole") for s in m.servers), *kubernetes_roles(m))))


def _number(value):
    return parsed(product_version(value)[1])


def lineage(a, values):
    """The ciamProductVersion values among these that are of adapter a's products and compare, oldest first."""
    names = {p for p, _ in a.products}
    return tuple(sorted((v for v in dict.fromkeys(values) if product_version(v)[0] in names and _number(v)),
                        key=_number))


def jumps(src, dst, adapters):
    """((adapter, roles, source version, target version), ...): for each adapter lineage, the server roles both
    environments run that move from the same oldest source version to the same newest target version, grouped, in
    the target's role order."""
    shared = tuple(r for r in _roles(dst) if r in _roles(src))
    found = tuple((a, r, s[0], t[-1]) for r in shared for a in adapters
                  for s, t in ((lineage(a, recorded_versions(src, r)), lineage(a, recorded_versions(dst, r))),)
                  if s and t)
    keys = tuple(dict.fromkeys((a.name, s, t) for a, _, s, t in found))
    return tuple((next(a for a, _, s, t in found if (a.name, s, t) == k),
                  tuple(r for a, r, s, t in found if (a.name, s, t) == k), k[1], k[2]) for k in keys)


def supported(a, value):
    """Whether adapter a declares a ciamProductVersion value's product and its version is inside the declared range."""
    product, version = product_version(value)
    return any(p == product and in_range(version, r) for p, r in a.products)


def _ranges(a):
    return ", ".join(f"{p} {r}" for p, r in a.products)


def crossing(d, m, a, roles, older, newer):
    """((change, names), ...) of adapter a's changes between two version numbers (the older lacks them, the newer has
    them) that touch what the record holds for these server roles of environment m (names: what they touch; None:
    whatever runs the roles), and how many changes lie between the versions in all."""
    between = tuple(c for c in a.version_changes if crossed(c.has, older, newer))
    hits = tuple((c, None if c.touches is None else
                  tuple(dict.fromkeys(n for r in roles for n in c.touches(d, m, r)))) for c in between)
    return tuple((c, names) for c, names in hits if names is None or names), len(between)


def _who(roles, m):
    return f"{', '.join(f'`{r}`' for r in roles)} in {m.label}"


def _change(ctx, c, names, who, owner):
    held = f"; the record holds {', '.join(f'`{n}`' for n in names)}" if names else ""
    text = f"{who}: {c.change}. Affects {c.affects}{held}. {c.fix}"
    return findings(blockers=[(AREA, text, owner)] if c.effect == "blocker" else [],
                    actions=[(AREA, text, owner, ctx.cutover)] if c.effect == "action" else [],
                    ok=[text] if c.effect not in ("blocker", "action") else [])


def _upgrade(ctx, a, roles, s, t, owner):
    who = _who(roles, ctx.dst)
    listed, between = crossing(ctx.d, ctx.dst, a, roles, product_version(s)[1], product_version(t)[1])
    if not a.version_changes:
        return findings(actions=[(AREA, f"{who}: {s} → {t}, an upgrade {a.name} declares no version changes for: "
                                  "test it separately from the move.", owner, ctx.cutover)])
    said = (f"{between} changes {a.name} declares lie between them; {len(listed)} apply to this record (named "
            "below)" if between else f"{a.name} declares no changes between them")
    return merge_findings([findings(ok=[f"{who}: {s} → {t}, an upgrade within the versions {a.name} supports "
                                        f"({_ranges(a)}); {said}."]),
                           *(_change(ctx, c, names, who, owner) for c, names in listed)])


def _downgrade(ctx, a, roles, s, t, owner):
    who = _who(roles, ctx.dst)
    lost, _ = crossing(ctx.d, ctx.dst, a, roles, product_version(t)[1], product_version(s)[1])
    return findings(actions=[(AREA, f"{who}: {s} → {t} is a downgrade. What a newer release wrote may not load in an "
                              "older one: build the target from the record and test it before the cutover, or record "
                              f"a version at or above {s}.", owner, ctx.cutover)],
                    ok=[f"{who} loses, at {t}: {c.change}. Affects {c.affects}." for c, _ in lost])


def _jump(ctx, a, roles, s, t, owner):
    out_of_range = findings(
        blockers=[(AREA, f"{_who(roles, ctx.dst)} would run {t}, outside the versions {a.name} supports "
                   f"({_ranges(a)}): it can't render or read it. Record a version in its range, or install an "
                   "adapter that supports it.", owner)] if not supported(a, t) else [],
        actions=[(AREA, f"{_who(roles, ctx.src)} runs {s}, outside the versions {a.name} supports ({_ranges(a)}): "
                  "what was read from it may be incomplete. Check the record against the source before the move.",
                  owner, ctx.cutover)] if not supported(a, s) else [])
    st, tt = _number(s), _number(t)
    moved = (_upgrade(ctx, a, roles, s, t, owner) if tt > st else
             _downgrade(ctx, a, roles, s, t, owner) if tt < st else findings())
    return merge_findings([out_of_range, moved])


def upgrade_check(src_adapters, dst_adapters):
    """The planner check for the product versions a move changes, given both environments' installed adapters."""
    adapters = tuple({a.name: a for a in (*src_adapters, *dst_adapters) if a.products}.values())

    def check_upgrades(ctx):
        owner = responsible(ctx.d, ctx.dst.env)
        return merge_findings([_jump(ctx, a, roles, s, t, owner) for a, roles, s, t in jumps(ctx.src, ctx.dst,
                                                                                               adapters)])
    return check_upgrades

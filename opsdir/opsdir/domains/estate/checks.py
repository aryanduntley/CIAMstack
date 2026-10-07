"""The estate's planner checks: a required tag an environment of a move can give no value (its owner, cost center or
classification isn't recorded), so what is rendered for it would go without that tag; a region the provider doesn't
list (or no longer lists, or opens only to accounts that opt in), or a catalog that can't tell; a region outside the
residency an environment's data is held to, or a target held to none; FIPS endpoints the source uses and the target
doesn't. Pure."""
from ...core.directory import one, rdn_value
from ...core.findings import findings, responsible
from .regions import holds_regions
from .residency import fips_endpoints, region_entry, residency_breach, residency_of
from .tags import missing_tags

AREA = "Tags"
REGIONS = "Regions"
RESIDENCY = "Residency"
FIPS = "FIPS"


def check_tags(ctx):
    """Each required tag source or target can give no value: an action for the environment's owner."""
    return findings(actions=[(AREA, f"Tag `{one(rule, 'ciamTagKey')}` (tag rule {rdn_value(rule)}) has no value in "
                                    f"{m.label}: {why}. Resources rendered for it go without the tag.",
                              responsible(ctx.d, m.env), ctx.cutover if m is ctx.dst else None)
                             for m in (ctx.src, ctx.dst) for rule, why in missing_tags(m)])


def _region_problem(m):
    """(what is wrong with environment m's region as the catalog sees it, whether it blocks a target), or None."""
    region = one(m.cloud, "ciamRegion")
    if not holds_regions(m.d, m.provider):
        return (f"The region catalog holds no {m.provider} regions, so {m.label}'s region {region} can't be checked "
                "against the provider's list: fetch the list (`opsdir prerequisites`).", False)
    e = region_entry(m)
    status = one(e, "ciamRegionStatus") if e is not None else None
    if e is None or status == "not-listed":
        listed = "doesn't list" if e is None else "no longer lists"
        return (f"{m.label} runs in {m.provider} region {region}, which the provider {listed} (region catalog): "
                "check the region.", True)
    if status == "opt-in":
        return (f"{m.label} runs in {m.provider} region {region}, open only to accounts that opt in: make sure its "
                "account has.", False)
    return None


def check_regions(ctx):
    """Each environment's region against the catalog: a target's region the provider doesn't or no longer lists is a
    blocker, the rest actions (a source's region, an opt-in region, a catalog without the provider's regions)."""
    models = (ctx.src,) if ctx.src.dn == ctx.dst.dn else (ctx.src, ctx.dst)
    found = [(m, text, m is ctx.dst and blocks) for m in models for p in (_region_problem(m),) if p
             for text, blocks in (p,)]
    return findings(blockers=[(REGIONS, text, responsible(ctx.d, m.env)) for m, text, blocks in found if blocks],
                    actions=[(REGIONS, text, responsible(ctx.d, m.env), ctx.cutover if m is ctx.dst else None)
                             for m, text, blocks in found if not blocks])


def check_residency(ctx):
    """A target outside the residency its data is held to is a blocker; a source outside its own, or a target held
    to none while the source is, an action."""
    held, target = residency_of(ctx.src), residency_of(ctx.dst)
    src_breach, dst_breach = residency_breach(ctx.src), residency_breach(ctx.dst)
    unheld = held is not None and target is None and dst_breach is None
    return findings(
        blockers=[(RESIDENCY, f"{dst_breach}: the move would hold data where its residency doesn't allow.",
                   responsible(ctx.d, ctx.dst.env))] if dst_breach else [],
        actions=[*([(RESIDENCY, f"{src_breach}.", responsible(ctx.d, ctx.src.env), None)] if src_breach else []),
                 *([(RESIDENCY, f"{ctx.dst.label} is held to no residency while {ctx.src.label}'s data is held to "
                                f"{rdn_value(held)}: record the target's (ciamResidencyRef) so the move is checked "
                                "against it.", responsible(ctx.d, ctx.dst.env), ctx.cutover)] if unheld else [])])


def check_fips(ctx):
    """A source whose clients use FIPS 140 validated endpoints and a target whose don't: a blocker."""
    return findings(blockers=[(FIPS, f"{ctx.src.label}'s cloud uses FIPS 140 validated endpoints and "
                                     f"{ctx.dst.label}'s doesn't (ciamFipsEndpoints): the move would drop them.",
                               responsible(ctx.d, ctx.dst.env))]
                    if fips_endpoints(ctx.src) and not fips_endpoints(ctx.dst) else [])

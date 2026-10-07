"""The estate's planner checks: a required tag an environment of a move can give no value (its owner, cost center or
classification isn't recorded), so what is rendered for it would go without that tag. Pure."""
from ...core.directory import one, rdn_value
from ...core.findings import findings, responsible
from .tags import missing_tags

AREA = "Tags"


def check_tags(ctx):
    """Each required tag source or target can give no value: an action for the environment's owner."""
    return findings(actions=[(AREA, f"Tag `{one(rule, 'ciamTagKey')}` (tag rule {rdn_value(rule)}) has no value in "
                                    f"{m.label}: {why}. Resources rendered for it go without the tag.",
                              responsible(ctx.d, m.env), ctx.cutover if m is ctx.dst else None)
                             for m in (ctx.src, ctx.dst) for rule, why in missing_tags(m)])

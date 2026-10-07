"""The tags report: for every environment, each tag of the estate's tag policy and the value it takes there (or why
it has none). Pure."""
from ...core.directory import one, subtree
from ...core.environment import env_model
from ...core.naming import branch
from .tags import tag_rules, tag_value

TAG_HEADERS = ("environment", "tag", "source", "value")


def tag_rows(d, dn=None):
    """One row per environment and tag rule."""
    rules = tag_rules(d)
    models = [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")] if rules else []
    return [(m.label, one(r, "ciamTagKey"), one(r, "ciamTagSource"), v or f"none: {why}")
            for m in models for r in rules for v, why in (tag_value(m, r),)]

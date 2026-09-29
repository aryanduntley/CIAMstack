"""Infrastructure reports, pure functions of a snapshot: the overrides every environment renders with."""
from ...core.directory import get, one, subtree, values
from ...core.environment import env_model
from ...core.overlays import overridden_in
from .naming import ENVIRONMENTS

OVERRIDES_HEADERS = ("environment", "entry", "attribute", "shared", "value", "from", "why")


def _shared(d, o):
    e = get(d, one(o, "ciamOverrides"))
    attr = d.lower_types.get(one(o, "ciamOverrideAttribute").lower(), one(o, "ciamOverrideAttribute"))
    return ", ".join(values(e, attr)) if e else ""


def override_rows(d, dn=None):
    """Every environment's overrides (its own and those it inherits as an overlay): the entry and attribute, the
    shared value, the environment's value, which environment's override it is, and why."""
    return [(m.label, one(o, "ciamOverrides"), one(o, "ciamOverrideAttribute"), _shared(d, o),
             ", ".join(values(o, "ciamOverrideValue")), overridden_in(o), one(o, "description") or "")
            for m in (env_model(d, e.dn) for e in subtree(d, ENVIRONMENTS, "ciamEnvironment")) for o in m.overrides]

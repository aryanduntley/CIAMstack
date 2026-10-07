"""The estate's reports. tags: for every environment, each tag of the estate's tag policy and the value it takes there
(or why it has none). regions: the region catalog, each region with the environments that run in it and the
residencies that allow it. residency: for every environment, the residency its data is held to, its region and whether
the residency allows it. Pure."""
from ...core.directory import children, one, rdn_value, referrers, subtree
from ...core.environment import env_model
from ...core.naming import branch
from .naming import REGIONS
from .regions import catalog_regions
from .residency import residency_breach, residency_of
from .tags import tag_rules, tag_value

TAG_HEADERS = ("environment", "tag", "source", "value")
REGION_HEADERS = ("provider", "region", "name", "geography", "status", "partition", "environments", "residencies")
RESIDENCY_HEADERS = ("environment", "residency", "provider", "region", "verdict")


def _models(d):
    return [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")]


def tag_rows(d, dn=None):
    """One row per environment and tag rule."""
    rules = tag_rules(d)
    models = _models(d) if rules else []
    return [(m.label, one(r, "ciamTagKey"), one(r, "ciamTagSource"), v or f"none: {why}")
            for m in models for r in rules for v, why in (tag_value(m, r),)]


def region_rows(d, dn=None):
    """One row per region of the catalog, by provider and code: the environments whose cloud runs in it and the
    residencies that allow it."""
    models = _models(d)
    return [(provider, rdn_value(r), one(r, "ciamRegionName", ""), one(r, "ciamGeography", ""),
             one(r, "ciamRegionStatus", ""), one(r, "ciamCloudEnvironment", ""),
             ", ".join(m.label for m in models if m.provider == provider and one(m.cloud, "ciamRegion") == rdn_value(r)),
             ", ".join(sorted(rdn_value(e) for _, e in referrers(d, r, "ciamAllowedRegion"))))
            for provider in (one(c, "ciamCloudProvider") for c in children(d, REGIONS, "ciamRegionCatalog"))
            for r in catalog_regions(d, provider)]


def residency_rows(d, dn=None):
    """One row per environment: its residency (or none), its provider and region, and whether the residency allows
    the region (ok, or why not)."""
    return [(m.label, rdn_value(held) if held is not None else one(m.env, "ciamResidencyRef", "none"), m.provider,
             one(m.cloud, "ciamRegion"), breach or ("ok" if held is not None else "not held to a residency"))
            for m in _models(d) for held, breach in ((residency_of(m), residency_breach(m)),)]

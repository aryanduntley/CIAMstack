"""Estate domain vocabulary: how sensitive an environment's data is, where a tag's value comes from, a cloud region's
status, and where the tag policy, the region catalog and the residencies live."""

from ...core.naming import branch

CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")   # least sensitive first
# where a tag rule takes its value in each environment: the environment's owner, that owner's cost center, the
# environment's data classification, the environment (cloud/env), its cloud, or the rule's own value
TAG_SOURCES = ("owner", "cost-center", "classification", "environment", "cloud", "literal")
TAG_POLICY = branch("tag-policy")       # the tag rules (ciamTagRule), one per tag every rendered resource carries
# a region as its provider lists it: available, open only to accounts that opt in, or no longer listed (kept: what names
# it keeps its link, and the planner says so)
REGION_STATUSES = ("available", "opt-in", "not-listed")
REGIONS = branch("regions")             # the region catalog: one ciamRegionCatalog per provider, its ciamCloudRegions
RESIDENCIES = branch("residencies")     # the estate's residencies (ciamResidency): the regions each allows

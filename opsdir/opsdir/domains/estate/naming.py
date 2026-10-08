"""Estate domain vocabulary: how sensitive an environment's data is, where a tag's value comes from, a cloud region's
status, where the tag policy, the region catalog and the residencies live, and what a cloud security service is and
watches."""

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
# what a cloud security service does: detect threats; scan for vulnerabilities; record resources' configuration and its
# changes; assess the estate's posture against compliance frameworks and the cloud's own baseline
SECURITY_KINDS = ("threat-detection", "vulnerability-scanning", "config-recording", "posture")
# what a threat-detection (or vulnerability-scanning) service watches: management API activity, sign-ins and
# credentials, traffic and name lookups, machines, containers and clusters, object storage, databases, key vaults,
# applications and APIs
SECURITY_AREAS = ("control-plane", "identity", "network", "compute", "containers", "storage", "databases",
                  "key-vaults", "applications")
STANDARD_ID = r"[a-z0-9]+(-[a-z0-9]+)*"     # a compliance framework's or baseline's id: nist-800-171-r2, cis
# the regulatory frameworks a posture service assesses that a move can't silently drop (a target without posture
# assessment while the source assesses one of these is a blocker)
REGULATORY = frozenset(("nist-800-53-r5", "nist-800-171-r2", "fedramp-low", "fedramp-moderate", "fedramp-high",
                        "cmmc-l1", "cmmc-l2", "cmmc-l3", "dod-il2", "dod-il4", "dod-il5"))
RESTRICTED = "restricted"                   # the data classification under which a narrower target blocks the move

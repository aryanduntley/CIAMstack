"""Estate domain vocabulary: how sensitive an environment's data is, where a tag's value comes from, and where the tag
policy lives."""

from ...core.naming import branch

CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")   # least sensitive first
# where a tag rule takes its value in each environment: the environment's owner, that owner's cost center, the
# environment's data classification, the environment (cloud/env), its cloud, or the rule's own value
TAG_SOURCES = ("owner", "cost-center", "classification", "environment", "cloud", "literal")
TAG_POLICY = branch("tag-policy")       # the tag rules (ciamTagRule), one per tag every rendered resource carries

"""Custom domain vocabulary: its branch and the prefix every custom name carries."""
from ...core.naming import branch

CUSTOM_SCHEMA = branch("custom-schema")   # definitions of the fields and record types operators add
PREFIX = "x"                              # custom names start with it (xKeyVaultRetentionDays): the core (ciam*) and
                                          # packages never use it, so their later definitions can't collide

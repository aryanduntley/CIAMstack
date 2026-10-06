"""Data domain vocabulary: the database engines a managed database runs and how available it is kept; how an object
store keeps what it holds (immutability, lifecycle)."""

ENGINES = ("postgresql", "mysql", "mariadb", "sqlserver", "oracle")
HIGH_AVAILABILITY = ("none", "zone-redundant")          # least available first
EDITIONS = ("enterprise", "standard", "standard2", "web", "express")   # SQL Server's and Oracle's
IMMUTABILITY = ("none", "governance", "compliance")    # weakest first: governance can be lifted by a privileged user
LIFECYCLE_ACTIONS = ("cool", "cold", "archive", "delete")   # cheaper and slower tiers first; delete last
# '[noncurrent ]<days> <action>': after <days> days, move objects (or their noncurrent versions) to a tier or delete
LIFECYCLE = rf"(noncurrent )?[1-9][0-9]{{0,4}} ({'|'.join(LIFECYCLE_ACTIONS)})"

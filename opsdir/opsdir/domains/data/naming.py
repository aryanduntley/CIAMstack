"""Data domain vocabulary: the database engines a managed database runs and how available it is kept; how an object
store keeps what it holds (immutability, lifecycle); the disks servers keep their data on and how they are
snapshotted."""

ENGINES = ("postgresql", "mysql", "mariadb", "sqlserver", "oracle")
DEFAULT_PORTS = {"postgresql": 5432, "mysql": 3306, "mariadb": 3306, "sqlserver": 1433, "oracle": 1521}
HIGH_AVAILABILITY = ("none", "zone-redundant")          # least available first
EDITIONS = ("enterprise", "standard", "standard2", "web", "express")   # SQL Server's and Oracle's
IMMUTABILITY = ("none", "governance", "compliance")    # weakest first: governance can be lifted by a privileged user
LIFECYCLE_ACTIONS = ("cool", "cold", "archive", "delete")   # cheaper and slower tiers first; delete last
# '[noncurrent ]<days> <action>': after <days> days, move objects (or their noncurrent versions) to a tier or delete
LIFECYCLE = rf"(noncurrent )?[1-9][0-9]{{0,4}} ({'|'.join(LIFECYCLE_ACTIONS)})"
VOLUME_KINDS = ("boot", "data")               # the disk a server starts from, or one it keeps data on
# what a disk is, slowest first: magnetic (each cloud's "standard"), general-purpose SSD, SSD with provisioned IOPS
VOLUME_CLASSES = ("standard", "ssd", "provisioned")
# what a snapshot holds of a running server: the disk as a power cut would leave it, or what the application flushed
CONSISTENCY = ("crash", "application")
SNAPSHOT_AT = r"([01][0-9]|2[0-3]):[0-5][0-9]"    # a daily start time, UTC (03:00)

"""Data domain vocabulary: the database engines a managed database runs and how available it is kept."""

ENGINES = ("postgresql", "mysql", "mariadb", "sqlserver", "oracle")
HIGH_AVAILABILITY = ("none", "zone-redundant")          # least available first
EDITIONS = ("enterprise", "standard", "standard2", "web", "express")   # SQL Server's and Oracle's

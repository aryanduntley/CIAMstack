"""Directory domain vocabulary: its branches and the server role that serves the user directory."""
from ...core.naming import branch

CONFIG = branch("config")
DECLARED = branch("declared", CONFIG)      # desired, environment-neutral server configuration
OBSERVED = branch("observed", CONFIG)      # snapshots captured from live servers
USER_SCHEMA = branch("user-schema")
CONSUMERS = branch("consumers")
ACIS = branch("acis")
DATA_PROFILE = branch("data-profile")   # the shape of each environment's user data, values-free

DIRECTORY_SERVER_ROLE = "ds"               # ciamServerRole of servers that serve the user directory

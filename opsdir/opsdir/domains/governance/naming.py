"""Governance domain vocabulary: its branches."""
from ...core.naming import branch

OWNERS = branch("owners")
CHANGES = branch("changes")
RUNBOOKS = branch("runbooks")
IMPORTS = branch("imports")           # the last import run of each scope by each importer
UNKNOWNS = branch("unknowns")         # the unknowns register: open and answered questions (ciamUnknown)

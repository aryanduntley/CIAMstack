"""Governance domain vocabulary: its branches."""
from ...core.naming import branch

OWNERS = branch("owners")
CHANGES = branch("changes")
RUNBOOKS = branch("runbooks")
IMPORTS = branch("imports")           # the last import run of each scope by each importer
UNKNOWNS = branch("unknowns")         # the unknowns register: open and answered questions (ciamUnknown)
APPLICATIONS = branch("applications")      # applications grouping the entries they are made of
TICKETS = branch("tickets")            # ITSM tickets the change records name, as last read (ciamTicket)
SOURCE_OBJECTS = branch("source-objects")   # what a source product holds that has no standard equivalent

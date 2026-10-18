"""Governance domain vocabulary: its branches."""
from ...core.naming import branch

OWNERS = branch("owners")
CHANGES = branch("changes")
RUNBOOKS = branch("runbooks")
IMPORTS = branch("imports")           # import runs: each importer's last read of each scope set it read, per
                                     # environment (or shared); and collection attempts
UNKNOWNS = branch("unknowns")         # the unknowns register: open and answered questions (ciamUnknown)
APPLICATIONS = branch("applications")      # applications grouping the entries they are made of
TICKETS = branch("tickets")            # ITSM tickets the change records name, as last read (ciamTicket)
SOURCE_OBJECTS = branch("source-objects")   # what a source product holds that has no standard equivalent
PEOPLE = branch("people")             # the people who work on the record, named by their database logins
GRANTS = branch("grants")             # permissions: actions given to people or teams over areas

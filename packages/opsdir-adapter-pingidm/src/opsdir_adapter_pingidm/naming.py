"""Where an IDM deployment's entries live: ou=pingidm, a branch per kind."""
from opsdir.core.naming import branch

PINGIDM = branch("pingidm")
MANAGED = branch("managed-objects", PINGIDM)
CONNECTORS = branch("connectors", PINGIDM)
MAPPINGS = branch("mappings", PINGIDM)
SCHEDULES = branch("schedules", PINGIDM)
SERVER_ROLES = ("idm",)            # ciamServerRole / ciamTargetRole values this adapter defines


def named(base, name):
    return f"cn={name},{base}"

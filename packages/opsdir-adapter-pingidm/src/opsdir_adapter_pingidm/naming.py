"""Where an IDM deployment's entries live: ou=pingidm, a branch per kind."""
from opsdir.core.contract import Endpoint
from opsdir.core.naming import branch

PINGIDM = branch("pingidm")
MANAGED = branch("managed-objects", PINGIDM)
CONNECTORS = branch("connectors", PINGIDM)
MAPPINGS = branch("mappings", PINGIDM)
SCHEDULES = branch("schedules", PINGIDM)
SERVER_ROLES = ("idm",)            # ciamServerRole / ciamTargetRole values this adapter defines
# What the edge treats specially (contract.Endpoint): self-service reset and registration, the ping endpoint
ENDPOINTS = tuple(Endpoint(kind, path, "idm") for kind, path in (
    ("password-reset", "/openidm/selfservice/reset"), ("registration", "/openidm/selfservice/registration"),
    ("health", "/openidm/info/ping")))


def named(base, name):
    return f"cn={name},{base}"

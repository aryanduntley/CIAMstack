"""Where an IDM deployment's entries live: ou=pingidm, a branch per kind."""
from opsdir.core.contract import Endpoint
from opsdir.core.naming import branch

PINGIDM = branch("pingidm")
MANAGED = branch("managed-objects", PINGIDM)
CONNECTORS = branch("connectors", PINGIDM)
MAPPINGS = branch("mappings", PINGIDM)
SCHEDULES = branch("schedules", PINGIDM)
SERVER_ROLES = ("idm",)            # ciamServerRole / ciamTargetRole values this adapter defines
# What the edge treats specially (contract.Endpoint), by version: standalone self-service reset and registration
# (removed in PingIDM 8.0: AM journeys do it), the ping endpoint (deprecated in 8.1 for /openidm/health/ready; PingIDM
# 8.1 release notes, REST API reference: info endpoints)
ENDPOINTS = tuple(Endpoint(kind, path, "idm", versions) for kind, path, versions in (
    ("password-reset", "/openidm/selfservice/reset", "<8"),
    ("registration", "/openidm/selfservice/registration", "<8"),
    ("health", "/openidm/info/ping", "<8.1"), ("health", "/openidm/health/ready", ">=8.1")))


def named(base, name):
    return f"cn={name},{base}"

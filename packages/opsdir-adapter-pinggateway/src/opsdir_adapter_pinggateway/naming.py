"""Where the gateway's routes live: ou=routes,ou=pinggateway."""
from opsdir.core.contract import Endpoint
from opsdir.core.naming import branch

PINGGATEWAY = branch("pinggateway")
ROUTES = branch("routes", PINGGATEWAY)
SERVER_ROLES = ("ig",)             # ciamServerRole / ciamTargetRole values this adapter defines
ADMIN_PORT = 8085                  # the admin connector's default port from PingGateway 2025.3
# What the edge treats specially (contract.Endpoint), by version: the health endpoint on the client port before 2025.3
# (/openig/ping); from 2025.3 the admin endpoints are on the admin port without the deprecated /openig prefix (/ping),
# and /health/startup replaces ping from 2025.6 (PingGateway release notes: incompatible changes 2025.3, what's new
# 2025.6)
ENDPOINTS = (Endpoint("health", "/openig/ping", "ig", "<2025.3"),
             Endpoint("health", "/ping", "ig", ">=2025.3,<2025.6", ADMIN_PORT),
             Endpoint("health", "/health/startup", "ig", ">=2025.6", ADMIN_PORT))


def route_dn(name):
    return f"cn={name},{ROUTES}"

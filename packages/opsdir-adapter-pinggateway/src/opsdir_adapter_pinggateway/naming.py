"""Where the gateway's routes live: ou=routes,ou=pinggateway."""
from opsdir.core.naming import branch

PINGGATEWAY = branch("pinggateway")
ROUTES = branch("routes", PINGGATEWAY)
SERVER_ROLES = ("ig",)             # ciamServerRole / ciamTargetRole values this adapter defines


def route_dn(name):
    return f"cn={name},{ROUTES}"

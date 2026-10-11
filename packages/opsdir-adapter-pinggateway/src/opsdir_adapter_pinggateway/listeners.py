"""PingGateway's listeners for the ports matrix: its HTTPS listener for clients (8443, the estate's convention: the
product's default connector is 8080; the record holds no port for it), from 2025.3 its admin connector (8085: the
admin endpoints, where a load balancer probes its health) for the versions the role's servers record (none: the
newest), and the ports its routes reach on the applications behind service names. Pure."""
from opsdir.core.contract import Listener
from opsdir.core.directory import children, one, rdn_value
from opsdir.core.versions import holds
from opsdir.domains.compute.workloads import recorded_versions
from opsdir.domains.network.ports import via_service
from .naming import ADMIN_PORT, ROUTES

HTTPS = Listener("ig", 8443, "tcp", "HTTPS", ("clients",))
ADMIN = Listener("ig", ADMIN_PORT, "tcp", "admin endpoints and health checks", ("admin",))


def route_listeners(m):
    """The ports environment m's gateways reach through the routes that name a backend's service name role."""
    return tuple(lst for r in children(m.d, ROUTES, "pinggwRoute") if one(r, "pinggwBackendRole")
                 for lst in via_service(m, one(r, "pinggwBackendRole"), f"PingGateway route {rdn_value(r)}", ("ig",)))


def listeners(m):
    """PingGateway's listeners in environment m: its HTTPS listener, its admin connector (2025.3+), then what its
    routes reach."""
    return (HTTPS, *((ADMIN,) if holds(">=2025.3", recorded_versions(m, "ig")) else ()), *route_listeners(m))

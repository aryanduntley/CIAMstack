"""PingGateway's listeners for the ports matrix: its HTTPS listener for clients (8443 unless the estate moved it; the
record holds no port for it), and the ports its routes reach on the applications behind service names. Pure."""
from opsdir.core.contract import Listener
from opsdir.core.directory import children, one, rdn_value
from opsdir.domains.network.ports import via_service
from .naming import ROUTES

HTTPS = Listener("ig", 8443, "tcp", "HTTPS", ("clients",))


def route_listeners(m):
    """The ports environment m's gateways reach through the routes that name a backend's service name role."""
    return tuple(lst for r in children(m.d, ROUTES, "pinggwRoute") if one(r, "pinggwBackendRole")
                 for lst in via_service(m, one(r, "pinggwBackendRole"), f"PingGateway route {rdn_value(r)}", ("ig",)))


def listeners(m):
    """PingGateway's listeners in environment m: its HTTPS listener, then what its routes reach."""
    return (HTTPS, *route_listeners(m))

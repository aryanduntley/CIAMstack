"""PingIDM's listeners for the ports matrix: its REST and administration interface (HTTPS on 8443 unless the estate
moved it; the record holds no port for it), and the ports its connectors reach through service names (the connector's
own port, else the service's). Pure."""
from opsdir.core.contract import Listener
from opsdir.core.directory import children, one, rdn_value
from opsdir.core.jsondata import held_json
from opsdir.domains.network.ports import via_service
from .naming import CONNECTORS

REST = Listener("idm", 8443, "tcp", "REST and administration", ("admin",))


def connector_port(c):
    """The port a connector's configuration names, or None."""
    return (held_json(c, "pingidmConfig").get("configurationProperties") or {}).get("port")


def connector_listeners(m):
    """The ports environment m's IDM servers reach through the connectors that name a service name's role."""
    return tuple(lst for c in children(m.d, CONNECTORS, "pingidmConnector") if one(c, "pingidmTargetRole")
                 for lst in via_service(m, one(c, "pingidmTargetRole"), f"PingIDM connector {rdn_value(c)}", ("idm",),
                                        connector_port(c)))


def listeners(m):
    """PingIDM's listeners in environment m: its REST interface, then what its connectors reach."""
    return (REST, *connector_listeners(m))

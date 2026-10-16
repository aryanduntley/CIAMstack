"""PingAccess's listeners for the ports matrix, from the product's documented defaults (the record holds no listener
ports: engine listeners are environment-bound objects): the engines' runtime port for clients (3000), the admin node's
console and API (9000) and its cluster configuration port the engines and a replica admin pull from (9090), from 9.1
the temporary cluster certificate rotation port (9095) for the versions the role's servers record (none: the newest),
the agent (3030) and sideband (3020) ports only where the record holds agents or sideband clients, and the ports the
sites reach on the applications behind service names (the record's sites, and the backends of the protected
applications the environment has PingAccess take over). Pure."""
from opsdir.core.contract import Listener
from opsdir.core.directory import children, one, rdn_value
from opsdir.core.versions import holds
from opsdir.domains.compute.workloads import recorded_versions
from opsdir.domains.network.ports import via_service
from .api import ADMIN_PORT, AGENT_PORT, CLUSTER_PORT, ENGINE_PORT, SIDEBAND_PORT
from .naming import ADMIN, ENGINE, KINDS, held_base
from .takeover import taken_over

ROTATION_PORT, ROTATION_SINCE = 9095, ">=9.1"
ENGINE_HTTPS = Listener(ENGINE, ENGINE_PORT, "tcp", "HTTPS (applications' clients)", ("clients",))
ADMIN_API = Listener(ADMIN, ADMIN_PORT, "tcp", "admin console and API", ("admin",))
CLUSTER = Listener(ADMIN, CLUSTER_PORT, "tcp", "cluster configuration", (ENGINE, "peers"))
ROTATION = Listener(ADMIN, ROTATION_PORT, "tcp", "cluster certificate rotation", (ENGINE, "peers"))
AGENTS = Listener(ENGINE, AGENT_PORT, "tcp", "agents (PAAP)", ("clients",))
SIDEBAND = Listener(ENGINE, SIDEBAND_PORT, "tcp", "sideband clients", ("clients",))


def site_listeners(m):
    """The ports environment m's engines reach through the sites that name a backend's service name role."""
    return (*(lst for s in children(m.d, KINDS["site"][0], "paSite") if one(s, "paBackendRole")
              for lst in via_service(m, one(s, "paBackendRole"), f"PingAccess site {rdn_value(s)}", (ENGINE,))),
            *(lst for a in taken_over(m) if one(a, "ciamBackendRole")
              for lst in via_service(m, one(a, "ciamBackendRole"), f"PingAccess site {rdn_value(a)}-backend",
                                     (ENGINE,))))


def listeners(m):
    """PingAccess's listeners in environment m."""
    d = m.d
    return (ENGINE_HTTPS, ADMIN_API, CLUSTER,
            *((ROTATION,) if holds(ROTATION_SINCE, recorded_versions(m, ADMIN)) else ()),
            *((AGENTS,) if children(d, held_base("agents"), "paHeld") else ()),
            *((SIDEBAND,) if children(d, held_base("sidebandClients"), "paHeld") else ()),
            *site_listeners(m))

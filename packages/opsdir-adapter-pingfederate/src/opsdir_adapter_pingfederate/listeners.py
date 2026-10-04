"""PingFederate's listeners for the ports matrix: what each node's run.properties says it listens on (the runtime for
clients, the administrative console for the operators, the cluster ports for the other nodes), PingFederate's defaults
where the record holds none, and the ports its engines reach through the data stores' service names. Pure."""
from types import MappingProxyType

from opsdir.core.contract import Listener
from opsdir.core.directory import children, one, rdn_value, values
from opsdir.domains.network.ports import via_service
from .discovery import CLUSTER_PORT
from .naming import DATA_STORES, SERVER_ROLES

# run.properties listener names (nodes.LISTENERS) and who connects to each; the cluster ports are the other nodes'
WHO = MappingProxyType({"runtime": ("clients",), "runtime-http": ("clients",), "runtime-secondary": ("clients",),
                        "admin": ("admin",)})
CLUSTER = ("cluster", "cluster-failure-detection")
# what a node listens on when the record holds nothing of its run.properties (PingFederate's defaults), and the cluster
# ports a clustered node listens on unless its run.properties moves them
DEFAULTS = MappingProxyType({"pf-engine": ("runtime=9031",), "pf-admin": ("admin=9999",)})
CLUSTER_DEFAULTS = (f"cluster={CLUSTER_PORT}", "cluster-failure-detection=7700")


def _nodes(m, role):
    return tuple(s for s in m.servers if one(s, "ciamServerRole") == role)


def _recorded(nodes, role):
    """The '<name>=<port>' listeners a role's nodes record (the defaults when they record none), with the default
    cluster ports they don't record when they run clustered."""
    found = tuple(dict.fromkeys(v for s in nodes for v in values(s, "pingfedListener"))) or DEFAULTS[role]
    names = {v.split("=", 1)[0] for v in found}
    clustered = "cluster" in names or any(one(s, "pingfedOperationalMode", "").startswith("CLUSTERED") for s in nodes)
    return (*found, *(v for v in CLUSTER_DEFAULTS if clustered and v.split("=", 1)[0] not in names))


def node_listeners(m):
    """What environment m's PingFederate nodes listen on, per server role."""
    roles = tuple(r for r in SERVER_ROLES if _nodes(m, r))

    def listener(role, text):
        name, _, port = text.partition("=")
        peers = ("peers", *(r for r in roles if r != role)) if name in CLUSTER else WHO.get(name, ("admin",))
        return Listener(role, int(port), "tcp", name, peers)
    return tuple(listener(role, text) for role in roles for text in _recorded(_nodes(m, role), role))


def store_listeners(m):
    """The ports environment m's engines reach through the data stores that name a service name's role."""
    return tuple(lst for store in children(m.d, DATA_STORES, "pingfedDataStore") if one(store, "pingfedTargetRole")
                 for lst in via_service(m, one(store, "pingfedTargetRole"),
                                        f"PingFederate data store {rdn_value(store)}", ("pf-engine",),
                                        one(store, "pingfedPort")))


def listeners(m):
    """PingFederate's listeners in environment m: its nodes', then what its data stores reach."""
    return (*node_listeners(m), *store_listeners(m))

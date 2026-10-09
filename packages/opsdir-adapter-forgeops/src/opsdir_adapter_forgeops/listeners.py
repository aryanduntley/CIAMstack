"""ForgeOps' listeners: what the release's pods listen on (its container ports, release.POD_PORTS) for each server
role an environment runs with ForgeOps. Declared on="kubernetes", so the kubernetes adapter's network policies admit
these ports to the role's pods instead of the product's own (PingAM's 8443 on its servers), and the firewall checks
leave them out. Pure."""
from opsdir.core.contract import Listener
from opsdir.core.directory import one
from .components import placements
from .release import POD_PORTS


def listeners(m):
    """The container ports of the server roles environment m runs with ForgeOps."""
    roles = dict.fromkeys(one(w, "ciamTargetRole") for p in placements(m) for _, w in p.placed)
    return tuple(Listener(role, port, "tcp", purpose, peers, "kubernetes")
                 for role, port, purpose, peers in POD_PORTS if role in roles)

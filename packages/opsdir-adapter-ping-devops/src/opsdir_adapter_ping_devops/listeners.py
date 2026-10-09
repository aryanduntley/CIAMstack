"""The ping-devops chart's listeners: what its PingFederate pods listen on (release.POD_PORTS) for each server role an
environment runs with the chart. Declared on="kubernetes", so the kubernetes adapter's network policies admit these
ports to the role's pods and the firewall checks leave them out. Pure."""
from opsdir.core.contract import Listener
from opsdir.core.directory import one
from .products import placements
from .release import POD_PORTS


def listeners(m):
    """The container ports of the PingFederate roles environment m runs with the ping-devops chart."""
    roles = dict.fromkeys(one(w, "ciamTargetRole") for p in placements(m) for _, w in p.placed)
    return tuple(Listener(role, port, "tcp", purpose, peers, "kubernetes")
                 for role, port, purpose, peers in POD_PORTS if role in roles)

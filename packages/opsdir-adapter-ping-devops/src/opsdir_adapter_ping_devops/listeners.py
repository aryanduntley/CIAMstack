"""The ping-devops chart's listeners: what its PingFederate pods listen on (release.POD_PORTS) for each server role an
environment runs with the chart. Declared on="kubernetes", so the kubernetes adapter's network policies admit these
ports to the role's pods and the firewall checks leave them out (kubernetes kits.kit_listeners). Pure."""
from opsdir_adapter_kubernetes.kits import kit_listeners
from .products import placements
from .release import POD_PORTS


def listeners(m):
    """The container ports of the PingFederate roles environment m runs with the ping-devops chart."""
    return kit_listeners(placements(m), POD_PORTS)

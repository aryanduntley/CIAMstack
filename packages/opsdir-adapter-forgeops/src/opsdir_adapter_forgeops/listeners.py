"""ForgeOps' listeners: what the release's pods listen on (its container ports, release.POD_PORTS) for each server
role an environment runs with ForgeOps. Declared on="kubernetes", so the kubernetes adapter's network policies admit
these ports to the role's pods instead of the product's own (PingAM's 8443 on its servers), and the firewall checks
leave them out (kubernetes kits.kit_listeners). Pure."""
from opsdir_adapter_kubernetes.kits import kit_listeners
from .components import placements
from .release import POD_PORTS


def listeners(m):
    """The container ports of the server roles environment m runs with ForgeOps."""
    return kit_listeners(placements(m), POD_PORTS)

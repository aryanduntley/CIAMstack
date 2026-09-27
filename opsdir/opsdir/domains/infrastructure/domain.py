"""Infrastructure domain: clouds, environments, servers and their bindings (network, subnets, service names,
firewall rules, egress, interconnects, secret and key references, backup targets), plus the external
allowlists that hold our addresses. Vendor-neutral: provider adapters realize it."""
from ...core.contract import Domain
from .checks import check_allowlists, check_versions
from .schema import FRAGMENT

# Every environment needs a network and encrypted disks, whatever runs in it.
REQUIRED_ROLES = ("network", "disk-encryption")

DOMAIN = Domain(name="infrastructure", schema=FRAGMENT, required_roles=REQUIRED_ROLES, sql=(), reports={},
                checks=(check_versions, check_allowlists), order=10,
                vocabulary={})

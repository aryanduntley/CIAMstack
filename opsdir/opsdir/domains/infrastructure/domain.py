"""Infrastructure domain: clouds, environments, servers and their bindings (network, subnets, service names,
firewall rules, egress, interconnects, secret and key references, backup targets), plus the external
allowlists that hold our addresses. Vendor-neutral: provider adapters realize it."""
from ...core.contract import Domain
from ...core.naming import branch
from .schema import FRAGMENT

ENVIRONMENTS = branch("environments")
EXTERNAL_ALLOWLISTS = branch("external-allowlists")

# Every environment needs a network and encrypted disks, whatever runs in it.
REQUIRED_ROLES = ("network", "disk-encryption")

DOMAIN = Domain(name="infrastructure", schema=FRAGMENT, required_roles=REQUIRED_ROLES, sql=(), reports={})

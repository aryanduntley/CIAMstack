"""The F5 add-on's planner check: a target whose stack declares F5 BIG-IP but records no appliance filling the
load-balancer role has nothing to push its service names to. Pure."""
from functools import partial

from opsdir.domains.infrastructure.appliances import check_appliance
from .play import STACK_ROLE

check_appliances = partial(check_appliance, adapter="f5-bigip", product="F5 BIG-IP", stack_role=STACK_ROLE,
                           area="Load balancer", consequence="its service names would have no load balancer",
                           record="the BIG-IP(s)")

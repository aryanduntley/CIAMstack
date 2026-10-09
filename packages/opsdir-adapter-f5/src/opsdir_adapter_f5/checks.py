"""The F5 add-on's planner check: a target whose stack declares F5 BIG-IP but records no appliance filling the
load-balancer role has nothing to push its service names to. Pure."""
from opsdir.core.findings import findings, responsible
from opsdir.domains.infrastructure.appliances import appliances
from .play import STACK_ROLE


def check_appliances(ctx):
    """A blocker when the target declares F5 BIG-IP and records no load-balancer appliance."""
    m = ctx.dst
    if not any(c.adapter == "f5-bigip" for c in m.stack) or appliances(m, STACK_ROLE):
        return findings()
    return findings(blockers=[("Load balancer", f"{m.label} declares F5 BIG-IP (stack role load-balancer) but records "
                               "no appliance for it (ciamAppliance, ciamStackRole load-balancer): its service names "
                               "would have no load balancer. Record the BIG-IP(s).", responsible(ctx.d, m.env))])

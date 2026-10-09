"""The HAProxy add-on's planner check: a target whose stack declares HAProxy but records no server of role
load-balancer has nowhere to run it, so its service names would have no load balancer. Pure."""
from opsdir.core.environment import servers_with_role
from opsdir.core.findings import findings, responsible
from .playbook import HOSTS


def check_hosts(ctx):
    """A blocker when the target declares HAProxy and records no load-balancer server."""
    m = ctx.dst
    if not any(c.adapter == "haproxy" for c in m.stack) or servers_with_role(m, HOSTS):
        return findings()
    return findings(blockers=[("Load balancer", f"{m.label} declares HAProxy (stack role load-balancer) but records no "
                               f"server of role `{HOSTS}` to run it: its service names would have no load balancer. "
                               "Record the load-balancer servers.", responsible(ctx.d, m.env))])

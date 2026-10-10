"""The HAProxy add-on's planner checks: a target whose stack declares HAProxy but records no server of role
load-balancer has nowhere to run it, so its service names would have no load balancer; and two service names whose
frontends would bind the same address and port (one without a frontend address binds every address) can't both be
served: the later isn't rendered. Pure."""
from opsdir.core.environment import servers_with_role
from opsdir.core.directory import one, rdn_value
from opsdir.core.findings import findings, responsible
from .config import clashes
from .playbook import HOSTS


def check_hosts(ctx):
    """A blocker when the target declares HAProxy and records no load-balancer server."""
    m = ctx.dst
    if not any(c.adapter == "haproxy" for c in m.stack) or servers_with_role(m, HOSTS):
        return findings()
    return findings(blockers=[("Load balancer", f"{m.label} declares HAProxy (stack role load-balancer) but records no "
                               f"server of role `{HOSTS}` to run it: its service names would have no load balancer. "
                               "Record the load-balancer servers.", responsible(ctx.d, m.env))])


def check_binds(ctx):
    """A blocker per frontend of a target declaring HAProxy that binds an address and port an earlier one binds."""
    m = ctx.dst
    if not any(c.adapter == "haproxy" for c in m.stack):
        return findings()
    return findings(blockers=[("Load balancer", f"{m.label}: service name `{one(svc, 'ciamFqdn')}` and "
                               f"`{one(other, 'ciamFqdn')}` would both listen on "
                               f"{one(svc, 'ciamFrontendIp') or 'every address'}:{port} on the HAProxy servers "
                               f"(`{rdn_value(svc)}` isn't rendered): record a frontend address for each "
                               "(ciamFrontendIp).", responsible(ctx.d, svc, m.env))
                              for svc, port, other in clashes(m)])

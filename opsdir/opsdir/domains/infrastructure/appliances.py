"""Appliances (ciamAppliance bindings): what an environment's configuration is pushed to beyond its servers (a load
balancer, a DNS server, a network firewall), each filling a stack role an add-on adapter renders for. A load balancer
that records where its own traffic comes from (ciamApplianceSource: its source NAT pool and self addresses) needs the
servers' firewall rules to admit that traffic on every service name's ports: the planner names each port that no rule
admits it on. Pure."""
import ipaddress

from ...core.directory import one, rdn_value, values
from ...core.environment import of_class, one_role
from ...core.findings import findings, responsible

LOAD_BALANCER = "load-balancer"


def appliances(m, stack_role):
    """Environment m's appliances filling a stack role (load-balancer, dns, network-firewall), in record order."""
    return tuple(a for a in of_class(m, "ciamAppliance") if one(a, "ciamStackRole") == stack_role)


def login_secret(m, appliance):
    """The reference (ciamRefUri) of the secret an appliance's login signs in with (its ciamLoginSecretRole as
    environment m binds it), or None."""
    role = one(appliance, "ciamLoginSecretRole")
    b = one_role(m, role) if role else None
    return one(b, "ciamRefUri") if b is not None else None


def check_appliance(ctx, adapter, product, stack_role, area, consequence, record):
    """An add-on's planner check (bound with functools.partial): a blocker when the target's stack declares adapter
    (named product) and the target records no appliance filling stack_role; area: the finding's area, consequence:
    what would go wrong, record: what to record."""
    m = ctx.dst
    if not any(c.adapter == adapter for c in m.stack) or appliances(m, stack_role):
        return findings()
    return findings(blockers=[(area, f"{m.label} declares {product} (stack role {stack_role}) but records no "
                               f"appliance for it (ciamAppliance, ciamStackRole {stack_role}): {consequence}. "
                               f"Record {record}.", responsible(ctx.d, m.env))])


def _admits(rules, role, port, source):
    """Whether a firewall rule admits a source range to a server role on a port."""
    net = ipaddress.ip_network(source, strict=False)
    return any(one(r, "ciamTargetRole") == role and str(port) in values(r, "ciamPort")
               and any(net.version == c.version and net.subnet_of(c)
                       for c in (ipaddress.ip_network(x, strict=False) for x in values(r, "ciamSourceCidr")))
               for r in rules)


def unadmitted(m):
    """((appliance, source range, service name, role, port), ...) environment m's load balancers' source ranges that
    no firewall rule admits to the servers behind a service name on its port."""
    rules = of_class(m, "ciamFirewallRule")
    return tuple((a, src, svc, one(svc, "ciamTargetRole"), port)
                 for a in appliances(m, LOAD_BALANCER) for src in values(a, "ciamApplianceSource")
                 for svc in of_class(m, "ciamServiceName") if one(svc, "ciamTargetRole")
                 for port in values(svc, "ciamPort") if not _admits(rules, one(svc, "ciamTargetRole"), port, src))


def check_appliance_sources(ctx):
    """An action per service-name port the target's load balancers' traffic (ciamApplianceSource) isn't admitted on
    by any firewall rule to the servers behind it."""
    m = ctx.dst
    return findings(actions=[("Firewall", f"{m.label}: no firewall rule admits load balancer `{rdn_value(a)}`'s "
                              f"traffic from {src} to role `{role}` on port {port} (service name "
                              f"`{one(svc, 'ciamFqdn')}`, its health monitors too): add a rule (ciamFirewallRule, "
                              f"ciamTargetRole {role}, ciamSourceCidr {src}, ciamPort {port}).",
                              responsible(ctx.d, a, m.env), None)
                             for a, src, svc, role, port in unadmitted(m)])

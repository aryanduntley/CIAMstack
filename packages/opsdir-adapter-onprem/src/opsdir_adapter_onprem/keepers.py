"""What fronts and connects an on-prem environment's servers, kept by the teams that run the site: each service name's
load balancer and DNS record, the environment's other DNS records, and each firewall rule on the network's firewalls.
Nothing in the record renders them unless the environment's stack declares an add-on for that part (a stack component
with role load-balancer, dns or network-firewall: an appliance adapter); otherwise the planner's check asks whoever
keeps each one, as a request. A DNS add-on writes only the names in zones the platform runs (core edge.records
published): the others (in a zone another party runs, in no bound zone, or kept by another party) are still asked
for. Who is asked: the binding's ciamManagedBy, for DNS the party running the zone, else the site's owner
(as for a landing zone). An item no one is recorded to keep is an action. Pure.
"""
from opsdir.core.directory import follow, one, rdn_value, values
from opsdir.core.environment import of_class, servers_with_role
from opsdir.core.findings import findings, responsible
from opsdir.domains.access.workloads import landing_zone_party
from opsdir.domains.edge.records import run_by, unpublished

LOAD_BALANCER, DNS, NETWORK_FIREWALL = "load-balancer", "dns", "network-firewall"   # the add-ons' stack roles
AREA = "On-prem"


def declared(m, role):
    """Whether environment m's stack declares a component (an add-on) for a stack role."""
    return any(c.role == role for c in m.stack)


def _keeper(m, b, name=None):
    return follow(m.d, b, "ciamManagedBy") or (run_by(m.d, m, name) if name else None) or landing_zone_party(m)


def _servers(m, role):
    return ", ".join(one(s, "ciamHostname") for s in servers_with_role(m, role)) or f"no {role} servers recorded"


def _address(s):
    ip = one(s, "ciamFrontendIp")
    return f" at {ip}" if ip else ""


def _load_balancer(m, s):
    role = one(s, "ciamTargetRole")
    return (f"a load balancer for `{one(s, 'ciamFqdn')}`{_address(s)} on port(s) {', '.join(values(s, 'ciamPort'))}"
            f" ({one(s, 'ciamExposure') or 'exposure as its address says'}), in front of role `{role}` "
            f"({_servers(m, role)})")


def _items(m):
    """((binding, keeper party or None, text), ...): what environment m's keepers are asked to set up."""
    lb, dns, fw = (not declared(m, r) for r in (LOAD_BALANCER, DNS, NETWORK_FIREWALL))
    names = of_class(m, "ciamServiceName")
    return (
        *((s, _keeper(m, s), _load_balancer(m, s)) for s in names if lb),
        *((s, _keeper(m, s, one(s, "ciamFqdn")),
           f"DNS record `{one(s, 'ciamFqdn')}` answering its load balancer's address{_address(s)}")
          for s in names if dns),
        *((r, _keeper(m, r, one(r, "ciamRecordName")), f"DNS {one(r, 'ciamRecordType')} record "
           f"`{one(r, 'ciamRecordName')}` → {', '.join(values(r, 'ciamRecordValue'))}")
          for r in of_class(m, "ciamDnsRecord") if dns),
        *((b, _keeper(m, b, fqdn), f"DNS record `{fqdn}` ({why}: the DNS add-on writes only the zones the platform "
           "runs)") for b, fqdn, why in (() if dns else unpublished(m))),
        *((r, _keeper(m, r), f"network firewall rule `{rdn_value(r)}`: {', '.join(values(r, 'ciamSourceCidr'))} → "
           f"role `{one(r, 'ciamTargetRole')}` on port(s) {', '.join(values(r, 'ciamPort'))}")
          for r in of_class(m, "ciamFirewallRule") if fw))


def check_keepers(ctx):
    """Requests to the keepers of what fronts and connects an on-prem target (no add-on renders it), actions for what
    no one is recorded to keep."""
    m = ctx.dst
    if m.provider != "onprem":
        return findings()
    items = _items(m)
    return findings(
        actions=[(AREA, f"{m.label}: {text}: no one is recorded to keep it (ciamManagedBy, or the site's owner).",
                  responsible(ctx.d, b, m.env), ctx.cutover) for b, party, text in items if party is None],
        requests=[(party, None, f"{m.label}: set up {text}.", "on-prem", ctx.cutover)
                  for b, party, text in items if party is not None])

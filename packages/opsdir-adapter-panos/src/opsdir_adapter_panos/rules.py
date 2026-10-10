"""The record's firewall rules (ciamFirewallRule) as PAN-OS objects and security rules: an address object per source
range (named by the range: the same object in every environment) and per server of the rule's target role (named by
the environment and the server: environments sharing a firewall don't overwrite each other's), a service object per
protocol and port, and a security rule per firewall rule allowing those sources to those servers on those services,
logged at session end, named by the environment and the rule, in ciamRulePriority order (unpinned rules last, by
name). Names are opsdir-<...>, PAN-OS's characters only, at most 63 characters: a longer one is cut and given a digest
of the whole, so two never meet. A target role with no server address recorded gives an UNBOUND address object, which
PAN-OS refuses, naming it. Pure."""
import hashlib
import ipaddress
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, of_class, servers_with_role

LIMIT = 63          # PAN-OS object and rule names


def name(text):
    """A PAN-OS name: opsdir-<text>, letters, digits, '.', '_' and '-' only; cut to 63 characters with an 8-character
    digest of the whole when longer."""
    full = "opsdir-" + re.sub(r"[^A-Za-z0-9._-]", "-", text)
    if len(full) <= LIMIT:
        return full
    return f"{full[:LIMIT - 9]}-{hashlib.sha256(full.encode()).hexdigest()[:8]}"


def marker(m):
    """The description prefix of environment m's security rules: how a run finds the rules it wrote before."""
    return f"opsdir {m.label}:"


def _env(m):
    return f"{rdn_value(m.cloud)}-{rdn_value(m.env)}"


def _source(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return {"name": name(str(net).replace("/", "_")), "value": str(net), "address_type": "ip-netmask"}


def _order(r):
    priority = one(r, "ciamRulePriority")
    return (priority is None, int(priority) if priority else 0, rdn_value(r))


def objects(m):
    """{addresses, services, rules} of environment m's firewall rules, as the play's variables; each rule with the
    rule before it (after: None for the first), where a new rule is placed."""
    rules = sorted(of_class(m, "ciamFirewallRule"), key=_order)
    addresses, services, found = {}, {}, []
    for r in rules:
        sources = [_source(c) for c in values(r, "ciamSourceCidr")]
        servers = [{"name": name(f"{_env(m)}-{rdn_value(s)}"),
                    "value": one(s, "ciamPrivateIp") or f"{UNBOUND}{rdn_value(s)}-address",
                    "address_type": "ip-netmask"} for s in servers_with_role(m, one(r, "ciamTargetRole"))]
        protocol = one(r, "ciamProtocol", "tcp")
        ports = [{"name": name(f"{protocol}-{p}"), "protocol": protocol, "destination_port": p}
                 for p in values(r, "ciamPort")]
        addresses.update({a["name"]: a for a in (*sources, *servers)})
        services.update({s["name"]: s for s in ports})
        found.append({"rule_name": name(f"{_env(m)}-{rdn_value(r)}"), "source_ip": [a["name"] for a in sources],
                      "destination_ip": [a["name"] for a in servers]
                      or [f"{UNBOUND}{one(r, 'ciamTargetRole')}-servers"],
                      "service": [s["name"] for s in ports],
                      "description": f"{marker(m)} {rdn_value(r)} -> role {one(r, 'ciamTargetRole')}",
                      "after": found[-1]["rule_name"] if found else None})
    return {"addresses": list(addresses.values()), "services": list(services.values()), "rules": found}

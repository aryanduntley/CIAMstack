"""The record's firewall rules (ciamFirewallRule) as PAN-OS objects and security rules: an address object per source
range and per server of the rule's target role (its private address), a service object per protocol and port, and a
security rule per firewall rule allowing those sources to those servers on those services (zones and application
any: the record names neither), logged at session end. Names are opsdir-<...>, PAN-OS's characters only. A target
role with no server address recorded gives an UNBOUND address object, which PAN-OS refuses, naming it. Pure."""
import ipaddress
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, of_class, servers_with_role


def _name(text):
    """A PAN-OS object name: opsdir-<text>, letters, digits, '.', '_' and '-' only, at most 63 characters."""
    return ("opsdir-" + re.sub(r"[^A-Za-z0-9._-]", "-", text))[:63]


def _source(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return {"name": _name(str(net).replace("/", "_")), "value": str(net), "address_type": "ip-netmask"}


def objects(m):
    """{addresses: [...], services: [...], rules: [...]} of environment m's firewall rules, as the play's variables."""
    rules = of_class(m, "ciamFirewallRule")
    addresses, services, found = {}, {}, []
    for r in rules:
        sources = [_source(c) for c in values(r, "ciamSourceCidr")]
        servers = [{"name": _name(rdn_value(s)),
                    "value": one(s, "ciamPrivateIp") or f"{UNBOUND}{rdn_value(s)}-address",
                    "address_type": "ip-netmask"} for s in servers_with_role(m, one(r, "ciamTargetRole"))]
        protocol = one(r, "ciamProtocol", "tcp")
        ports = [{"name": _name(f"{protocol}-{p}"), "protocol": protocol, "destination_port": p}
                 for p in values(r, "ciamPort")]
        addresses.update({a["name"]: a for a in (*sources, *servers)})
        services.update({s["name"]: s for s in ports})
        found.append({"rule_name": _name(rdn_value(r)), "source_ip": [a["name"] for a in sources],
                      "destination_ip": [a["name"] for a in servers]
                      or [f"{UNBOUND}{one(r, 'ciamTargetRole')}-servers"],
                      "service": [s["name"] for s in ports],
                      "description": f"opsdir: {rdn_value(r)} -> role {one(r, 'ciamTargetRole')}"})
    return {"addresses": list(addresses.values()), "services": list(services.values()), "rules": found}

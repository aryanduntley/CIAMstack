"""The record's firewall rules (ciamFirewallRule) as each target role's host firewall: one firewalld rich rule per
source range and port, accepting the role's traffic on its servers themselves (the network's firewalls are the
provider's or the site's keepers'). Pure."""
import ipaddress

from opsdir.core.directory import one, values
from opsdir.core.environment import of_class


def _rule(cidr, port, protocol):
    family = "ipv6" if ipaddress.ip_network(cidr, strict=False).version == 6 else "ipv4"
    return (f'rule family="{family}" source address="{cidr}" port port="{port}" protocol="{protocol}" accept')


def firewall_vars(m, role):
    """{ciam_firewall_rules: [rich rule, ...]} of a role's rules in environment m (those it has)."""
    rules = [_rule(cidr, port, one(r, "ciamProtocol", "tcp"))
             for r in of_class(m, "ciamFirewallRule") if one(r, "ciamTargetRole") == role
             for cidr in values(r, "ciamSourceCidr") for port in values(r, "ciamPort")]
    return {"ciam_firewall_rules": list(dict.fromkeys(rules))} if rules else {}

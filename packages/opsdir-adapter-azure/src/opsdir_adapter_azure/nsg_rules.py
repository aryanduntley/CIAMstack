"""Azure network security rules as the record reads them (azurerm attribute names; the CLI and ARM templates
normalize to them): a rule's sources, ports and source ranges, the rules each network security group holds (separate
rules by their group's name and resource group, and inline ones), and the ranges a group's inbound allow rules admit.
Shared by the firewall reader and the readers whose groups it leaves to them (a database's). Pure."""
from opsdir.core.inventory import of_types

ANY = ("*", "any", "internet", "0.0.0.0/0")


def _low(v):
    return (v or "").lower()


def rule_sources(rule):
    """A rule's source prefixes (several, or the one)."""
    given = (*(rule.get("source_address_prefixes") or ()), rule.get("source_address_prefix"))
    return tuple(p for p in given if p)


def source_cidr(prefix):
    """A source prefix as a CIDR: any source is 0.0.0.0/0, a bare address a /32; None for a service tag."""
    if prefix.lower() in ANY:
        return "0.0.0.0/0"
    if all(c in "0123456789./:" for c in prefix):
        return prefix if "/" in prefix else f"{prefix}/32"
    return None


def rule_ports(rule):
    """A rule's destination ports (several, or the one), as text."""
    given = (*(rule.get("destination_port_ranges") or ()), rule.get("destination_port_range"))
    return tuple(str(p) for p in given if p)


def allows_in(rule):
    """Whether a rule is an inbound allow rule (what the record holds)."""
    return _low(rule.get("direction")) == "inbound" and _low(rule.get("access")) == "allow"


def group_rules(found):
    """[(the id, lower case, of the network security group a rule belongs to, or None when it isn't reported; the
    rule)]: separate rules by their group's name and resource group, then each group's inline rules."""
    groups = {_low(g.get("id")): g for g in of_types(found, "azurerm_network_security_group")}
    by_name = {(_low(g.get("resource_group_name")), _low(g.get("name"))): k for k, g in groups.items()}
    return [*((by_name.get((_low(r.get("resource_group_name")), _low(r.get("network_security_group_name")))), r)
              for r in of_types(found, "azurerm_network_security_rule")),
            *((k, r) for k, g in groups.items() for r in g.get("security_rule") or ())]


def admitted_ranges(found, groups):
    """{network security group id (lower case): the source ranges its inbound allow rules admit} for these groups."""
    rules = group_rules(found)
    return {k: tuple(source_cidr(p) for g, r in rules if g == k and allows_in(r) for p in rule_sources(r)
                     if source_cidr(p)) for k in groups}

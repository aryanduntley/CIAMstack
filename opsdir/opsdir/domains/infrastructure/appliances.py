"""Appliances (ciamAppliance bindings): what an environment's configuration is pushed to beyond its servers (a load
balancer, a DNS server, a network firewall), each filling a stack role an add-on adapter renders for. Pure."""
from ...core.directory import one
from ...core.environment import of_class, one_role


def appliances(m, stack_role):
    """Environment m's appliances filling a stack role (load-balancer, dns, network-firewall), in record order."""
    return tuple(a for a in of_class(m, "ciamAppliance") if one(a, "ciamStackRole") == stack_role)


def login_secret(m, appliance):
    """The reference (ciamRefUri) of the secret an appliance's login signs in with (its ciamLoginSecretRole as
    environment m binds it), or None."""
    role = one(appliance, "ciamLoginSecretRole")
    b = one_role(m, role) if role else None
    return one(b, "ciamRefUri") if b is not None else None

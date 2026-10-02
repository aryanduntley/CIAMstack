"""Address arithmetic shared by every layer (no provider knowledge)."""
import ipaddress

# The address space a private network (VPC, VNet) frontend takes: RFC 1918, RFC 6598 shared space, IPv6 unique local.
# Not ipaddress's is_private, which also counts documentation and other special ranges (198.51.100.0/24, ...) that
# examples use for public addresses.
PRIVATE_USE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")


def is_private(ip):
    """Whether an address (or range) is in private-use address space."""
    net = ipaddress.ip_network(ip, strict=False)
    return covers(tuple(c for c in PRIVATE_USE if ipaddress.ip_network(c).version == net.version), ip)


def covers(cidrs, addr):
    """Whether an address or range lies inside any of the given CIDRs."""
    net = ipaddress.ip_network(addr, strict=False)
    return any(net.subnet_of(ipaddress.ip_network(c, strict=False)) for c in cidrs)

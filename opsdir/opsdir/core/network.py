"""Address arithmetic shared by every layer (no provider knowledge)."""
import ipaddress


def is_private(ip):
    return ipaddress.ip_address(ip.split("/")[0]).is_private


def covers(cidrs, addr):
    """Whether an address or range lies inside any of the given CIDRs."""
    net = ipaddress.ip_network(addr, strict=False)
    return any(net.subnet_of(ipaddress.ip_network(c, strict=False)) for c in cidrs)

"""What every cloud's exports share (pure): stable made-up IDs and lookups over an environment fixture's rows
(infrastructure.SOURCE / TARGET / STANDBY)."""
import hashlib


def hex_id(*parts, n=12):
    """A stable made-up hex ID for these parts (the same on every run)."""
    return hashlib.sha256("/".join(map(str, parts)).encode()).hexdigest()[:n]


def by_role(rows, roles):
    """Provider refs of the (binding name, role, ref, ...) rows whose role is one of roles."""
    wanted = roles if isinstance(roles, list) else [roles]
    return [ref for _, role, ref, *_ in rows if role in wanted]


def service_named(p, role):
    """The binding name of the environment's service name with this role."""
    return next(cn for cn, r, *_ in p["services"] if r == role)


def rows_of(rows, oc):
    """(cn, binding role, attributes) of the (object class, cn, role, attributes) rows of one object class."""
    return [(cn, role, attrs) for c, cn, role, attrs in rows if c == oc]


def listed(v):
    """A fixture attribute's values as a list: a string is one value."""
    return [v] if isinstance(v, str) else list(v or ())


def servers_of(p, role):
    """The environment's server rows of one server role."""
    return [s for s in p["servers"] if s[1] == role]


def edge_subnets(p):
    """(binding name, role, provider ref, CIDR, zone) of the environment's edge subnets (the gateways', the
    proxies')."""
    return [(cn, role, attrs["ciamProviderRef"], attrs["ciamCidr"], None)
            for oc, cn, role, attrs in p["edge"] if oc == "ciamSubnetBinding"]

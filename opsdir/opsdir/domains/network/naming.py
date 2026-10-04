"""Network domain vocabulary: where the outside sites the platform must reach live, the neutral terms routes, network
ACL rules and destinations are written in, and the kinds of private endpoints, links, proxies, time sources, flow logs
and firewall policies an environment binds."""
from ...core.naming import branch

EGRESS_DESTINATIONS = branch("egress-destinations")

# Where a route sends matching traffic. The target after the kind is the binding role of what realizes it (a NAT's
# egress role, an interconnect's role, a firewall or proxy's role) or, when the record has no binding for it, the
# provider's reference.
ROUTE_TARGETS = ("local", "internet", "egress-only", "nat", "transit", "peering", "vpn", "endpoint", "firewall",
                 "appliance", "gateway-lb", "none")
_ROLES = "[a-z0-9][a-z0-9-]*(,[a-z0-9][a-z0-9-]*)*"
# '<destination> <target kind> [<target>] [for <server roles>]': the destination a CIDR or a prefix list's name; 'for'
# scopes a route that applies only to some servers (routes that follow network tags)
ROUTE = rf"^([0-9A-Fa-f:.]+/[0-9]+|[A-Za-z][A-Za-z0-9._-]*) ({'|'.join(ROUTE_TARGETS)})( [^ ]+)?( for {_ROLES})?$"
DEFAULT_ROUTE = ("0.0.0.0/0", "::/0")

# '<number> <allow|deny> <in|out> <protocol> <port|from-to|all> <cidr>': one rule of a stateless network ACL, evaluated
# in number order (100 allow in tcp 636 10.20.0.0/16)
ACL_RULE = r"^[0-9]+ (allow|deny) (in|out) (tcp|udp|icmp|all) ([0-9]+(-[0-9]+)?|all) [0-9A-Fa-f:.]+/[0-9]+$"
PORT_RANGE = r"^[0-9]+-[0-9]+$"
EPHEMERAL = "1024-65535"            # the return-traffic range a stateless rule set must allow unless the record says

# What a private endpoint reaches, and how: an endpoint the network's routes point at (gateway), an address in a subnet
# for one service (interface), one address for all of the provider's APIs (all-apis), the provider's service networks
# reached by peering (peered-service: managed databases), or a subnet setting that reaches the APIs privately
# (subnet-access)
PRIVATE_SERVICES = ("secrets", "keys", "object-storage", "database", "logs", "messaging", "registry", "apis", "other")
PRIVATE_ENDPOINT_KINDS = ("gateway", "interface", "all-apis", "peered-service", "subnet-access")

LINK_KINDS = ("peering", "transit", "vpn", "dedicated", "hub")
# What controls egress to named sites: a cloud firewall with domain rules, a managed web proxy, a forward proxy the
# platform runs, a proxy service run by someone else
PROXY_KINDS = ("firewall", "web-proxy", "forward-proxy", "service")
PROXY_ADDRESS = r"^[A-Za-z0-9.-]+:[0-9]+$"
DESTINATION = r"^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+(:[0-9]+)?$"
SITE_KINDS = ("partner-metadata", "jwks", "ocsp-crl", "mfa", "messaging", "vendor-update", "directory", "other")

TIME_KINDS = ("provider", "ntp", "ptp", "internal")
FLOW_SCOPES = ("network", "subnet", "interface", "transit", "security-group")
FIREWALL_MODELS = ("rules", "policy")       # rules: rules on the network; policy: a policy attached to it, by tags
POLICY_SCOPES = ("network", "hierarchical")
POLICY_ORDER = ("rules-first", "policy-first")
NAT_ALLOCATION = ("static", "automatic")    # automatic: the provider picks the addresses (nothing to allowlist)

# How servers reach a port a product listens on: clients (consumers, through the service names or directly), peers
# (other servers of the same role: replication, clustering), admin (the operators' ways in), or named server roles
LISTENER_PEERS = ("clients", "peers", "admin")

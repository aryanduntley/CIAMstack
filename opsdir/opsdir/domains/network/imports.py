"""Network's import kinds (core.contract.ImportKind): what the cloud importers read into route tables, network ACLs,
private endpoints, endpoint services, proxies, flow logs and firewall policies (each matched by provider ref), and
what core.inventory resolves for them. Pure.

  route-table      -> ciamRouteTable       a route's target written as the provider's reference (0.0.0.0/0 nat
                                           nat-0abc) becomes the role of the binding with that reference
  acl              -> ciamNetworkAcl       a stateless network ACL
  private-endpoint -> ciamPrivateEndpoint  a VPC endpoint, a private endpoint, a PSC endpoint, private services access
  endpoint-service -> ciamEndpointService  an endpoint service, a Private Link Service, a service attachment
  proxy            -> ciamProxy            a firewall with domain rules, a web proxy: its allowlist reported without
                                           the ports a source can't express is the record's with them
  flow-log         -> ciamFlowLog          a flow log, a subnet's flow log setting; a new one without a role takes
                                           'flow-logs-<role of its subnet>'
  firewall-policy  -> ciamFirewallPolicy   a network or hierarchical firewall policy
"""
from ...core.contract import ImportKind
from ...core.inventory import first_ref

ROUTE_TARGET = 2                     # the token of a ciamRoute value naming its target (a role, else a provider ref)


def route_targets(attrs, roles):
    """{ciamRoute: its values with a target written as a provider ref replaced by the role of the binding with that
    ref}, or {} when the attributes carry no routes."""
    def one_route(text):
        tokens = text.split(" ")
        return " ".join((*tokens[:ROUTE_TARGET], roles[tokens[ROUTE_TARGET]], *tokens[ROUTE_TARGET + 1:])) \
            if len(tokens) > ROUTE_TARGET and tokens[ROUTE_TARGET] in roles else text
    return {"ciamRoute": tuple(one_route(v) for v in attrs["ciamRoute"])} if "ciamRoute" in attrs else {}


def flow_log_role(r, roles):
    """A new flow log's role from its subnet ('flow-logs-<subnet role>'), else None."""
    subnet = roles.get(first_ref(r.links.get("ciamSubnetRole")))
    return f"flow-logs-{subnet}" if subnet else None


IMPORT_KINDS = (
    ImportKind("route-table", "ciamRouteTable", ("ciamRoute",), resolve=route_targets),
    ImportKind("acl", "ciamNetworkAcl", ("ciamAclRule",)),
    ImportKind("private-endpoint", "ciamPrivateEndpoint", ("ciamPrivateService",)),
    ImportKind("endpoint-service", "ciamEndpointService", ("ciamServiceRole",)),
    ImportKind("proxy", "ciamProxy", ("ciamProxyKind",), ported=frozenset({"ciamAllowedDestination"})),
    ImportKind("flow-log", "ciamFlowLog", ("ciamFlowScope",), role=flow_log_role),
    ImportKind("firewall-policy", "ciamFirewallPolicy", ("ciamPolicyScope",)),
)
ROLE_LINKS = {"ciamSubnetRole": "subnet", "ciamPolicyRole": "firewall-policy"}

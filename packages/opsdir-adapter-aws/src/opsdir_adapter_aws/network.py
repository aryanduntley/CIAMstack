"""AWS: what the stack renders of its network depth (opsdir.domains.network.stack). VPC endpoints to the services it
uses: Interface endpoints in its subnets, with a security group admitting the network on 443 and private DNS as
recorded; Gateway endpoints (S3, DynamoDB) on the route tables the record binds. Endpoint services exposing a service
name's network load balancer to the principals allowed, acceptance as recorded: only a passthrough (L4) service can be
exposed, since an endpoint service needs an NLB. An egress firewall the stack keeps gets its domain allowlist as a
Network Firewall stateful rule group (ALLOWLIST on TLS SNI and HTTP Host), referenced from the firewall's policy. What
someone else keeps is a comment naming them. Pure."""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class, one_role
from opsdir.domains.edge.resolve import service_edge
from opsdir.domains.network.stack import (allowlist, egress_firewalls, elsewhere, endpoint_services, private_endpoints,
                                          reached, subnets)
from opsdir_format_terraform.hcl import Block, block, ref, tf_name

# the AWS service a private endpoint to each kind of service reaches (com.amazonaws.<region>.<service>)
SERVICES = {"secrets": "secretsmanager", "keys": "kms", "object-storage": "s3", "logs": "logs", "messaging": "sns",
            "registry": "ecr.api"}
GATEWAY_SERVICES = ("s3", "dynamodb")


def _tags(b):
    return {"Name": rdn_value(b), "Role": one(b, "ciamBindingRole"), "ManagedBy": "opsdir"}


def _route_tables(m, p):
    """Provider refs of the route tables a gateway endpoint goes on: those naming its subnets (the main table when one
    of them has none), every recorded table when it names no subnets."""
    tables = tuple(t for t in of_class(m, "ciamRouteTable") if one(t, "ciamProviderRef"))
    roles = set(values(p, "ciamSubnetRole"))
    if not roles:
        return tuple(one(t, "ciamProviderRef") for t in tables)
    named = tuple(t for t in tables if roles & set(values(t, "ciamSubnetRole")))
    unassociated = roles - {r for t in tables for r in values(t, "ciamSubnetRole")}
    main = tuple(t for t in tables if one(t, "ciamMainTable") == "TRUE") if unassociated else ()
    return tuple(dict.fromkeys(one(t, "ciamProviderRef") for t in (*named, *main)))


def _interface(m, p, n, service):
    net = one_role(m, "network")
    found = subnets(m, p)
    return (block("resource", ["aws_security_group", f"{n}_endpoint"], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(p)}"),
                ("description", f"CIAM private endpoint {rdn_value(p)} ({m.label})"),
                ("vpc_id", ref("data.aws_vpc.main.id")), ("tags", {"ManagedBy": "opsdir"})]),
            *(block("resource", ["aws_vpc_security_group_ingress_rule", f"{n}_endpoint_{i}"], [
                ("security_group_id", ref(f"aws_security_group.{n}_endpoint.id")), ("cidr_ipv4", cidr),
                ("from_port", 443), ("to_port", 443), ("ip_protocol", "tcp"),
                ("description", f"the network to {rdn_value(p)}")])
              for i, cidr in enumerate(values(net, "ciamCidr") if net is not None else ())),
            block("resource", ["aws_vpc_endpoint", n], [
                ("vpc_id", ref("data.aws_vpc.main.id")),
                ("service_name", f"com.amazonaws.{one(m.cloud, 'ciamRegion')}.{service}"),
                ("vpc_endpoint_type", "Interface"),
                *((("subnet_ids", [ref(f"data.aws_subnet.{tf_name(rdn_value(s))}.id") for s in found]),) if found
                  else (("#", "UNBOUND: the endpoint names no subnet this environment binds"),)),
                ("security_group_ids", [ref(f"aws_security_group.{n}_endpoint.id")]),
                ("private_dns_enabled", one(p, "ciamPrivateDns") == "TRUE"), ("tags", _tags(p))]))


def _gateway(m, p, n, service):
    if service not in GATEWAY_SERVICES:
        return (f"# Private endpoint '{rdn_value(p)}': {service} has no gateway endpoint (only S3 and DynamoDB); "
                "record it as an interface endpoint. Not rendered.",)
    tables = _route_tables(m, p)
    return (block("resource", ["aws_vpc_endpoint", n], [
        ("vpc_id", ref("data.aws_vpc.main.id")),
        ("service_name", f"com.amazonaws.{one(m.cloud, 'ciamRegion')}.{service}"),
        ("vpc_endpoint_type", "Gateway"),
        ("route_table_ids", list(tables)) if tables
        else ("#", "UNBOUND: no route table with a provider ref carries the endpoint's subnets"),
        ("tags", _tags(p))]),)


def private_endpoint(m, p):
    """A VPC endpoint the stack keeps: Interface (with its security group) or Gateway; a comment for what AWS has no
    endpoint for or a kind AWS doesn't have."""
    n, kind, what = tf_name(rdn_value(p)), one(p, "ciamPrivateEndpointKind", "interface"), one(p, "ciamPrivateService")
    service = SERVICES.get(what)
    roles = ", ".join(one(b, "ciamBindingRole") for b in reached(m, p))
    head = (f"# Private endpoint '{rdn_value(p)}' to {what}" + (f" (reaches {roles})" if roles else ""),)
    if service is None:
        return (f"# Private endpoint '{rdn_value(p)}': no VPC endpoint for {what} (a database is reached at its own "
                "private address); not rendered.",)
    if kind == "interface":
        return (*head, *_interface(m, p, n, service))
    if kind == "gateway":
        return (*head, *_gateway(m, p, n, service))
    return (f"# Private endpoint '{rdn_value(p)}': AWS has no {kind} endpoint; record it as an interface or gateway "
            "endpoint. Not rendered.",)


def endpoint_service(m, e, svc, endpoints=()):
    """An endpoint service on the NLB of the service name it exposes; a comment when the name isn't bound or its
    traffic policy puts it on an ALB (an endpoint service needs an NLB)."""
    role = one(e, "ciamServiceRole")
    if svc is None:
        return (f"# UNBOUND: endpoint service '{rdn_value(e)}' exposes {role}, which this environment doesn't bind",)
    spec = service_edge(m, svc, endpoints)
    if spec is not None and (spec.layer7 or spec.cdn):
        return (f"# Endpoint service '{rdn_value(e)}': {rdn_value(svc)} terminates TLS at an application load "
                "balancer; an endpoint service needs a network load balancer (L4 passthrough). Not rendered.",)
    return (block("resource", ["aws_vpc_endpoint_service", tf_name(rdn_value(e))], [
        ("acceptance_required", one(e, "ciamAcceptanceRequired") == "TRUE"),
        ("network_load_balancer_arns", [ref(f"aws_lb.{tf_name(rdn_value(svc))}.arn")]),
        ("allowed_principals", values(e, "ciamAllowedPrincipal")), ("tags", _tags(e))]),)


def _domain(host):
    """A Network Firewall domain list target: *.example becomes .example (the domain and its subdomains)."""
    return "." + host[2:] if host.startswith("*.") else host


def domain_rules(m, proxy):
    """An egress firewall's allowlist as a stateful domain-list rule group (ALLOWLIST: other TLS and HTTP egress is
    dropped), the network as HOME_NET; its firewall policy references it. Sites on other ports (a mail relay) aren't
    web traffic, which a domain list can't match: said."""
    n = tf_name(rdn_value(proxy))
    sites = allowlist(proxy)
    hosts = tuple(dict.fromkeys(_domain(h) for _, found in sites for h in found))
    other = tuple(f"{h}:{port}" for port, found in sites if port not in (80, 443) for h in found)
    net = one_role(m, "network")
    policy = one(proxy, "ciamProviderRef")
    home = Block((("key", "HOME_NET"),
                  ("ip_set", Block((("definition", values(net, "ciamCidr") if net is not None else []),)))))
    domains = Block((("generated_rules_type", "ALLOWLIST"), ("target_types", ["TLS_SNI", "HTTP_HOST"]),
                     ("targets", list(hosts))))
    return (f"# Egress firewall '{rdn_value(proxy)}': reference this rule group from its firewall policy"
            + (f" ({policy})" if policy else "") + " (stateful_rule_group_reference)",
            *((f"# A domain list matches TLS SNI and HTTP Host only: {', '.join(other)} isn't web traffic, so the "
               "policy's other stateful rules decide it",) if other else ()),
            block("resource", ["aws_networkfirewall_rule_group", f"{n}_domains"], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(proxy)}-domains"), ("type", "STATEFUL"),
                ("capacity", max(100, 2 * len(hosts))),
                ("description", f"Sites the CIAM platform reaches ({m.label})"),
                ("rule_group", Block((("rule_variables", Block((("ip_sets", home),))),
                                      ("rules_source", Block((("rules_source_list", domains),)))))),
                ("tags", {**_tags(proxy), **({"FirewallPolicy": policy} if policy else {})})]))


def render_network(m, endpoints=()):
    """HCL blocks for environment m's network depth the stack keeps, after comments naming what others keep; () when
    the record has none."""
    notes = tuple(f"# {s}" for s in elsewhere(m))
    return (*notes,
            *(x for p in private_endpoints(m) for x in private_endpoint(m, p)),
            *(x for e, svc in endpoint_services(m) for x in endpoint_service(m, e, svc, endpoints)),
            *(x for f in egress_firewalls(m) for x in domain_rules(m, f)))

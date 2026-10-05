"""Google Cloud: what the stack renders of its network depth (opsdir.domains.network.stack). A Private Service Connect
endpoint for Google's APIs (a global internal address with purpose PRIVATE_SERVICE_CONNECT and a global forwarding
rule to all-apis, in the network's project); Private Google Access and private services access are the subnets' and
the network's settings, which the landing zone keeps: said in comments. Service attachments exposing a service name's
internal passthrough forwarding rule through a PSC NAT subnet, connections accepted automatically or from the allowed
projects and networks. An egress firewall the stack keeps gets its allowlist as egress rules of the network firewall
policy (opsdir_adapter_gcp.firewall_policy): FQDN rules exist only there. What someone else keeps is a comment naming
them. Pure."""
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.network import is_private
from opsdir.domains.edge.resolve import service_edge
from opsdir.domains.network.stack import (egress_firewalls, elsewhere, endpoint_services, firewall_model,
                                          private_endpoints, subnets)
from opsdir_adapter_gcp.firewall_policy import egress_rules, network_project
from opsdir_adapter_gcp.names import NETWORK, REGION, label
from opsdir_format_terraform.hcl import Block, block, ref, tf_name

# what a private endpoint of each other kind is on Google Cloud, and who keeps it
NOT_HERE = {"subnet-access": "Private Google Access is a subnet setting the landing zone keeps",
            "peered-service": "private services access (a service networking peering) is the landing zone's",
            "gateway": "Google Cloud has no gateway endpoints",
            "interface": "a PSC endpoint to a published service needs the service attachment it connects to"}


def psc_name(cn):
    """A PSC forwarding rule's name for Google's APIs: 1-20 lowercase letters and digits, a letter first."""
    n = re.sub(r"[^a-z0-9]", "", cn.lower())
    return (n if n[:1].isalpha() else "p" + n)[:20]


def private_endpoint(m, p):
    """A Private Service Connect endpoint for Google's APIs the stack keeps; a comment for the kinds the landing zone
    keeps or that need more than the record says."""
    n, kind = tf_name(rdn_value(p)), one(p, "ciamPrivateEndpointKind", "all-apis")
    if kind != "all-apis":
        return (f"# Private endpoint '{rdn_value(p)}' ({kind}): {NOT_HERE[kind]}; not rendered.",)
    ip = one(p, "ciamFrontendIp")
    if not ip:
        return (f"# UNBOUND: private endpoint '{rdn_value(p)}' to Google's APIs records no address (ciamFrontendIp)",)
    dns = (f"# private DNS: the landing zone's private googleapis.com zone answers {ip} for '{rdn_value(p)}'",) \
        if one(p, "ciamPrivateDns") == "TRUE" else ()
    return (*dns,
            block("resource", ["google_compute_global_address", n], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(p)}"), *network_project(m),
                ("purpose", "PRIVATE_SERVICE_CONNECT"), ("address_type", "INTERNAL"), ("network", NETWORK),
                ("address", ip), ("labels", {"role": label(one(p, "ciamBindingRole")), "managed_by": "opsdir"})]),
            block("resource", ["google_compute_global_forwarding_rule", n], [
                ("name", psc_name(rdn_value(p))), *network_project(m), ("target", "all-apis"), ("network", NETWORK),
                ("ip_address", ref(f"google_compute_global_address.{n}.id")), ("load_balancing_scheme", "")]))


def _accept(principal):
    """A consumer accept list entry: a network by its URL, else a project by id or number."""
    who = (("network_url", principal),) if "/networks/" in principal else \
        (("project_id_or_num", principal.removeprefix("projects/")),)
    return Block((*who, ("connection_limit", 10)))


def service_attachment(m, e, svc, endpoints=()):
    """A service attachment on the internal passthrough forwarding rule of the service name it exposes; a comment when
    the name isn't bound, is public or runs on an application load balancer."""
    role = one(e, "ciamServiceRole")
    if svc is None:
        return (f"# UNBOUND: endpoint service '{rdn_value(e)}' exposes {role}, which this environment doesn't bind",)
    spec = service_edge(m, svc, endpoints)
    ip = one(svc, "ciamFrontendIp")
    if not ip or not is_private(ip) or (spec is not None and (spec.layer7 or spec.cdn)):
        return (f"# Endpoint service '{rdn_value(e)}': {rdn_value(svc)} isn't an internal passthrough load balancer; "
                "a service attachment here needs one. Not rendered.",)
    manual, nat = one(e, "ciamAcceptanceRequired") == "TRUE", subnets(m, e)
    return (block("resource", ["google_compute_service_attachment", tf_name(rdn_value(e))], [
        ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(e)}"), ("region", REGION),
        ("description", f"{one(svc, 'ciamFqdn')} for other networks ({m.label})"),
        ("enable_proxy_protocol", False),
        ("connection_preference", "ACCEPT_MANUAL" if manual else "ACCEPT_AUTOMATIC"),
        ("nat_subnets", [ref(f"data.google_compute_subnetwork.{tf_name(rdn_value(s))}.id") for s in nat]) if nat
        else ("#", "UNBOUND: no PSC NAT subnet recorded (ciamSubnetRole)"),
        ("target_service", ref(f"google_compute_forwarding_rule.{tf_name(rdn_value(svc))}.id")),
        *((("consumer_accept_lists", _accept(pr)) for pr in values(e, "ciamAllowedPrincipal"))
          if manual else ())]),)


def egress(m, proxy):
    """An egress firewall's allowlist as network firewall policy rules, or a comment when the network keeps VPC
    firewall rules (which have no FQDN rules)."""
    if firewall_model(m) != "policy":
        return (f"# Egress firewall '{rdn_value(proxy)}': FQDN egress rules exist only in network firewall policies; "
                "set the network's firewall model to policy (ciamFirewallModel). Not rendered.",)
    return egress_rules(m, proxy)


def render_network(m, endpoints=()):
    """HCL blocks for environment m's network depth the stack keeps, after comments naming what others keep; () when
    the record has none."""
    return (*(f"# {s}" for s in elsewhere(m)),
            *(x for p in private_endpoints(m) for x in private_endpoint(m, p)),
            *(x for e, svc in endpoint_services(m) for x in service_attachment(m, e, svc, endpoints)),
            *(x for f in egress_firewalls(m) for x in egress(m, f)))


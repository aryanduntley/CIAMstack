"""Google Cloud: what the stack renders of its network depth (opsdir.domains.network.stack). A Private Service Connect
endpoint for Google's APIs (a global internal address with purpose PRIVATE_SERVICE_CONNECT and a global forwarding
rule to all-apis, in the network's project). Private services access (the service producer networks managed
databases get their private addresses from), when the record gives its allocated range: a global internal address
with purpose VPC_PEERING and the service networking connection reserving it, rendered in its keeper's root like any
plumbing. Private Google Access is a subnet setting the landing zone keeps: said in a comment. Service attachments
exposing a service name's internal passthrough forwarding rule through a PSC NAT subnet, connections accepted
automatically or from the allowed projects and networks. An egress firewall the stack keeps gets its allowlist as
egress rules of the network firewall policy (opsdir_adapter_gcp.firewall_policy): FQDN rules exist only there. What
someone else keeps is a comment naming them. What it leaves out or to a person is a render note (core.notes, flow 43)
written as its comment: endpoint_notes, attachment_note, egress_note, all of them network_notes. Pure."""
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.core.network import is_private
from opsdir.core.notes import RECORD, note_comment
from opsdir.domains.edge.resolve import service_edge
from opsdir.domains.network.plumbing import network_note
from opsdir.domains.network.stack import (egress_firewalls, elsewhere, endpoint_services, firewall_model,
                                          private_endpoints, subnets)
from opsdir_adapter_gcp.firewall_policy import egress_rules, network_project
from opsdir_adapter_gcp.names import NETWORK, REGION, label, name_parts, resource_id
from opsdir_format_terraform.hcl import Block, comment, ref, tf_block, tf_name

# what a private endpoint of each other kind is on Google Cloud, and who keeps it: (severity, text, how) of its note
NOT_HERE = {"subnet-access": ("action", "Private Google Access is a subnet setting the landing zone keeps",
                              ("Have the landing zone turn on Private Google Access on the subnets",)),
            "peered-service": ("blocker", "private services access needs its allocated range (ciamCidr)",
                               (f"Record the allocated range (ciamCidr), {RECORD}",)),
            "gateway": ("blocker", "Google Cloud has no gateway endpoints",
                        (f"Record it as an all-apis endpoint (ciamPrivateEndpointKind), {RECORD}",)),
            "interface": ("blocker", "a PSC endpoint to a published service needs the service attachment it connects "
                          "to", ("Create the endpoint by hand to the service attachment it connects to",))}


def psc_name(cn):
    """A PSC forwarding rule's name for Google's APIs: 1-20 lowercase letters and digits, a letter first."""
    n = re.sub(r"[^a-z0-9]", "", cn.lower())
    return (n if n[:1].isalpha() else "p" + n)[:20]


SERVICE_NETWORKING = "servicenetworking.googleapis.com"


def peering_connection_id(m):
    """The import id of environment m's network's service networking connection (<network>:<service>)."""
    net = one(one_role(m, "network"), "ciamProviderRef")
    return f"{resource_id(net)}:{SERVICE_NETWORKING}" if net else None


def _peered_service(m, p):
    """Private services access: the allocated range as a VPC_PEERING global address (named by its provider ref, else
    after the binding) and the service networking connection reserving it."""
    n = tf_name(rdn_value(p))
    address, _, prefix = one(p, "ciamCidr").partition("/")
    name = name_parts(one(p, "ciamProviderRef")).get("addresses") or f"ciam-{rdn_value(m.env)}-{rdn_value(p)}"
    return (tf_block("resource", ["google_compute_global_address", n], [
                ("name", name), *network_project(m), ("purpose", "VPC_PEERING"), ("address_type", "INTERNAL"),
                ("address", address), ("prefix_length", int(prefix or 32)), ("network", NETWORK),
                ("description", f"Private services access ({one(p, 'ciamPrivateService')}) for {m.label}"),
                ("labels", {"role": label(one(p, "ciamBindingRole")), "managed_by": "opsdir"})]),
            tf_block("resource", ["google_service_networking_connection", n], [
                ("network", NETWORK), ("service", SERVICE_NETWORKING),
                ("reserved_peering_ranges", [ref(f"google_compute_global_address.{n}.name")])]))


def _dns_note(m, p, ip):
    return network_note(m, p, "action", f"private DNS: the landing zone's private googleapis.com zone answers {ip} "
                        "for it", (f"Have the landing zone's private googleapis.com zone answer {ip} (its keeper)",))


def endpoint_notes(m, p):
    """The render notes of private endpoint p as private_endpoint writes them: a kind it doesn't render (NOT_HERE),
    the landing zone's private googleapis.com zone answering a PSC endpoint's address (an action); none when it is
    UNBOUND."""
    kind, ip = one(p, "ciamPrivateEndpointKind", "all-apis"), one(p, "ciamFrontendIp")
    if kind == "peered-service" and one(p, "ciamCidr"):
        return ()
    if kind != "all-apis":
        severity, text, how = NOT_HERE[kind]
        return (network_note(m, p, severity, f"{kind}: {text}: not rendered", how),)
    return (_dns_note(m, p, ip),) if ip and one(p, "ciamPrivateDns") == "TRUE" else ()


def private_endpoint(m, p):
    """A Private Service Connect endpoint for Google's APIs, or private services access with its allocated range;
    its notes' comments for the kinds the landing zone keeps or that need more than the record says, and for private
    DNS (endpoint_notes)."""
    n, kind = tf_name(rdn_value(p)), one(p, "ciamPrivateEndpointKind", "all-apis")
    if kind == "peered-service" and one(p, "ciamCidr"):
        return _peered_service(m, p)
    if kind != "all-apis":
        return tuple(comment(note_comment(x)) for x in endpoint_notes(m, p))
    ip = one(p, "ciamFrontendIp")
    if not ip:
        return (comment(f"UNBOUND: private endpoint '{rdn_value(p)}' to Google's APIs records no address "
                        "(ciamFrontendIp)"),)
    dns = (comment(note_comment(_dns_note(m, p, ip))),) if one(p, "ciamPrivateDns") == "TRUE" else ()
    return (*dns,
            tf_block("resource", ["google_compute_global_address", n], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(p)}"), *network_project(m),
                ("purpose", "PRIVATE_SERVICE_CONNECT"), ("address_type", "INTERNAL"), ("network", NETWORK),
                ("address", ip), ("labels", {"role": label(one(p, "ciamBindingRole")), "managed_by": "opsdir"})]),
            tf_block("resource", ["google_compute_global_forwarding_rule", n], [
                ("name", psc_name(rdn_value(p))), *network_project(m), ("target", "all-apis"), ("network", NETWORK),
                ("ip_address", ref(f"google_compute_global_address.{n}.id")), ("load_balancing_scheme", "")]))


def _accept(principal):
    """A consumer accept list entry: a network by its URL, else a project by id or number."""
    who = (("network_url", principal),) if "/networks/" in principal else \
        (("project_id_or_num", principal.removeprefix("projects/")),)
    return Block((*who, ("connection_limit", 10)))


def attachment_note(m, e, svc, endpoints=()):
    """The render note (a blocker) of an endpoint service whose service name isn't an internal passthrough load
    balancer (no private address, layer 7 or a CDN): a service attachment needs one; else None."""
    if svc is None:
        return None
    spec, ip = service_edge(m, svc, endpoints), one(svc, "ciamFrontendIp")
    if ip and is_private(ip) and not (spec is not None and (spec.layer7 or spec.cdn)):
        return None
    return network_note(m, e, "blocker", f"{rdn_value(svc)} isn't an internal passthrough load balancer; a service "
                        "attachment here needs one: not rendered",
                        ("Expose a service name on an internal passthrough load balancer (a private address, layer 4, "
                         f"no CDN in its protection policy), or connect its consumers another way, {RECORD}",))


def service_attachment(m, e, svc, endpoints=()):
    """A service attachment on the internal passthrough forwarding rule of the service name it exposes; a comment when
    the name isn't bound, its note's when it is public or runs on an application load balancer (attachment_note)."""
    role = one(e, "ciamServiceRole")
    if svc is None:
        return (comment(f"UNBOUND: endpoint service '{rdn_value(e)}' exposes {role}, which this environment doesn't "
                        "bind"),)
    noted = attachment_note(m, e, svc, endpoints)
    if noted is not None:
        return (comment(note_comment(noted)),)
    manual, nat = one(e, "ciamAcceptanceRequired") == "TRUE", subnets(m, e)
    return (tf_block("resource", ["google_compute_service_attachment", tf_name(rdn_value(e))], [
        ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(e)}"), ("region", REGION),
        ("description", f"{one(svc, 'ciamFqdn')} for other networks ({m.label})"),
        ("enable_proxy_protocol", False),
        ("connection_preference", "ACCEPT_MANUAL" if manual else "ACCEPT_AUTOMATIC"),
        ("nat_subnets", [ref(f"data.google_compute_subnetwork.{tf_name(rdn_value(s))}.id") for s in nat]) if nat
        else ("#", "UNBOUND: no PSC NAT subnet recorded (ciamSubnetRole)"),
        ("target_service", ref(f"google_compute_forwarding_rule.{tf_name(rdn_value(svc))}.id")),
        *((("consumer_accept_lists", _accept(pr)) for pr in values(e, "ciamAllowedPrincipal"))
          if manual else ())]),)


def egress_note(m, proxy):
    """The render note (a blocker) of an egress firewall on a network that keeps VPC firewall rules (which have no
    FQDN rules), else None."""
    if firewall_model(m) == "policy":
        return None
    return network_note(m, proxy, "blocker", "FQDN egress rules exist only in network firewall policies, and the "
                        "network keeps VPC firewall rules: not rendered",
                        (f"Set the network's firewall model to policy (ciamFirewallModel), {RECORD}",))


def egress(m, proxy):
    """An egress firewall's allowlist as network firewall policy rules, or its note's comment when the network keeps
    VPC firewall rules (egress_note)."""
    noted = egress_note(m, proxy)
    return (comment(note_comment(noted)),) if noted is not None else egress_rules(m, proxy)


def network_notes(m, endpoints=()):
    """The render notes of environment m's network depth the stack renders (render_network): its own private
    endpoints', endpoint services' and egress firewalls'."""
    return (*(x for p in private_endpoints(m) for x in endpoint_notes(m, p)),
            *(x for x in (*(attachment_note(m, e, svc, endpoints) for e, svc in endpoint_services(m)),
                          *(egress_note(m, f) for f in egress_firewalls(m))) if x is not None))


def render_network(m, endpoints=()):
    """HCL blocks for environment m's network depth the stack keeps, after comments naming what others keep; () when
    the record has none."""
    return (*(comment(s) for s in elsewhere(m)),
            *(x for p in private_endpoints(m) for x in private_endpoint(m, p)),
            *(x for e, svc in endpoint_services(m) for x in service_attachment(m, e, svc, endpoints)),
            *(x for f in egress_firewalls(m) for x in egress(m, f)))


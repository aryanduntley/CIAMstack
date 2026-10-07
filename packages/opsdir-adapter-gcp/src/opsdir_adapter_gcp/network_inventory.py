"""What Google Cloud's networks carry beyond networks, subnetworks and VPC firewall rules, read back in the network
domain's terms (hashicorp/google attribute names; Cloud Asset Inventory and gcloud items normalize to them). Pure.

  google_compute_network_firewall_policy    -> firewall policy (scope network): which the network evaluates first
    (+ its association, the network's          (the network's network_firewall_policy_enforcement_order)
    enforcement order)
  google_compute_network_firewall_policy_   -> firewall rules (the policy model): ingress allow rules by rule name,
    rule                                       sources, single ports, priority, the policy they belong to, the role
                                               of the instances their target secure tags are bound to (else the tag
                                               value's short name); probe and proxy-only-subnet rules are the load
                                               balancers'; egress allow rules naming sites (dest_fqdns) are the
                                               policy's egress allowlist (a proxy kind firewall, the policy its
                                               provider ref); other egress and deny rules are the allowlist's own
  google_tags_tag_key (purpose GCE_FIREWALL) -> the network policy's tag key reference (ciamTagKeyRef) when someone
                                               else made it (one whose description doesn't say opsdir made it)
  google_compute_firewall_policy (+ rules)  -> firewall policy (scope hierarchical): read, never rendered; its rules
                                               named, not recorded
  google_compute_route                      -> one route table per network (Google Cloud's routes are network-wide):
                                               '<destination> <kind> [<target>] [for <roles>]', the roles those of
                                               the instances carrying the route's network tags; next hop the internet
                                               gateway, an appliance (an address or instance), an internal load
                                               balancer (gateway-lb), a VPN tunnel
  google_compute_global_address (purpose    -> private endpoint all-apis: Private Service Connect for Google's APIs
    PRIVATE_SERVICE_CONNECT) + global          (its forwarding rule the provider ref, the address its frontend; role
    forwarding rule to all-apis / vpc-sc       from the address's label role)
  google_compute_global_address (purpose    -> private endpoint peered-service: private services access, its
    VPC_PEERING)                               allocated range (address/prefix_length) its ciamCidr; what it serves
                                               the record says (the address doesn't)
  google_compute_service_attachment         -> endpoint service: the forwarding rule it exposes, its URI for
                                               consumers, the projects and networks it accepts (acceptance required
                                               unless it accepts automatically), its PSC NAT subnets
  google_compute_network_peering,           -> interconnect depth: peering (active: the other side accepted), VPN
    google_compute_vpn_tunnel (+ router,       (peer address, BGP numbers), dedicated (an interconnect attachment)
    router peer), google_compute_
    interconnect_attachment
  google_compute_subnetwork log_config      -> flow log (scope subnet) of a subnetwork that logs its flows
Roles: label role (or bindingrole) where the resource has labels. Routes, peerings and subnetworks can't be labelled:
a network's routes take the role routes, a peering peering-<the peer network's name> (its other side the environment
whose network binding is the peer network: core), a subnet's flow logs flow-logs-<the subnet's role> (core). The same
roles in every environment, so the planner compares them across a move.
"""
import re
from collections import Counter

from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.network.routing import Route, route_text
from opsdir_format_terraform.state import blocks, first_block
from .health_checks import is_probe_rule
from .names import MANAGED, name_parts, resource_id, state_labels

OWN_KEY = re.compile(r"^ciam-[a-z0-9-]+-role$")      # the short name of the tag key the render makes
ROUTES = "routes"          # the role of a network's routes: Google Cloud's routes can't be labelled
GOOGLE_APIS = ("all-apis", "vpc-sc")            # what a Private Service Connect endpoint for Google's APIs targets
ORDER = {"BEFORE_CLASSIC_FIREWALL": "policy-first", "AFTER_CLASSIC_FIREWALL": "rules-first"}
HTTPS = 443


def _labels(a):
    return a.get("labels") or {}


def _role(a):
    labels = _labels(a)
    return tagged_role({k: labels[low] for k, low in (("Role", "role"), ("BindingRole", "bindingrole"))
                        if labels.get(low)})


def google_apis_endpoint(fr):
    """Whether a forwarding rule is a Private Service Connect endpoint for Google's APIs (not a service name)."""
    return (fr.get("target") or "") in GOOGLE_APIS


# ------------------------------------------------------------------ firewall policies
def _tag_value_roles(found, instance_roles):
    """{tag value (tagValues/...): role}: the role of the instances it is bound to, else its short name."""
    short = {resource_id(v.get("id") or v.get("name")): v.get("short_name")
             for v in of_types(found, "google_tags_tag_value")}
    bound = {}
    for b in of_types(found, "google_tags_location_tag_binding"):
        instance = resource_id((b.get("parent") or "").split("/compute.googleapis.com/", 1)[-1])
        role = instance_roles.get(instance) or instance_roles.get(instance.rsplit("/", 1)[-1])
        if role:
            bound.setdefault(resource_id(b.get("tag_value")), Counter())[role] += 1
    return {**{v: s for v, s in short.items() if s},
            **{v: c.most_common(1)[0][0] for v, c in bound.items()}}


def _policy_ref(found, given):
    """A policy rule's policy (its name or ID) as the policy's resource name."""
    policies = {p.get("name"): resource_id(p.get("id"))
                for p in of_types(found, "google_compute_network_firewall_policy")}
    return policies.get(given) or resource_id(given)


def _match(rule):
    return first_block(rule.get("match"))


def _ports(match):
    """(single ports, why not for the others) of a match's layer 4 configs."""
    configs = blocks(match.get("layer4_configs"))
    singles = sorted({str(p) for c in configs for p in c.get("ports") or () if "-" not in str(p)}, key=int)
    why = [*(f"port range {p}" for c in configs for p in c.get("ports") or () if "-" in str(p)),
           *("all ports" for c in configs if not c.get("ports"))]
    return singles, why


def _site(host, port):
    return host if str(port) == str(HTTPS) else f"{host}:{port}"


def policy_rules(found, instance_roles, proxies):
    """(firewall rules, egress allowlists {policy: sites}, notices) of the network firewall policies' rules."""
    roles = _tag_value_roles(found, instance_roles)
    rules = [r for r in of_types(found, "google_compute_network_firewall_policy_rule") if not r.get("disabled")]
    ingress = [r for r in rules if (r.get("direction") or "INGRESS") == "INGRESS" and r.get("action") == "allow"
               and not is_probe_rule(_match(r).get("src_ip_ranges"))
               and not (_match(r).get("src_ip_ranges") and set(_match(r)["src_ip_ranges"]) <= proxies)]

    def name(r):
        return r.get("rule_name") or f"{(r.get('firewall_policy') or '').rsplit('/', 1)[-1]}-{r.get('priority')}"

    def target(r):
        found_roles = Counter(roles[resource_id(t.get("name"))] for t in blocks(r.get("target_secure_tags"))
                              if resource_id(t.get("name")) in roles)
        return found_roles.most_common(1)[0][0] if found_roles else None
    egress = [(r, p) for r in rules if r.get("direction") == "EGRESS" and r.get("action") == "allow"
              for p in (_ports(_match(r))[0] or [HTTPS]) if _match(r).get("dest_fqdns")]
    sites = {}
    for r, port in egress:
        policy = _policy_ref(found, r.get("firewall_policy"))
        sites[policy] = (*sites.get(policy, ()), *(_site(h, port) for h in _match(r)["dest_fqdns"]))
    notices = (*(f"firewall policy rule {name(r)}: {why}, not a single port; not recorded"
                 for r in ingress for why in dict.fromkeys(_ports(_match(r))[1])),
               *(f"firewall policy rule {name(r)}: source secure tags; not recorded"
                 for r in ingress if _match(r).get("src_secure_tags")),
               *(f"firewall policy rule {name(r)}: a {r.get('action')} rule; not recorded" for r in rules
                 if (r.get("direction") or "INGRESS") == "INGRESS" and r.get("action") not in ("allow", None)))
    return (tuple(resource("firewall", name(r), {
                "ciamSourceCidr": sorted(_match(r).get("src_ip_ranges") or ()), "ciamPort": _ports(_match(r))[0],
                "ciamProtocol": next((c.get("ip_protocol") for c in blocks(_match(r).get("layer4_configs"))
                                      if c.get("ip_protocol") in ("tcp", "udp")), None),
                "ciamTargetRole": target(r), "ciamRulePriority": r.get("priority")},
                links={"ciamPolicyRole": _policy_ref(found, r.get("firewall_policy"))}, name=name(r), role=None)
                  for r in ingress),
            {p: tuple(dict.fromkeys(s)) for p, s in sites.items()}, notices)


def _own_key(k):
    """Whether opsdir's render made a tag key: its description says so, or its short name is the render's
    (ciam-<env>-role)."""
    return MANAGED in (k.get("description") or "") or bool(OWN_KEY.match(k.get("short_name") or ""))


def _key_network(k):
    """The network a firewall tag key is for (purpose_data network: <project>/<network>, or a URL), as
    (project, network), or None when it names none."""
    given = resource_id((k.get("purpose_data") or {}).get("network") or "")
    parts = name_parts(given)
    if "projects" in parts:
        return parts.get("projects"), parts.get("networks")
    return tuple(given.split("/", 1)) if "/" in given else None


def foreign_tag_keys(found):
    """The firewall tag keys (purpose GCE_FIREWALL) someone else made for the environment's networks: not the render's
    own (description mark, short name) and not for another network (a key the record references rather than
    renders)."""
    networks = {(name_parts(resource_id(n.get("id"))).get("projects"), n.get("name"))
                for n in of_types(found, "google_compute_network")}
    return tuple(resource_id(k.get("id") or k.get("name")) for k in of_types(found, "google_tags_tag_key")
                 if k.get("purpose") == "GCE_FIREWALL" and not _own_key(k)
                 and (_key_network(k) is None or not networks or _key_network(k) in networks))


def _policies(found, sites):
    networks = {resource_id(n.get("id")): n for n in of_types(found, "google_compute_network")}
    attached = {_policy_ref(found, a.get("firewall_policy")): resource_id(a.get("attachment_target"))
                for a in of_types(found, "google_compute_network_firewall_policy_association")}

    def order(ref):
        network = networks.get(attached.get(ref)) or {}
        return ORDER.get(network.get("network_firewall_policy_enforcement_order"))
    keys = foreign_tag_keys(found)
    network_policies = tuple(resource("firewall-policy", resource_id(p.get("id")), {
        "ciamPolicyScope": "network", "ciamPolicyOrder": order(resource_id(p.get("id"))),
        "ciamTagKeyRef": keys[0] if len(keys) == 1 else None},
        name=p.get("name"), role=None)
        for p in of_types(found, "google_compute_network_firewall_policy") if p.get("id"))
    hierarchical = tuple(resource("firewall-policy", resource_id(p.get("id") or p.get("name")),
                                  {"ciamPolicyScope": "hierarchical"}, name=p.get("short_name") or p.get("name"),
                                  role=None)
                         for p in of_types(found, "google_compute_firewall_policy") if p.get("id") or p.get("name"))
    proxies = tuple(resource("proxy", policy, {"ciamProxyKind": "firewall", "ciamAllowedDestination": hosts},
                             name=policy.rsplit("/", 1)[-1], role=None) for policy, hosts in sites.items())
    return (*network_policies, *hierarchical, *proxies)


# ------------------------------------------------------------------ routes, endpoints, links, flow logs
def _route(r, tag_roles):
    hop = (("internet", "") if (r.get("next_hop_gateway") or "").endswith("default-internet-gateway") else
           ("appliance", r["next_hop_ip"]) if r.get("next_hop_ip") else
           ("appliance", resource_id(r["next_hop_instance"])) if r.get("next_hop_instance") else
           ("gateway-lb", resource_id(r["next_hop_ilb"])) if r.get("next_hop_ilb") else
           ("vpn", resource_id(r["next_hop_vpn_tunnel"])) if r.get("next_hop_vpn_tunnel") else None)
    roles = tuple(sorted({tag_roles[t] for t in r.get("tags") or () if t in tag_roles}))
    return Route(r.get("dest_range"), hop[0], hop[1], roles) if hop and r.get("dest_range") else None


def _routes(found, tag_roles):
    networks = dict.fromkeys(resource_id(r.get("network")) for r in of_types(found, "google_compute_route")
                             if r.get("network"))
    return tuple(resource("route-table", f"{network}/routes", {"ciamRoute": tuple(dict.fromkeys(
        route_text(x) for x in (_route(r, tag_roles) for r in of_types(found, "google_compute_route")
                                if resource_id(r.get("network")) == network) if x))},
        name=f"{network.rsplit('/', 1)[-1]}-routes", role=ROUTES) for network in networks)


def _google_apis(found):
    addresses = {a.get("address"): a for a in of_types(found, "google_compute_global_address")
                 if a.get("purpose") == "PRIVATE_SERVICE_CONNECT"}
    by_id = {resource_id(a.get("id")): a for a in addresses.values()}

    def one(fr):
        address = by_id.get(resource_id(fr.get("ip_address"))) or addresses.get(fr.get("ip_address")) or {}
        return resource("private-endpoint", resource_id(fr.get("id")), {
            "ciamPrivateService": "apis", "ciamPrivateEndpointKind": "all-apis",
            "ciamFrontendIp": address.get("address") or fr.get("ip_address")},
            name=fr.get("name"), role=_role(address) or _role(fr), tags=state_labels(fr))
    return tuple(one(fr) for fr in of_types(found, "google_compute_global_forwarding_rule")
                 if google_apis_endpoint(fr) and fr.get("id"))


def _peered_services(found):
    return tuple(resource("private-endpoint", resource_id(a.get("id")), {
                     "ciamPrivateEndpointKind": "peered-service",
                     "ciamCidr": f"{a.get('address')}/{a.get('prefix_length')}" if a.get("address") else None},
                          name=a.get("name"), role=_role(a), tags=state_labels(a))
                 for a in of_types(found, "google_compute_global_address")
                 if a.get("purpose") == "VPC_PEERING" and a.get("id"))


def _last(v):
    return resource_id(v or "").rsplit("/", 1)[-1]


def _accepted(entry):
    return entry.get("network_url") or entry.get("project_id_or_num")


def _attachments(found):
    def one(s):
        manual = s.get("connection_preference") == "ACCEPT_MANUAL"
        return resource("endpoint-service", resource_id(s.get("id")), {
            "ciamServiceAlias": resource_id(s.get("id")), "ciamAcceptanceRequired": "TRUE" if manual else "FALSE",
            "ciamAllowedPrincipal": tuple(a for a in map(_accepted, blocks(s.get("consumer_accept_lists"))) if a)},
            links={"ciamServiceRole": resource_id(s.get("target_service")),
                   "ciamSubnetRole": tuple(resource_id(n) for n in s.get("nat_subnets") or ())},
            name=s.get("name"), role=_role(s))
    return tuple(one(s) for s in of_types(found, "google_compute_service_attachment") if s.get("id"))


def _links(found):
    routers = {resource_id(r.get("id")): r for r in of_types(found, "google_compute_router")}
    peers = {resource_id(p.get("router")): p for p in of_types(found, "google_compute_router_peer")}

    def link(a, ref, kind, text, extra=None, network=None, role=None, labeled=True):
        return resource("interconnect", ref, {"ciamLinkKind": kind, "ciamInterconnectKind": text, **(extra or {})},
                        links={"ciamPeerEnvironment": network}, name=a.get("name"), role=_role(a) or role,
                        tags=state_labels(a) if labeled else None)        # a peering takes no labels

    def tunnel(t):
        router = resource_id(t.get("router"))
        return link(t, resource_id(t.get("id")), "vpn", "Cloud VPN", {
            "ciamPeerGateway": t.get("peer_ip"),
            "ciamLocalAsn": first_block((routers.get(router) or {}).get("bgp")).get("asn"),
            "ciamPeerAsn": (peers.get(router) or {}).get("peer_asn")})
    return tuple(r for r in (
        *(link(p, f"{resource_id(p.get('network'))}/peerings/{p.get('name')}", "peering", "VPC peering",
               {"ciamPeerAccepted": None if not p.get("state") else "TRUE" if p.get("state") == "ACTIVE" else "FALSE"},
               (resource_id(p.get("peer_network")), _last(p.get("peer_network"))),    # recorded by name or in full
               f"peering-{_last(p.get('peer_network'))}", labeled=False)
          for p in of_types(found, "google_compute_network_peering") if p.get("name") and p.get("network")),
        *(tunnel(t) for t in of_types(found, "google_compute_vpn_tunnel") if t.get("id")),
        *(link(a, resource_id(a.get("id")), "dedicated", "Cloud Interconnect attachment")
          for a in of_types(found, "google_compute_interconnect_attachment") if a.get("id"))) if r.ref)


def _flow_logs(found):
    return tuple(resource("flow-log", f"{resource_id(s.get('id'))}/logConfig", {"ciamFlowScope": "subnet"},
                          links={"ciamSubnetRole": resource_id(s.get("id"))}, name=f"{s.get('name')}-flow-logs",
                          role=None)
                 for s in of_types(found, "google_compute_subnetwork")
                 if s.get("id") and first_block(s.get("log_config")) and
                 first_block(s.get("log_config")).get("enable", True) is not False)


def network_resources(found, instance_roles, tag_roles, proxies):
    """(resources, notices) of the network depth among (google resource type, attributes) pairs; instance_roles
    ({instance resource name or numeric ID: role}) and tag_roles ({network tag: role}) give the roles firewall
    policies and routes target, proxies the proxy-only subnets' ranges (rules admitting only them are the load
    balancers')."""
    rules, sites, notices = policy_rules(found, instance_roles, proxies)
    hierarchical_rules = of_types(found, "google_compute_firewall_policy_rule")
    keys = foreign_tag_keys(found)
    return ((*rules, *_policies(found, sites), *_routes(found, tag_roles), *_google_apis(found),
             *_peered_services(found), *_attachments(found), *_links(found), *_flow_logs(found)),
            (*notices, *((f"hierarchical firewall policy rules ({len(hierarchical_rules)}): read, not recorded",)
                         if hierarchical_rules else ()),
             *((f"firewall tag keys not made by opsdir ({', '.join(keys)}): which one the network policy targets by "
                "is the record's to say; not recorded",) if len(keys) > 1 else ())))

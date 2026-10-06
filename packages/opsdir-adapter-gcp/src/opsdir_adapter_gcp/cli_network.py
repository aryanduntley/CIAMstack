"""What Cloud Asset Inventory and gcloud report about an environment's network depth, normalized to the hashicorp/google
attribute names the shared mapping reads (opsdir_adapter_gcp.network_inventory). Pure.

  compute.googleapis.com/NetworkFirewallPolicy,      gcloud compute network-firewall-policies describe: a network
    FirewallPolicy                                   policy with its rules and associations; a hierarchical one
                                                     (gcloud compute firewall-policies describe) under an
                                                     organization or folder, by its self link
  compute.googleapis.com/Route                       gcloud compute routes list
  compute.googleapis.com/ServiceAttachment           gcloud compute service-attachments list
  compute.googleapis.com/VpnTunnel                   gcloud compute vpn-tunnels list
  compute.googleapis.com/InterconnectAttachment      gcloud compute interconnects attachments list
  cloudresourcemanager.googleapis.com/TagKey,        gcloud resource-manager tags keys list / values list
    TagValue
  tag bindings                                       gcloud resource-manager tags bindings list --parent=<instance>
                                                     (--location=<zone>), by their names (tagBindings/...)
  the networks' peerings and firewall policy enforcement order, subnetworks' flow log settings, routers' BGP numbers
  and peers, Cloud NAT's address allocation, global addresses for Private Service Connect and private services access
  (VPC_PEERING): read from the network, subnetwork, router and address items the main reader recognizes
  (opsdir_adapter_gcp.cli)
"""
from types import MappingProxyType

from .names import resource_id

KINDS = MappingProxyType({
    **{f"compute.googleapis.com/{t}": "firewall-policy"
       for t in ("FirewallPolicy", "NetworkFirewallPolicy", "RegionNetworkFirewallPolicy")},
    "compute#firewallPolicy": "firewall-policy",
    "compute.googleapis.com/Route": "route", "compute#route": "route",
    "compute.googleapis.com/ServiceAttachment": "service-attachment", "compute#serviceAttachment": "service-attachment",
    "compute.googleapis.com/VpnTunnel": "vpn-tunnel", "compute#vpnTunnel": "vpn-tunnel",
    "compute.googleapis.com/InterconnectAttachment": "interconnect-attachment",
    "compute#interconnectAttachment": "interconnect-attachment",
    "cloudresourcemanager.googleapis.com/TagValue": "tag-value",
    "cloudresourcemanager.googleapis.com/TagKey": "tag-key",
    "compute.googleapis.com/GlobalForwardingRule": "forwarding-rule",
    "compute.googleapis.com/GlobalAddress": "address"})


def network_shape(item):
    """What a gcloud item without a kind is when it is a tag key, value or binding, by its name; else None."""
    name = item.get("name") or ""
    return {"tagValues": "tag-value", "tagBindings": "tag-binding", "tagKeys": "tag-key"}.get(name.split("/", 1)[0])


def _self(d):
    return resource_id(d.get("selfLink") or d.get("name"))


def _match(m):
    return [{"src_ip_ranges": m.get("srcIpRanges") or [], "dest_ip_ranges": m.get("destIpRanges") or [],
             "dest_fqdns": m.get("destFqdns") or [], "src_secure_tags": m.get("srcSecureTags") or [],
             "layer4_configs": [{"ip_protocol": c.get("ipProtocol"), "ports": c.get("ports") or []}
                                for c in m.get("layer4Configs") or ()]}]


def _rule(policy, r):
    return {"firewall_policy": policy, "priority": r.get("priority"), "direction": r.get("direction"),
            "action": r.get("action"), "rule_name": r.get("ruleName"), "description": r.get("description"),
            "disabled": r.get("disabled"), "match": _match(r.get("match") or {}),
            "target_secure_tags": [{"name": t.get("name")} for t in r.get("targetSecureTags") or ()]}


def _hierarchical(d):
    return bool(d.get("parent")) or _self(d).startswith("locations/")


def _policies(of):
    policies = [d for d, _ in of("firewall-policy")]
    return [*(x for d in policies if not _hierarchical(d) for x in (
                ("google_compute_network_firewall_policy", {"id": _self(d), "name": d.get("name")}),
                *(("google_compute_network_firewall_policy_rule", _rule(_self(d), r)) for r in d.get("rules") or ()),
                *(("google_compute_network_firewall_policy_association", {
                    "firewall_policy": _self(d), "attachment_target": resource_id(a.get("attachmentTarget"))})
                  for a in d.get("associations") or ()))),
            *(x for d in policies if _hierarchical(d) for x in (
                ("google_compute_firewall_policy", {"id": _self(d), "short_name": d.get("shortName") or d.get("name")}),
                *(("google_compute_firewall_policy_rule", {"firewall_policy": _self(d)})
                  for _ in d.get("rules") or ())))]


def _routing(of):
    return [("google_compute_route", {
        "id": _self(d), "name": d.get("name"), "network": resource_id(d.get("network")),
        "dest_range": d.get("destRange"),
        "next_hop_gateway": resource_id(d.get("nextHopGateway")), "next_hop_ip": d.get("nextHopIp"),
        "next_hop_instance": resource_id(d.get("nextHopInstance")), "next_hop_ilb": resource_id(d.get("nextHopIlb")),
        "next_hop_vpn_tunnel": resource_id(d.get("nextHopVpnTunnel")), "tags": d.get("tags") or [],
        "priority": d.get("priority")})
        for d, _ in of("route") if not d.get("nextHopPeering")]          # a peering's routes: the peering's


def _endpoints(of):
    return [*(("google_compute_global_address", {"id": _self(d), "name": d.get("name"), "address": d.get("address"),
                                                 "purpose": d.get("purpose"), "prefix_length": d.get("prefixLength"),
                                                 "labels": d.get("labels") or {}})
              for d, _ in of("address") if d.get("purpose") in ("PRIVATE_SERVICE_CONNECT", "VPC_PEERING")
              and not d.get("region")),
            *(("google_compute_service_attachment", {
                "id": _self(d), "name": d.get("name"), "target_service": resource_id(d.get("targetService")),
                "connection_preference": d.get("connectionPreference"),
                "nat_subnets": [resource_id(n) for n in d.get("natSubnets") or ()],
                "consumer_accept_lists": [{"project_id_or_num": c.get("projectIdOrNum"),
                                           "network_url": resource_id(c.get("networkUrl"))}
                                          for c in d.get("consumerAcceptLists") or ()]})
              for d, _ in of("service-attachment"))]


def _links(of):
    return [*(("google_compute_network_peering", {"name": p.get("name"), "network": _self(d), "state": p.get("state"),
                                                  "peer_network": resource_id(p.get("network"))})
              for d, _ in of("network") for p in d.get("peerings") or ()),
            *(("google_compute_vpn_tunnel", {"id": _self(d), "name": d.get("name"), "peer_ip": d.get("peerIp"),
                                             "router": resource_id(d.get("router")), "labels": d.get("labels") or {}})
              for d, _ in of("vpn-tunnel")),
            *(("google_compute_router", {"id": _self(d), "bgp": [{"asn": (d.get("bgp") or {}).get("asn")}]})
              for d, _ in of("router") if d.get("bgp")),
            *(("google_compute_router_peer", {"router": _self(d), "peer_asn": p.get("peerAsn")})
              for d, _ in of("router") for p in d.get("bgpPeers") or ()),
            *(("google_compute_interconnect_attachment", {"id": _self(d), "name": d.get("name"),
                                                          "labels": d.get("labels") or {}})
              for d, _ in of("interconnect-attachment"))]


def _tags(of):
    return [*(("google_tags_tag_key", {"id": d.get("name"), "short_name": d.get("shortName"),
                                       "purpose": d.get("purpose"), "description": d.get("description"),
                                       "purpose_data": d.get("purposeData") or {}})
              for d, _ in of("tag-key")),
            *(("google_tags_tag_value", {"id": d.get("name"), "short_name": d.get("shortName"),
                                         "parent": d.get("parent")}) for d, _ in of("tag-value")),
            *(("google_tags_location_tag_binding", {"parent": d.get("parent"), "tag_value": d.get("tagValue")})
              for d, _ in of("tag-binding"))]


def network_pairs(of):
    """(google resource type, attributes) pairs of the network depth; of(kind) gives the recognized items of a kind
    ((data, origin), ...)."""
    return [*_policies(of), *_routing(of), *_endpoints(of), *_links(of), *_tags(of)]

"""Infrastructure's import kinds (core.contract.ImportKind): what the cloud importers read into networks, subnets,
servers, service names, firewall rules, object stores, egress and interconnects, and how core.inventory matches each
to the record. Pure.

  network      -> ciamNetwork          matched by provider ref (the VPC or virtual network); placed first
  subnet       -> ciamSubnetBinding    matched by provider ref; placed first
  server       -> ciamServer           matched by name, hostname or private address (the record keeps no instance IDs)
  service      -> ciamServiceName      matched by the service's DNS name (a load balancer and its record)
  firewall     -> ciamFirewallRule     matched by the rule's name
  storage      -> ciamObjectStore      matched by storage reference (a backup target is one too)
  egress       -> ciamEgress           matched by provider ref (the NAT gateway)
  interconnect -> ciamInterconnect     matched by provider ref (a peering, a transit attachment, a VPN); its other
                                       side's environment is the one whose network binding has the peer network's
                                       provider ref (else a tag PeerEnvironment: <cloud>/<env>; a new link needs one)
"""
from ...core.contract import ImportKind
from ...core.directory import get, is_kind, norm_dn, one
from ...core.overlays import lineage

PEER = "ciamPeerEnvironment"         # an interconnect's link to its other side's network (its environment is the value)


def peer(d, dn, r):
    """An interconnect with the environment on its other side: a link naming the peer network's provider ref (or
    candidates: a peering names both of its networks, a network its full and short name) is read as the environment,
    outside dn's lineage, whose network binding has that ref (case aside: Azure's IDs ignore it); a tag the source
    gives (ciamPeerEnvironment) wins. Without such a link, the resource as it is."""
    if PEER not in r.links:
        return r
    refs = {x.lower() for x in (r.links[PEER] if isinstance(r.links[PEER], tuple) else (r.links[PEER],))}
    mine = {norm_dn(e.dn) for e in lineage(d, get(d, dn))}
    found = {e.dn.split(",ou=bindings,", 1)[1] for e in d.entries.values()
             if is_kind(d, e, "ciamNetwork") and (one(e, "ciamProviderRef") or "").lower() in refs
             and ",ou=bindings," in e.dn
             and norm_dn(e.dn.split(",ou=bindings,", 1)[1]) not in mine}
    given = {} if PEER in r.attrs or len(found) != 1 else {PEER: tuple(found)}
    return r._replace(attrs={**r.attrs, **given}, links={k: v for k, v in r.links.items() if k != PEER})


IMPORT_KINDS = (
    ImportKind("network", "ciamNetwork", ("ciamCidr",), first=True),
    ImportKind("subnet", "ciamSubnetBinding", ("ciamCidr",), first=True),
    ImportKind("server", "ciamServer", ("ciamHostname", "ciamSubnet"), match="name", server=True),
    ImportKind("service", "ciamServiceName", ("ciamFqdn", "ciamTargetRole", "ciamPort"), match="ciamFqdn", lower=True),
    ImportKind("firewall", "ciamFirewallRule", ("ciamSourceCidr", "ciamPort", "ciamTargetRole"), match="name"),
    ImportKind("storage", "ciamObjectStore", ("ciamStorageRef",), match="ciamStorageRef"),
    ImportKind("egress", "ciamEgress", ("ciamCidr",)),
    ImportKind("interconnect", "ciamInterconnect", ("ciamInterconnectKind", PEER, "ciamSourceCidr"), prepare=peer),
)

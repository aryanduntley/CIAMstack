"""An environment's network plumbing, read neutrally for the cloud adapters' landing-zone renders: the bindings the
platform's own Terraform doesn't keep (its NAT egress, route tables, network ACLs, interconnects and flow logs always;
private endpoints and egress firewalls when ciamManagedBy names someone else), grouped by who keeps them. The landing
zone's owner keeps what names no one else, in terraform/landing-zone/; each other party named keeps its own root in
terraform/landing-zone/<party>/, applied by that team (governance.keepers decides who and where). A binding with a
provider ref already exists (the render adopts it with an import block); one without is still to be built, which the
planner asks its keeper for. Pure."""
from typing import NamedTuple, Optional

from ...core.directory import children, get, is_kind, one, rdn_value, values
from ...core.environment import EnvModel, of_class, one_role
from ...core.naming import env_label
from ..governance.keepers import LANDING_ZONE, keeper
from .stack import owned

NETWORK_FILE = "network.tf"
# what is always the landing zone's (or the party ciamManagedBy names), in render order
PLUMBING = ("ciamEgress", "ciamRouteTable", "ciamNetworkAcl", "ciamInterconnect", "ciamFlowLog")
# what is the stack's own unless ciamManagedBy names someone else
KEPT_ELSEWHERE = ("ciamPrivateEndpoint", "ciamProxy")

# name: who keeps it (as findings name owners); folder: the Terraform root it renders into; party: their entry (None
# when the record names none); bindings: what they keep, in PLUMBING order; takes: whether the default render gives
# them that root (governance.keepers)
Keeper = NamedTuple("Keeper", [("name", str), ("folder", str), ("party", Optional[object]), ("bindings", tuple),
                               ("takes", bool)])


def plumbing(m: EnvModel):
    """Environment m's bindings a landing zone or another keeper renders: its plumbing, then the private endpoints and
    egress firewalls with domain rules someone else keeps."""
    elsewhere = (b for oc in KEPT_ELSEWHERE for b in of_class(m, oc) if not owned(b)
                 and (oc != "ciamProxy" or one(b, "ciamProxyKind") == "firewall"))
    return (*(b for oc in PLUMBING for b in of_class(m, oc)), *elsewhere)


def keepers(m: EnvModel):
    """(Keeper, ...) of environment m's plumbing, the landing zone's owner first, then each other party in order: the
    landing zone's keeper unless ciamManagedBy names another party (governance.keepers.keeper)."""
    found = tuple((keeper(m, b, landing_zone=True), b) for b in plumbing(m))
    folders = sorted(dict.fromkeys(k.folder for k, _ in found), key=lambda f: (f != LANDING_ZONE, f))
    return tuple(Keeper(k.name, k.folder, k.party, tuple(b for k_, b in found if k_.folder == f), k.takes)
                 for f in folders for k in (next(k for k, _ in found if k.folder == f),))


def adopted(b):
    """Whether a binding already exists (its provider ref is recorded), so a render adopts it rather than creates it."""
    return one(b, "ciamProviderRef") is not None


def route_target(m, route):
    """The binding a route's target names by role in environment m, or None (no target, or a provider ref)."""
    return one_role(m, route.target) if route.target else None


def peer_network(d, link):
    """The network binding of the environment at the other end of an interconnect, or None."""
    peer = one(link, "ciamPeerEnvironment")
    return next(iter(children(d, f"ou=bindings,{peer}", "ciamNetwork")), None) if peer else None


def peer_cloud(d, link):
    """The cloud entry (provider, region) of the environment at the other end of an interconnect, or None."""
    peer = one(link, "ciamPeerEnvironment")
    return get(d, peer.split(",", 1)[1]) if peer and "," in peer else None


def describe(m, b):
    """A binding of the plumbing in words, for a request to its keeper."""
    name, subnets = rdn_value(b), ", ".join(f"`{s}`" for s in values(b, "ciamSubnetRole"))
    on = f" for subnets {subnets}" if subnets else ""
    if is_kind(m.d, b, "ciamEgress"):
        return f"NAT egress `{name}` sending from {', '.join(values(b, 'ciamCidr'))}"
    if is_kind(m.d, b, "ciamRouteTable"):
        main = " (the network's main table)" if one(b, "ciamMainTable") == "TRUE" else ""
        return f"Route table `{name}`{main}{on}: {'; '.join(values(b, 'ciamRoute'))}"
    if is_kind(m.d, b, "ciamNetworkAcl"):
        return f"Network ACL `{name}`{on} ({len(values(b, 'ciamAclRule'))} rules)"
    if is_kind(m.d, b, "ciamInterconnect"):
        peer = one(b, "ciamPeerEnvironment")
        return (f"{one(b, 'ciamLinkKind') or one(b, 'ciamInterconnectKind')} `{name}` to "
                f"{env_label(peer) if peer else 'the peer'}")
    if is_kind(m.d, b, "ciamFlowLog"):
        days = one(b, "ciamRetentionDays")
        return (f"Flow log `{name}` ({one(b, 'ciamFlowScope')}{on}) to `{one(b, 'ciamLogDestinationRole')}`"
                + (f", kept {days} days" if days else ""))
    if is_kind(m.d, b, "ciamPrivateEndpoint"):
        return f"Private endpoint `{name}` to {one(b, 'ciamPrivateService')}{on}"
    return f"Domain allowlist of egress firewall `{name}` ({len(values(b, 'ciamAllowedDestination'))} sites)"


def plumbing_requests(m, by=None):
    """((party, text, by), ...) asking each keeper of environment m's plumbing for what isn't built yet (no provider
    ref): where everything they keep is rendered, then each item. Keepers the record names no party for are left out
    (plumbing_unasked says so)."""
    return tuple(r for k in keepers(m) if k.party is not None
                 for todo in ([b for b in k.bindings if not adopted(b)],) if todo
                 for r in ((k.party, f"Everything you keep for {m.label} is rendered in `{k.folder}/` (what already "
                            "exists carries import blocks, so you can adopt it into your state).", by),
                           *((k.party, f"{describe(m, b)}: to set up (`{k.folder}/{NETWORK_FILE}`).", by)
                             for b in todo)))


def plumbing_unasked(m):
    """(Keeper, ...) of environment m with plumbing still to build but no party recorded to ask."""
    return tuple(k for k in keepers(m) if k.party is None and any(not adopted(b) for b in k.bindings))

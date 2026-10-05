"""What a cloud says an environment runs, read into the environment's servers and bindings. Pure and neutral: each cloud
adapter parses its own sources (Terraform state, its CLI's inventories, its native templates) into Resources, and
this module places them.

  network   -> ciamNetwork          matched by provider ref (the VPC or virtual network)
  subnet    -> ciamSubnetBinding    matched by provider ref
  server    -> ciamServer           matched by name, hostname or private address (the record keeps no instance IDs)
  service   -> ciamServiceName      matched by the service's DNS name (a load balancer and its record)
  firewall  -> ciamFirewallRule     matched by the rule's name
  secret    -> ciamSecretRef        matched by reference URI (never a value)
  key       -> ciamKeyRef           matched by reference URI
  storage   -> ciamObjectStore      matched by storage reference (a backup target is one too)
  egress    -> ciamEgress           matched by provider ref (the NAT gateway)
  job       -> ciamJobBinding       matched by provider ref (a function, a pipeline: what realizes a job)
  compute   -> ciamComputeGroup     matched by provider ref (an autoscaling group, a scale set)
  cluster   -> ciamCluster          matched by provider ref (a managed Kubernetes cluster)
  sending   -> ciamSendingIdentity  matched by provider ref (an email sending identity for a domain)
  stream    -> ciamStreamBinding    matched by provider ref (a queue, topic or bus carrying an event stream)
  channel   -> ciamAlertChannel     matched by provider ref (a topic or action group alarms notify)
  logs      -> ciamLogDestination   matched by provider ref (a log group, a workspace)
  alarm     -> ciamAlarmBinding     matched by provider ref (an alarm the cloud runs: the alert rule it realizes)
  canary    -> ciamCanaryBinding    matched by provider ref (a synthetic check the cloud runs)
  identity  -> ciamIdentityBinding  matched by provider ref, else by the identity's short name (an IAM role's name, a
                                    resource ID's last segment, a service account's account id)
  guardrail -> ciamGuardrail        matched by provider ref (a control policy, a policy assignment, a constraint)
  access    -> ciamAccessPath       matched by provider ref (single sign-on, a bastion, a proxy)
  edge      -> ciamEdgeService      matched by provider ref (a web application firewall, a CDN, DDoS protection); a
                                    new one without a role takes '<its kind>-<role of the service it fronts>'
  zone      -> ciamDnsZoneBinding   matched by the zone's name
  record    -> ciamDnsRecord        matched by the record's name and type
  forwarder -> ciamDnsForwarder     matched by the domains it forwards
  route-table      -> ciamRouteTable       matched by provider ref (a route table; Google Cloud's routes of a network)
  acl              -> ciamNetworkAcl       matched by provider ref (a stateless network ACL)
  private-endpoint -> ciamPrivateEndpoint  matched by provider ref (a VPC endpoint, a private endpoint, a PSC endpoint)
  endpoint-service -> ciamEndpointService  matched by provider ref (an endpoint service, a Private Link Service, a
                                           service attachment)
  proxy            -> ciamProxy            matched by provider ref (a firewall with domain rules, a web proxy)
  flow-log         -> ciamFlowLog          matched by provider ref (a flow log, a subnet's flow log setting); a new
                                           one without a role takes 'flow-logs-<role of its subnet>'
  firewall-policy  -> ciamFirewallPolicy   matched by provider ref (a network or hierarchical firewall policy)
  interconnect     -> ciamInterconnect     matched by provider ref (a peering, a transit attachment, a VPN); its other
                                           side's environment is the one whose network binding has the peer network's
                                           provider ref (else a tag PeerEnvironment: <cloud>/<env>; a new link needs one)
What a source says replaces the record's value for the attributes it gives; the rest of the entry is kept (the same
values in another order, or an allowlist a source reports without the ports it can't express, change nothing). A
resource the record doesn't have is added only when the source names its role (a tag), and is named otherwise: a role
can't be guessed. A binding an overlay inherits from its base is left to the base environment. A link to another
resource names its entry (a DN), or for a role link (ciamEncryptedByRole, ciamSubnetRole, ...) the binding role that
entry has; a link may name several resources (a route table's subnets). A route's target, written as the provider's
reference (0.0.0.0/0 nat nat-0abc), becomes the role of the binding with that reference when the source reports it.

Sources are laid out one folder per environment, <cloud>/<env>/ (layout_import); the cloud adapter says what it reads
there and parses each file. A role map beside them, <cloud>/<env>/roles.json ({provider ref or name: role}), gives roles
to resources the cloud can't tag (subnets and security rules in Azure, for instance); where the source names a role
itself, the source's is kept.
"""
import json
import re
from functools import reduce
from types import MappingProxyType
from typing import Mapping, NamedTuple, Optional

from .contract import Imported
from .directory import children, get, is_kind, is_subclass, make_entry, norm_dn, one, ou_entry, rdn_value
from .environment import env_dn
from .overlays import lineage

# One resource a cloud reports: its kind, the provider's reference for it, the record attributes the source gives,
# links to other resources by their provider refs ({attribute: ref}), and hints for a new entry's name and role.
Resource = NamedTuple("Resource", [("kind", str), ("ref", str), ("attrs", Mapping), ("links", Mapping),
                                   ("name", Optional[str]), ("role", Optional[str])])

CLASSES = MappingProxyType({"network": "ciamNetwork", "subnet": "ciamSubnetBinding", "server": "ciamServer",
                            "service": "ciamServiceName", "firewall": "ciamFirewallRule", "secret": "ciamSecretRef",
                            "key": "ciamKeyRef", "storage": "ciamObjectStore", "egress": "ciamEgress",
                            "job": "ciamJobBinding", "compute": "ciamComputeGroup", "cluster": "ciamCluster",
                            "sending": "ciamSendingIdentity", "stream": "ciamStreamBinding",
                            "channel": "ciamAlertChannel", "logs": "ciamLogDestination", "alarm": "ciamAlarmBinding",
                            "canary": "ciamCanaryBinding", "identity": "ciamIdentityBinding",
                            "guardrail": "ciamGuardrail", "access": "ciamAccessPath", "edge": "ciamEdgeService",
                            "zone": "ciamDnsZoneBinding", "record": "ciamDnsRecord", "forwarder": "ciamDnsForwarder",
                            "route-table": "ciamRouteTable", "acl": "ciamNetworkAcl",
                            "private-endpoint": "ciamPrivateEndpoint", "endpoint-service": "ciamEndpointService",
                            "proxy": "ciamProxy", "flow-log": "ciamFlowLog", "firewall-policy": "ciamFirewallPolicy",
                            "interconnect": "ciamInterconnect"})
BY_REF = ("network", "subnet", "egress", "job", "compute", "cluster", "sending", "stream", "channel", "logs", "alarm",
          "canary", "identity", "guardrail", "access", "edge", "route-table", "acl", "private-endpoint",
          "endpoint-service", "proxy", "flow-log", "firewall-policy", "interconnect")    # matched by provider ref
# links naming the linked binding's role, not its DN, and the kind of resource each names (two kinds may share a
# provider ref: a firewall policy and the egress allowlist it enforces)
ROLE_KINDS = MappingProxyType({"ciamEncryptedByRole": "key", "ciamServiceRole": "service", "ciamSubnetRole": "subnet",
                               "ciamPolicyRole": "firewall-policy", "ciamLogDestinationRole": "logs"})
ROLE_LINKS = frozenset(ROLE_KINDS)
PEER = "ciamPeerEnvironment"         # an interconnect's link to its other side's network (its environment is the value)
ROUTE_TARGET = 2                     # the token of a ciamRoute value naming its target (a role, else a provider ref)
# attributes whose values may carry a port a source can't express (a firewall's domain list): when the source reports
# none, the record's values with their ports are the same as the source's without
PORTED = frozenset({"ciamAllowedDestination"})
_PORT = re.compile(r":[0-9]+$")
ROLE_MAP = "roles.json"                         # <cloud>/<env>/roles.json: roles for what a cloud can't tag
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def resource(kind, ref, attrs=None, links=None, name=None, role=None):
    """A Resource, dropping attributes and links the source left empty."""
    clean = {k: tuple(str(x) for x in (v if isinstance(v, (list, tuple)) else (v,)) if x not in (None, ""))
             for k, v in (attrs or {}).items()}
    return Resource(kind, ref, {k: v for k, v in clean.items() if v},
                    {k: v for k, v in (links or {}).items() if v}, name, role)


def _key(e, kind):
    """What a record entry of this kind is matched by."""
    if kind in BY_REF:
        return one(e, "ciamProviderRef")
    if kind in ("secret", "key"):
        return one(e, "ciamRefUri")
    if kind == "storage":
        return one(e, "ciamStorageRef")
    if kind == "service":
        return (one(e, "ciamFqdn") or "").lower()
    if kind in ("zone", "record", "forwarder"):
        return _dns_key(kind, e.attrs)
    return rdn_value(e).lower()


def _dns_key(kind, attrs):
    """What a DNS zone, record or forwarder is matched by: its zone name; its name and type; the domains it
    forwards."""
    def names(attr):
        return tuple(sorted(v.lower().rstrip(".") for v in attrs.get(attr) or ()))
    if kind == "zone":
        return "|".join(names("ciamDnsZone")) or None
    if kind == "record":
        return "|".join((*names("ciamRecordName"), *(attrs.get("ciamRecordType") or ()))) or None
    return "|".join(names("ciamForwardDomain")) or None


def _resource_key(r):
    if r.kind in BY_REF:
        return r.ref
    if r.kind in ("secret", "key"):
        return (r.attrs.get("ciamRefUri") or (None,))[0]
    if r.kind == "storage":
        return (r.attrs.get("ciamStorageRef") or (None,))[0]
    if r.kind == "service":
        return ((r.attrs.get("ciamFqdn") or ("",))[0]).lower()
    if r.kind in ("zone", "record", "forwarder"):
        return _dns_key(r.kind, r.attrs)
    return (r.name or "").lower()


def _held(d, dn):
    """The environment's own servers and bindings, and those it inherits from its bases."""
    own = (*children(d, dn, "ciamServer"), *children(d, f"ou=bindings,{dn}"))
    bases = tuple(e for base in lineage(d, get(d, dn))[1:]
                  for e in (*children(d, base.dn, "ciamServer"), *children(d, f"ou=bindings,{base.dn}")))
    return own, bases


def short_name(ref):
    """An identity's short name from its provider ref: an IAM role's name, a resource ID's last segment, a service
    account's account id (lowercase)."""
    return (ref or "").rsplit("/", 1)[-1].split("@", 1)[0].lower() or None


def _match(d, r, entries):
    oc = CLASSES[r.kind]
    candidates = [e for e in entries if is_kind(d, e, oc)]
    key = _resource_key(r)
    found = next((e for e in candidates if key and _key(e, r.kind) == key), None)
    if found is None and r.kind == "identity" and short_name(r.ref):
        found = next((e for e in candidates if short_name(one(e, "ciamProviderRef")) == short_name(r.ref)), None)
    if found is not None or r.kind != "server":
        return found
    host, ip = (r.attrs.get("ciamHostname") or (None,))[0], (r.attrs.get("ciamPrivateIp") or (None,))[0]
    return next((e for e in candidates if (host and (one(e, "ciamHostname") or "").lower() == host.lower())
                 or (ip and one(e, "ciamPrivateIp") == ip)), None)


# what a new entry of each kind must have (its class's required attributes, beyond cn and its role)
REQUIRED = MappingProxyType({
    "network": ("ciamCidr",), "subnet": ("ciamCidr",), "server": ("ciamHostname", "ciamSubnet"),
    "service": ("ciamFqdn", "ciamTargetRole", "ciamPort"), "firewall": ("ciamSourceCidr", "ciamPort", "ciamTargetRole"),
    "secret": ("ciamRefUri",), "key": ("ciamRefUri",), "storage": ("ciamStorageRef",), "egress": ("ciamCidr",),
    "job": (), "compute": ("ciamTargetRole",), "cluster": (), "sending": ("ciamSenderDomain",), "stream": (),
    "channel": ("ciamChannelKind",), "logs": ("ciamDestinationKind",), "alarm": (), "canary": (), "identity": (),
    "guardrail": ("ciamGuardrailKind",), "access": ("ciamAccessKind",), "edge": ("ciamEdgeKind",),
    "zone": ("ciamDnsZone", "ciamZoneVisibility"), "record": ("ciamRecordName", "ciamRecordType"),
    "forwarder": ("ciamForwardDomain", "ciamForwardTarget"), "route-table": ("ciamRoute",), "acl": ("ciamAclRule",),
    "private-endpoint": ("ciamPrivateService",), "endpoint-service": ("ciamServiceRole",),
    "proxy": ("ciamProxyKind",), "flow-log": ("ciamFlowScope",), "firewall-policy": ("ciamPolicyScope",),
    "interconnect": ("ciamInterconnectKind", "ciamPeerEnvironment", "ciamSourceCidr")})


def zone_role(zone):
    """The binding role a DNS zone takes when its source names none, the same in every environment."""
    return f"zone-{zone.lower().rstrip('.')}" if zone else None


def record_role(name, record_type):
    """The binding role a DNS record takes when its source names none."""
    return f"record-{record_type.lower()}-{name.lower().rstrip('.')}" if name and record_type else None


def forwarder_role(domains):
    """The binding role a DNS forwarder takes when its source names none: by the first domain it forwards."""
    first = sorted(d.lower().rstrip(".") for d in domains or () if d)
    return f"forwarder-{first[0]}" if first else None


def _first_ref(link):
    return link[0] if isinstance(link, tuple) and link else link if isinstance(link, str) else None


def _derived_role(r, roles):
    """A new resource's role from the role of what it links to, when its source names none: an edge service's from the
    service it fronts ('<kind>-<service role>'), a flow log's from its subnet ('flow-logs-<subnet role>'); else None."""
    if r.kind == "edge":
        fronted = roles.get(_first_ref(r.links.get("ciamServiceRole")))
        return f"{r.attrs['ciamEdgeKind'][0]}-{fronted}" if fronted and "ciamEdgeKind" in r.attrs else None
    if r.kind == "flow-log":
        subnet = roles.get(_first_ref(r.links.get("ciamSubnetRole")))
        return f"flow-logs-{subnet}" if subnet else None
    return None


def _peer(d, dn, r):
    """An interconnect with the environment on its other side: a link naming the peer network's provider ref (or
    candidates: a peering names both of its networks, a network its full and short name) is read as the environment,
    outside dn's lineage, whose network binding has that ref (case aside: Azure's IDs ignore it); a tag the source
    gives (ciamPeerEnvironment) wins. Other resources as they are."""
    if r.kind != "interconnect" or PEER not in r.links:
        return r
    refs = {x.lower() for x in (r.links[PEER] if isinstance(r.links[PEER], tuple) else (r.links[PEER],))}
    mine = {norm_dn(e.dn) for e in lineage(d, get(d, dn))}
    found = {e.dn.split(",ou=bindings,", 1)[1] for e in d.entries.values()
             if is_kind(d, e, "ciamNetwork") and (one(e, "ciamProviderRef") or "").lower() in refs
             and ",ou=bindings," in e.dn
             and norm_dn(e.dn.split(",ou=bindings,", 1)[1]) not in mine}
    given = {} if PEER in r.attrs or len(found) != 1 else {PEER: tuple(found)}
    return r._replace(attrs={**r.attrs, **given}, links={k: v for k, v in r.links.items() if k != PEER})


def _resolved(links, attr, ref):
    """The DNs (or, for a role link, the roles of the entries of its kind) a link names: one ref, or a tuple of them;
    those the source doesn't report are left out."""
    table = {x: role for (kind, x), role in links["kinds"].items() if kind == ROLE_KINDS[attr]} \
        if attr in ROLE_LINKS else links[False]
    return tuple(dict.fromkeys(table[x] for x in (ref if isinstance(ref, tuple) else (ref,)) if x in table))


def _route_targets(routes, roles):
    """Route values with a target written as a provider ref replaced by the role of the binding with that ref."""
    def one_route(text):
        tokens = text.split(" ")
        return " ".join((*tokens[:ROUTE_TARGET], roles[tokens[ROUTE_TARGET]], *tokens[ROUTE_TARGET + 1:])) \
            if len(tokens) > ROUTE_TARGET and tokens[ROUTE_TARGET] in roles else text
    return tuple(one_route(v) for v in routes)


def _same(attr, reported, recorded):
    """Whether a source's values are the record's: the same set, or for a ported attribute reported without any port,
    the same set once the record's ports are left out."""
    if set(reported) == set(recorded):
        return True
    return attr in PORTED and not any(_PORT.search(v) for v in reported) and \
        {v.lower() for v in reported} == {_PORT.sub("", v).lower() for v in recorded}


def _entry(dn, r, held, links, name):
    linked = {attr: v for attr, ref in r.links.items() for v in (_resolved(links, attr, ref),) if v}
    routes = {"ciamRoute": _route_targets(r.attrs["ciamRoute"], links[True])} if "ciamRoute" in r.attrs else {}
    given = {**r.attrs, **routes, **linked, **({"ciamProviderRef": (r.ref,)} if r.kind in BY_REF and r.ref else {})}
    if held is not None:
        same = {k: held.attrs[k] for k, v in given.items() if k in held.attrs and _same(k, v, held.attrs[k])}
        return make_entry(held.dn, held.classes, {**{k: v for k, v in held.attrs.items() if k not in given}, **given,
                                                  **same})             # the same values in another order: no change
    role = {"ciamServerRole": (r.role,)} if r.kind == "server" else {"ciamBindingRole": (r.role,)}
    return make_entry(dn, ("top", CLASSES[r.kind]), {"cn": (name,), **role, **given})


def _new_dn(env, r, name):
    return f"cn={name},{env}" if r.kind == "server" else f"cn={name},ou=bindings,{env}"


def _label(d, dn):
    """'cloud/env' of the environment an entry belongs to."""
    parts = dict(p.split("=", 1) for p in dn.split(",") if p.split("=", 1)[0] in ("cloud", "env"))
    return f"{parts.get('cloud')}/{parts.get('env')}"


def _placed(d, own, bases):
    """((resource, own entry or None, inherited entry or None, name) for each resource), names never clashing."""
    def place(acc, r):
        held, inherited = _match(d, r, own), _match(d, r, bases)
        taken = {rdn_value(e).lower() for e in own} | {name.lower() for *_, name in acc}
        base = _UNSAFE.sub("-", r.name or r.ref or r.kind).strip("-") or r.kind
        name = rdn_value(held) if held else next(n for n in (base, *(f"{base}-{i}" for i in range(2, 1000)))
                                                if n.lower() not in taken)
        return (*acc, (r, held, inherited, name))
    return place


def environment_groups(d, spec, resources, summarize=()):
    """((DN, (entry,)), ...) and notices placing the resources a cloud reports into the environment spec names. Kinds in
    summarize (those an account-wide listing reports beyond the environment: secrets, keys, buckets) are counted, not
    listed one by one, when they are new and name no role."""
    dn = env_dn(spec)
    if get(d, dn) is None:
        return (), (f"{spec}: no such environment in the record; nothing imported",)
    own, bases = _held(d, dn)
    ordered = sorted((_peer(d, dn, r) for r in resources), key=lambda r: (r.kind not in ("network", "subnet"), r.kind,
                                                                         r.ref))
    first = reduce(_placed(d, own, bases), ordered, ())
    known = {**{r.ref: one(held or inh, "ciamBindingRole") for r, held, inh, _ in first if held or inh},
             **{r.ref: r.role for r, held, inh, _ in first if not (held or inh) and r.role}}
    placed = tuple((r._replace(role=_derived_role(r, known)) if not (held or inh) and r.role is None else r,
                    held, inh, name) for r, held, inh, name in first)
    new = [(r, name) for r, held, inh, name in placed if held is None and inh is None]
    dns = {**{r.ref: (held or inh).dn for r, held, inh, _ in placed if held or inh},
           **{r.ref: _new_dn(dn, r, name) for r, name in new if r.role}}
    roles = {**{r.ref: role for r, held, inh, _ in placed if held or inh
                for role in (one(held or inh, "ciamBindingRole"),) if role},
             **{r.ref: r.role for r, _ in new if r.role}}
    kinds = {**{(r.kind, r.ref): role for r, held, inh, _ in placed if held or inh
                for role in (one(held or inh, "ciamBindingRole"),) if role},
             **{(r.kind, r.ref): r.role for r, _ in new if r.role}}
    links = {False: dns, True: roles, "kinds": kinds}       # DN links; role links by ref (routes) and by kind
    incomplete = {id(r): [a for a in REQUIRED[r.kind] if a not in r.attrs and a not in r.links]
                  for r, _ in new if r.role}
    unresolved = {id(r): [a for a, ref in r.links.items() if not _resolved(links, a, ref) and a not in ROLE_LINKS]
                  for r, _ in new if r.role}
    added = [(r, name) for r, name in new if r.role and not incomplete[id(r)] and not unresolved[id(r)]]
    entries = (*(_entry(held.dn, r, held, links, name) for r, held, inh, name in placed if held is not None),
               *(_entry(_new_dn(dn, r, name), r, None, links, name) for r, name in added))
    reported = {held.norm for _, held, _, _ in placed if held is not None}
    kinds = {CLASSES[r.kind] for r in resources}
    notices = (*(f"{spec}: {r.kind} {r.name or r.ref} is inherited from {_label(d, inh.dn)}; unchanged here"
                 for r, held, inh, _ in placed if held is None and inh is not None),
               *(f"{spec}: {r.kind} {r.name or r.ref} ({_summary(r)}) is not in the record and names no role "
                 f"(tag it Role, name it in {ROLE_MAP}, or record it); not imported"
                 for r, _ in new if not r.role and r.kind not in summarize),
               *_counted(spec, [r for r, _ in new if not r.role and r.kind in summarize]),
               *(f"{spec}: {r.kind} {r.name or r.ref} lacks {', '.join(incomplete[id(r)] + unresolved[id(r)])}; "
                 f"not imported" for r, _ in new if r.role and (incomplete[id(r)] or unresolved[id(r)])),
               *(f"{spec}: {r.kind} {name} added (role {r.role})" for r, name in added),
               *(f"{spec}: {rdn_value(e)} ({next(c for c in e.classes if any(is_subclass(d, c, k) for k in kinds))}) is in "
                 f"the record but not in what the cloud reports"
                 for e in own if e.norm not in reported and any(is_kind(d, e, k) for k in kinds)))
    return tuple((e.dn, (e,)) for e in entries), notices


def _counted(spec, unplaced):
    """One notice per kind for new, role-less resources of an account-wide listing, with a few names as examples."""
    kinds = dict.fromkeys(r.kind for r in unplaced)
    return tuple(f"{spec}: {len(of)} {kind} resource(s) not in the record and naming no role, e.g. "
                 f"{', '.join(r.name or r.ref for r in of[:3])} (tag them Role, name them in {ROLE_MAP}, or record "
                 f"them); not imported"
                 for kind in kinds for of in ([r for r in unplaced if r.kind == kind],))


def _summary(r):
    shown = ("ciamCidr", "ciamSourceCidr", "ciamPort", "ciamPrivateIp", "ciamFqdn", "ciamRefUri", "ciamStorageRef")
    return ", ".join(f"{k} {'|'.join(r.attrs[k])}" for k in shown if k in r.attrs) or r.ref


# ------------------------------------------------------------------ sources laid out as <cloud>/<env>/
def _environments(files, suffix):
    """{'cloud/env': (paths ending in suffix, one or a tuple of them, under <cloud>/<env>/)}, and such paths outside
    that layout (role maps are never sources)."""
    found = sorted(p for p in files if p.endswith(suffix) and p.rsplit("/", 1)[-1] != ROLE_MAP)
    placed = {p: "/".join(p.split("/")[:2]) for p in found if p.count("/") >= 2}
    return ({spec: tuple(p for p in found if placed.get(p) == spec) for spec in dict.fromkeys(placed.values())},
            tuple(p for p in found if p not in placed))


def peer_environment(tags):
    """The DN of the environment on the other side of a link, from its tag PeerEnvironment (<cloud>/<env>), or None."""
    spec = tags.get("PeerEnvironment") or ""
    return env_dn(spec) if spec.count("/") == 1 else None


def tagged_role(tags):
    """The role a cloud resource's tags name: Role, else BindingRole (None when it has neither)."""
    return tags.get("Role") or tags.get("BindingRole")


def compute_roles(tags):
    """(binding role, server role) a compute group's tags name: the server role it runs is its tag Role, its binding
    role its tag BindingRole, else compute-<server role> (so every cloud's group for a role binds the same role)."""
    target = tags.get("Role")
    return tags.get("BindingRole") or (f"compute-{target}" if target else None), target


def realization_roles(tags, prefix):
    """(binding role, what it realizes) an alarm's or synthetic check's tags name: its tag Realizes names the alert
    rule or canary it serves; its binding role is its tag Role or BindingRole, else <prefix>-<realizes> (so every
    cloud's alarm for a rule binds the same role), else None (named, not recorded)."""
    realizes = tags.get("Realizes")
    return tagged_role(tags) or (f"{prefix}-{realizes}" if realizes else None), realizes


def duration_text(seconds):
    """Seconds as the record writes a duration (30s, 5m, 2h, 1d: the largest unit that divides it), or None."""
    if not seconds:
        return None
    return next(f"{seconds // n}{u}" for n, u in ((86400, "d"), (3600, "h"), (60, "m"), (1, "s")) if seconds % n == 0)


def cluster_role(tags):
    """The binding role a managed cluster's tags name (BindingRole, else Role), else cluster."""
    return tagged_role(tags) or "cluster"


def of_types(found, *types):
    """The attributes of each found (resource type, attributes) pair of one of types, in order."""
    return tuple(a for t, a in found if t in types)


def _bindings_container(spec):
    return ou_entry(f"ou=bindings,{env_dn(spec)}")


def read_role_map(text):
    """({provider ref or name: role}, problem): a role map's contents, or a problem when it isn't a JSON object of
    strings."""
    try:
        doc = json.loads(text)
    except ValueError:
        return {}, "not JSON"
    if not isinstance(doc, dict) or not all(isinstance(k, str) and isinstance(v, str) and v for k, v in doc.items()):
        return {}, "not a JSON object of provider references or names to roles"
    return doc, None


def with_roles(resources, roles):
    """(resources, notices): resources without a role take the one the map gives for their provider ref or name; a map
    entry that disagrees with the source's role, or matches no resource, is named."""
    def given(r):
        return roles.get(r.ref) if r.ref in roles else roles.get(r.name)
    used = {k for r in resources for k in (r.ref, r.name) if k in roles}
    return (tuple(r._replace(role=given(r)) if r.role is None and given(r) else r for r in resources),
            (*(f"{ROLE_MAP}: {r.kind} {r.name or r.ref} has role {r.role} from the source; the map's {given(r)} not used"
               for r in resources if r.role and given(r) and given(r) != r.role),
             *(f"{ROLE_MAP}: {k} matches nothing the source reports" for k in roles if k not in used)))


def _roles_for(files, spec, resources):
    """(resources, notices) with the environment's role map applied, when it has one."""
    text = files.get(f"{spec}/{ROLE_MAP}")
    if text is None:
        return resources, ()
    roles, problem = read_role_map(text)
    if problem:
        return resources, (f"{spec}/{ROLE_MAP}: {problem}; not used",)
    placed, notices = with_roles(resources, roles)
    return placed, tuple(f"{spec}/{n}" for n in notices)


def per_file(parse_text):
    """A folder parser from a one-file parser: parse_text(text) -> (resources, notices) applied to each file."""
    def parse(texts):
        each = [parse_text(t) for _, t in sorted(texts.items())]
        return tuple(r for rs, _ in each for r in rs), tuple(n for _, ns in each for n in ns)
    return parse


def layout_import(files, d, provider, label, parse, suffix, what, example, summarize=()):
    """Imported: each <cloud>/<env>/ folder's files ending in suffix, parsed together by parse({path within the folder:
    text}) -> (resources, notices), placed into that environment's servers and bindings. Environments whose cloud's
    ciamCloudProvider isn't provider, and files outside the layout, are named, not imported. Each folder's roles.json,
    when present, gives roles to what the cloud can't tag; kinds in summarize are counted when unplaced (see
    environment_groups). label names the provider in notices ('AWS'); what names the source ('Terraform state');
    example is a file name for the layout hint ('terraform.tfstate')."""
    envs, stray = _environments(files, suffix)
    parsed = {spec: [parse({p[len(spec) + 1:]: files[p] for p in paths})] for spec, paths in envs.items()}
    wrong = [spec for spec in envs if get(d, env_dn(spec)) is not None
             and one(get(d, env_dn(spec).split(",", 1)[1]), "ciamCloudProvider") != provider]
    roled = {spec: _roles_for(files, spec, tuple(r for rs, _ in parsed[spec] for r in rs))
             for spec in envs if spec not in wrong}
    placed = {spec: environment_groups(d, spec, resources, summarize) for spec, (resources, _) in roled.items()}
    return Imported(
        containers=tuple(_bindings_container(spec) for spec in placed),
        groups=tuple(g for groups, _ in placed.values() for g in groups),
        notices=(*(n for spec in placed for _, ns in parsed[spec] for n in ns),
                 *(n for _, ns in roled.values() for n in ns),
                 *(n for _, ns in placed.values() for n in ns),
                 *(f"{spec}: not {'an' if label[:1] in 'AEIOU' else 'a'} {label} environment in the record; "
                   "not imported" for spec in wrong),
                 *(f"{p}: put each environment's {what} under <cloud>/<env>/ (e.g. source/prod/{example}); "
                   f"not imported" for p in stray),
                 *((f"no {what} found ({', '.join('*' + x for x in _suffixes(suffix))} under <cloud>/<env>/)",)
                   if not envs and not stray else ())))


def _suffixes(suffix):
    return suffix if isinstance(suffix, tuple) else (suffix,)

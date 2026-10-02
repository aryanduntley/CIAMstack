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
  storage   -> ciamBackupTarget     matched by storage reference
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
What a source says replaces the record's value for the attributes it gives; the rest of the entry is kept. A resource
the record doesn't have is added only when the source names its role (a tag), and is named otherwise: a role can't be
guessed. A binding an overlay inherits from its base is left to the base environment.

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
from .directory import children, get, make_entry, one, ou_entry, rdn_value
from .environment import env_dn
from .overlays import lineage

# One resource a cloud reports: its kind, the provider's reference for it, the record attributes the source gives,
# links to other resources by their provider refs ({attribute: ref}), and hints for a new entry's name and role.
Resource = NamedTuple("Resource", [("kind", str), ("ref", str), ("attrs", Mapping), ("links", Mapping),
                                   ("name", Optional[str]), ("role", Optional[str])])

CLASSES = MappingProxyType({"network": "ciamNetwork", "subnet": "ciamSubnetBinding", "server": "ciamServer",
                            "service": "ciamServiceName", "firewall": "ciamFirewallRule", "secret": "ciamSecretRef",
                            "key": "ciamKeyRef", "storage": "ciamBackupTarget", "egress": "ciamEgress",
                            "job": "ciamJobBinding", "compute": "ciamComputeGroup", "cluster": "ciamCluster",
                            "sending": "ciamSendingIdentity", "stream": "ciamStreamBinding",
                            "channel": "ciamAlertChannel", "logs": "ciamLogDestination", "alarm": "ciamAlarmBinding",
                            "canary": "ciamCanaryBinding"})
BY_REF = ("network", "subnet", "egress", "job", "compute", "cluster", "sending", "stream", "channel", "logs", "alarm",
          "canary")                                                                       # matched by provider ref
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
    return rdn_value(e).lower()


def _resource_key(r):
    if r.kind in BY_REF:
        return r.ref
    if r.kind in ("secret", "key"):
        return (r.attrs.get("ciamRefUri") or (None,))[0]
    if r.kind == "storage":
        return (r.attrs.get("ciamStorageRef") or (None,))[0]
    if r.kind == "service":
        return ((r.attrs.get("ciamFqdn") or ("",))[0]).lower()
    return (r.name or "").lower()


def _held(d, dn):
    """The environment's own servers and bindings, and those it inherits from its bases."""
    own = (*children(d, dn, "ciamServer"), *children(d, f"ou=bindings,{dn}"))
    bases = tuple(e for base in lineage(d, get(d, dn))[1:]
                  for e in (*children(d, base.dn, "ciamServer"), *children(d, f"ou=bindings,{base.dn}")))
    return own, bases


def _match(r, entries):
    oc = CLASSES[r.kind]
    candidates = [e for e in entries if oc in e.classes]
    key = _resource_key(r)
    found = next((e for e in candidates if key and _key(e, r.kind) == key), None)
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
    "channel": ("ciamChannelKind",), "logs": ("ciamDestinationKind",), "alarm": (), "canary": ()})


def _entry(dn, r, held, links, name):
    given = {**r.attrs, **{attr: (links[ref],) for attr, ref in r.links.items() if ref in links},
             **({"ciamProviderRef": (r.ref,)} if r.kind in BY_REF and r.ref else {})}
    if held is not None:
        same = {k: held.attrs[k] for k, v in given.items() if k in held.attrs and set(v) == set(held.attrs[k])}
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


def _placed(own, bases):
    """((resource, own entry or None, inherited entry or None, name) for each resource), names never clashing."""
    def place(acc, r):
        held, inherited = _match(r, own), _match(r, bases)
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
    ordered = sorted(resources, key=lambda r: (r.kind not in ("network", "subnet"), r.kind, r.ref))
    placed = reduce(_placed(own, bases), ordered, ())
    new = [(r, name) for r, held, inh, name in placed if held is None and inh is None]
    links = {**{r.ref: (held or inh).dn for r, held, inh, _ in placed if held or inh},
             **{r.ref: _new_dn(dn, r, name) for r, name in new if r.role}}
    incomplete = {id(r): [a for a in REQUIRED[r.kind] if a not in r.attrs and a not in r.links]
                  for r, _ in new if r.role}
    unresolved = {id(r): [a for a, ref in r.links.items() if ref not in links] for r, _ in new if r.role}
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
               *(f"{spec}: {rdn_value(e)} ({next(c for c in e.classes if c in kinds)}) is in the record but not in "
                 f"what the cloud reports" for e in own if e.norm not in reported and kinds & set(e.classes)))
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

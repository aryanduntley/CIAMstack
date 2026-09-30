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
What a source says replaces the record's value for the attributes it gives; the rest of the entry is kept. A resource
the record doesn't have is added only when the source names its role (a tag), and is named otherwise: a role can't be
guessed. A binding an overlay inherits from its base is left to the base environment.
"""
import re
from functools import reduce
from typing import Mapping, NamedTuple, Optional

from .directory import children, get, make_entry, one, rdn_value
from .environment import env_dn
from .overlays import lineage

# One resource a cloud reports: its kind, the provider's reference for it, the record attributes the source gives,
# links to other resources by their provider refs ({attribute: ref}), and hints for a new entry's name and role.
Resource = NamedTuple("Resource", [("kind", str), ("ref", str), ("attrs", Mapping), ("links", Mapping),
                                   ("name", Optional[str]), ("role", Optional[str])])

CLASSES = {"network": "ciamNetwork", "subnet": "ciamSubnetBinding", "server": "ciamServer",
           "service": "ciamServiceName", "firewall": "ciamFirewallRule", "secret": "ciamSecretRef",
           "key": "ciamKeyRef", "storage": "ciamBackupTarget", "egress": "ciamEgress"}
BY_REF = ("network", "subnet", "egress")       # kinds the record matches by the provider's reference
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
REQUIRED = {"network": ("ciamCidr",), "subnet": ("ciamCidr",), "server": ("ciamHostname", "ciamSubnet"),
            "service": ("ciamFqdn", "ciamTargetRole", "ciamPort"), "firewall": ("ciamSourceCidr", "ciamPort",
                                                                             "ciamTargetRole"),
            "secret": ("ciamRefUri",), "key": ("ciamRefUri",), "storage": ("ciamStorageRef",), "egress": ("ciamCidr",)}


def _entry(dn, r, held, links, name):
    given = {**r.attrs, **{attr: (links[ref],) for attr, ref in r.links.items() if ref in links},
             **({"ciamProviderRef": (r.ref,)} if r.kind in BY_REF and r.ref else {})}
    if held is not None:
        return make_entry(held.dn, held.classes, {**{k: v for k, v in held.attrs.items() if k not in given}, **given})
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


def environment_groups(d, spec, resources):
    """((DN, (entry,)), ...) and notices placing the resources a cloud reports into the environment spec names."""
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
                 f"(tag it Role, or record it); not imported" for r, _ in new if not r.role),
               *(f"{spec}: {r.kind} {r.name or r.ref} lacks {', '.join(incomplete[id(r)] + unresolved[id(r)])}; "
                 f"not imported" for r, _ in new if r.role and (incomplete[id(r)] or unresolved[id(r)])),
               *(f"{spec}: {r.kind} {name} added (role {r.role})" for r, name in added),
               *(f"{spec}: {rdn_value(e)} ({next(c for c in e.classes if c in kinds)}) is in the record but not in "
                 f"what the cloud reports" for e in own if e.norm not in reported and kinds & set(e.classes)))
    return tuple((e.dn, (e,)) for e in entries), notices


def _summary(r):
    shown = ("ciamCidr", "ciamSourceCidr", "ciamPort", "ciamPrivateIp", "ciamFqdn", "ciamRefUri", "ciamStorageRef")
    return ", ".join(f"{k} {'|'.join(r.attrs[k])}" for k in shown if k in r.attrs) or r.ref

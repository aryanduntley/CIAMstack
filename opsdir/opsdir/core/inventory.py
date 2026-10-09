"""What a cloud says an environment runs, read into the environment's servers and bindings. Pure and neutral: each cloud
adapter parses its own sources (Terraform state, its CLI's inventories, its native templates) into Resources, and
this module places them.

Which kinds there are, and how each is matched, is the domains' to declare (core.contract.ImportKind on each Domain,
merged by imports(); an import attaches the merged table to the snapshot it reads, with_imports): its object class,
what a new entry must have, what an entry is matched by (provider ref, name, an attribute, or a function of the
attributes), and what it derives or resolves; each domain's imports module lists its kinds (infrastructure's
networks, subnets, servers, service names, firewall rules, object stores, egress and interconnects; network's,
edge's, access's, and the kinds other domains declare in their Domain). Servers are placed under the environment and
matched also by hostname or private address; every other kind is a binding under ou=bindings.
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
from .directory import children, get, is_kind, is_subclass, make_entry, one, ou_entry, rdn_value
from .environment import env_dn
from .overlays import lineage

# One resource a cloud reports: its kind, the provider's reference for it, the record attributes the source gives,
# links to other resources by their provider refs ({attribute: ref}), hints for a new entry's name and role, and the
# tags (labels) the cloud reports on it, when the source gives them (None when it doesn't; {} when it has none).
Resource = NamedTuple("Resource", [("kind", str), ("ref", str), ("attrs", Mapping), ("links", Mapping),
                                   ("name", Optional[str]), ("role", Optional[str]), ("tags", Optional[Mapping])])

# How the installed domains read cloud resources into the record: kinds {kind: ImportKind} (core.contract), role_links
# {attribute naming a binding's role: the kind of what it names}, checks (the domains' import checks: (directory, spec,
# resources) -> notices). Built from the domains (imports); an import attaches it to the snapshot it reads
# (with_imports), so the core names no domain's classes.
Imports = NamedTuple("Imports", [("kinds", Mapping), ("role_links", Mapping), ("checks", tuple)])
_PORT = re.compile(r":[0-9]+$")
ROLE_MAP = "roles.json"                         # <cloud>/<env>/roles.json: roles for what a cloud can't tag
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def resource(kind, ref, attrs=None, links=None, name=None, role=None, tags=None):
    """A Resource, dropping attributes and links the source left empty."""
    clean = {k: tuple(str(x) for x in (v if isinstance(v, (list, tuple)) else (v,)) if x not in (None, ""))
             for k, v in (attrs or {}).items()}
    return Resource(kind, ref, {k: v for k, v in clean.items() if v},
                    {k: v for k, v in (links or {}).items() if v}, name, role,
                    MappingProxyType(dict(tags)) if tags is not None else None)


def imports(domains):
    """The Imports of these domains: their import kinds, role links and import checks, merged; refused when two declare
    the same kind or link."""
    kinds = [k for dom in domains for k in dom.import_kinds]
    links = [(a, kind) for dom in domains for a, kind in dom.role_links.items()]
    twice = sorted({k.kind for k in kinds if [x.kind for x in kinds].count(k.kind) > 1} |
                   {a for a, _ in links if [x for x, _ in links].count(a) > 1})
    if twice:
        raise ValueError(f"declared by more than one domain: {', '.join(twice)}")
    return Imports(MappingProxyType({k.kind: k for k in kinds}), MappingProxyType(dict(links)),
                   tuple(c for dom in domains for c in dom.import_checks))


def with_imports(d, table):
    """The snapshot d carrying the Imports an import places resources by."""
    return d._replace(imports=table)


def _imports(d):
    if d.imports is None:
        raise ValueError("the snapshot carries no import kinds (core.inventory.with_imports): nothing can be placed")
    return d.imports


def _match_key(k, attrs, ref, name):
    """What an entry or a resource of import kind k is matched by, from its attributes, provider ref and name."""
    if k.match == "ref":
        return ref
    if k.match == "name":
        return (name or "").lower()
    if callable(k.match):
        return k.match(attrs)
    value = (attrs.get(k.match) or ("",))[0]
    return value.lower() if k.lower else value


def _key(e, k):
    """What a record entry of import kind k is matched by."""
    return _match_key(k, e.attrs, one(e, "ciamProviderRef"), rdn_value(e))


def _resource_key(r, k):
    return _match_key(k, r.attrs, r.ref, r.name)


def _servers(d, dn):
    """The servers directly under an environment (of the import kinds placed as servers)."""
    return tuple(e for k in _imports(d).kinds.values() if k.server for e in children(d, dn, k.object_class))


def _held(d, dn):
    """The environment's own servers and bindings, and those it inherits from its bases."""
    own = (*_servers(d, dn), *children(d, f"ou=bindings,{dn}"))
    bases = tuple(e for base in lineage(d, get(d, dn))[1:]
                  for e in (*_servers(d, base.dn), *children(d, f"ou=bindings,{base.dn}")))
    return own, bases


def _match(d, r, entries):
    k = _imports(d).kinds[r.kind]
    candidates = [e for e in entries if is_kind(d, e, k.object_class)]
    key = _resource_key(r, k)
    found = next((e for e in candidates if key and _key(e, k) == key), None)
    if found is None and k.alias is not None and k.alias(r.ref):
        found = next((e for e in candidates if k.alias(one(e, "ciamProviderRef")) == k.alias(r.ref)), None)
    if found is not None or not k.server:
        return found
    host, ip = (r.attrs.get("ciamHostname") or (None,))[0], (r.attrs.get("ciamPrivateIp") or (None,))[0]
    return next((e for e in candidates if (host and (one(e, "ciamHostname") or "").lower() == host.lower())
                 or (ip and one(e, "ciamPrivateIp") == ip)), None)


def first_ref(link):
    """The first provider ref a link names (one ref, or a tuple of them), or None: what an import kind's role function
    reads a link by."""
    return link[0] if isinstance(link, tuple) and link else link if isinstance(link, str) else None


def _resolved(links, attr, ref):
    """The DNs (or, for a role link, the roles of the entries of its kind) a link names: one ref, or a tuple of them;
    those the source doesn't report are left out."""
    role_links = links["role_links"]
    wanted = role_links.get(attr)
    kinds = wanted if isinstance(wanted, tuple) else (wanted,)
    table = {x: role for (kind, x), role in links["kinds"].items() if kind in kinds} \
        if attr in role_links else links[False]
    return tuple(dict.fromkeys(table[x] for x in (ref if isinstance(ref, tuple) else (ref,)) if x in table))


def _same(attr, reported, recorded, ported=frozenset()):
    """Whether a source's values are the record's: the same set, or for a ported attribute reported without any port,
    the same set once the record's ports are left out."""
    if set(reported) == set(recorded):
        return True
    return attr in ported and not any(_PORT.search(v) for v in reported) and \
        {v.lower() for v in reported} == {_PORT.sub("", v).lower() for v in recorded}


def _entry(dn, r, k, held, links, name):
    linked = {attr: v for attr, ref in r.links.items() for v in (_resolved(links, attr, ref),) if v}
    resolved = k.resolve(r.attrs, links[True]) if k.resolve is not None else {}
    given = {**r.attrs, **resolved, **linked, **({"ciamProviderRef": (r.ref,)} if k.match == "ref" and r.ref else {})}
    if held is not None:
        same = {a: held.attrs[a] for a, v in given.items() if a in held.attrs and _same(a, v, held.attrs[a], k.ported)}
        return make_entry(held.dn, held.classes, {**{a: v for a, v in held.attrs.items() if a not in given}, **given,
                                                  **same})             # the same values in another order: no change
    role = {"ciamServerRole": (r.role,)} if k.server else {"ciamBindingRole": (r.role,)}
    return make_entry(dn, ("top", k.object_class), {"cn": (name,), **role, **given})


def _new_dn(env, r, k, name):
    return f"cn={name},{env}" if k.server else f"cn={name},ou=bindings,{env}"


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
    table = _imports(d)
    unread = sorted({r.kind for r in resources if r.kind not in table.kinds})
    resources = tuple(r for r in resources if r.kind in table.kinds)
    kind = table.kinds.__getitem__

    def prepared(r):
        return kind(r.kind).prepare(d, dn, r) if kind(r.kind).prepare is not None else r
    own, bases = _held(d, dn)
    ordered = sorted((prepared(r) for r in resources), key=lambda r: (not kind(r.kind).first, r.kind, r.ref))
    first = reduce(_placed(d, own, bases), ordered, ())
    known = {**{r.ref: one(held or inh, "ciamBindingRole") for r, held, inh, _ in first if held or inh},
             **{r.ref: r.role for r, held, inh, _ in first if not (held or inh) and r.role}}

    def derived(r):
        return kind(r.kind).role(r, known) if kind(r.kind).role is not None else None
    placed = tuple((r._replace(role=derived(r)) if not (held or inh) and r.role is None else r,
                    held, inh, name) for r, held, inh, name in first)
    new = [(r, name) for r, held, inh, name in placed if held is None and inh is None]
    dns = {**{r.ref: (held or inh).dn for r, held, inh, _ in placed if held or inh},
           **{r.ref: _new_dn(dn, r, kind(r.kind), name) for r, name in new if r.role}}
    roles = {**{r.ref: role for r, held, inh, _ in placed if held or inh
                for role in (one(held or inh, "ciamBindingRole"),) if role},
             **{r.ref: r.role for r, _ in new if r.role}}
    kinds = {**{(r.kind, r.ref): role for r, held, inh, _ in placed if held or inh
                for role in (one(held or inh, "ciamBindingRole"),) if role},
             **{(r.kind, r.ref): r.role for r, _ in new if r.role}}
    # DN links; role links by ref (routes) and by kind
    links = {False: dns, True: roles, "kinds": kinds, "role_links": table.role_links}
    incomplete = {id(r): [a for a in kind(r.kind).required if a not in r.attrs and a not in r.links]
                  for r, _ in new if r.role}
    unresolved = {id(r): [a for a, ref in r.links.items() if not _resolved(links, a, ref)
                          and a not in table.role_links] for r, _ in new if r.role}
    added = [(r, name) for r, name in new if r.role and not incomplete[id(r)] and not unresolved[id(r)]]
    entries = (*(_entry(held.dn, r, kind(r.kind), held, links, name) for r, held, inh, name in placed
                 if held is not None),
               *(_entry(_new_dn(dn, r, kind(r.kind), name), r, kind(r.kind), None, links, name) for r, name in added))
    reported = {held.norm for _, held, _, _ in placed if held is not None}
    kinds = {kind(r.kind).object_class for r in resources}
    notices = (*(f"{spec}: {k} resources: no installed domain reads them; not imported" for k in unread),
               *(f"{spec}: {r.kind} {r.name or r.ref} is inherited from {_label(d, inh.dn)}; unchanged here"
                 for r, held, inh, _ in placed if held is None and inh is not None),
               *(f"{spec}: {r.kind} {r.name or r.ref} ({_summary(r)}) is not in the record and names no role "
                 f"(tag it Role, name it in {ROLE_MAP}, or record it); not imported"
                 for r, _ in new if not r.role and r.kind not in summarize),
               *_counted(spec, [r for r, _ in new if not r.role and r.kind in summarize]),
               *(f"{spec}: {r.kind} {r.name or r.ref} lacks {', '.join(incomplete[id(r)] + unresolved[id(r)])}; "
                 f"not imported" for r, _ in new if r.role and (incomplete[id(r)] or unresolved[id(r)])),
               *(f"{spec}: {r.kind} {name} added (role {r.role})" for r, name in added),
               *(f"{spec}: {rdn_value(e)} ("
                 f"{next(c for c in e.classes if any(is_subclass(d, c, k) for k in kinds))}) is in "
                 f"the record but not in what the cloud reports"
                 for e in own if e.norm not in reported and any(is_kind(d, e, k) for k in kinds)),
               *(n for check in table.checks
                 for n in check(d, spec, (*(r for r, held, _, _ in placed if held is not None),
                                          *(r for r, _ in added)))))
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
            (*(f"{ROLE_MAP}: {r.kind} {r.name or r.ref} has role {r.role} from the source; "
               f"the map's {given(r)} not used"
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

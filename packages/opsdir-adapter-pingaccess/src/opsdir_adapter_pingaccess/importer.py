"""PingAccess's configuration read into the record. Pure.

Two importers, the same record from either:
  pingaccess/admin-api   saved Admin API v3 GET responses (what `opsdir collect` reads with an Auditor credential),
                         and this adapter's own rendered requests.json, so a render reads back unchanged
  pingaccess/export      a saved configuration export (GET /config/export, Administrator only: saved by hand)

  applications, resources  -> paApplication (its context root a contract), paResource below it
  sites                    -> paSite: targets whose hosts are one role in the record (a service name, an external
                              system, or a rendered UNBOUND:<role>) become that role and port; else kept, fixed
  virtual hosts            -> paVirtualHost: a host that is a role in the record becomes it; else kept
  web sessions             -> paWebSession: linked to the OIDC client integration with its client id (then rendered
                              from it), and to the OpenID provider PingAccess's token provider names
  identity mappings        -> paIdentityMapping: linked to the header contracts of the headers it sets
  rules, rule sets         -> paRule
  everything else          -> paHeld, as is: environment-bound ones (keys, trust, listeners, nodes, agents) marked
Every object's settings keep the objects they name as ${pingaccess-id:<collection>/<name>} (refs.py), linked by DN
(paUses); secrets are withheld whole (withheld.py). A collection read replaces what the record holds for it (an object
it no longer has is removed); one nothing was read for is left as it is. What the record adds to an entry (owners, its
credential role) is kept.
"""
from functools import reduce

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import children, get, make_entry, merged_attrs, one, ou_entry
from opsdir.core.jsondata import canonical, held_json
from opsdir.domains.edge.naming import HEADER_CONTRACTS
from opsdir.domains.federation.services import integrations
from .api import CLIENT_ID, COLLECTIONS, CONTEXT_ROOT, HEADER_FIELDS, HOST, ISSUERS, RESOURCES, TARGETS, collection
from .naming import HELD, KINDS, PINGACCESS, entry_dn, held_base, usable_name
from .refs import host_role, leaves, resolved
from .sources import admin_api_read, export_read
from .withheld import withheld_settings

OWNED = ("cn", "paConfig", "paWithheld", "paSourceVersion", "paObjectType", "paUses", "paContextRoot",
         "paServiceRole", "paPort", "paBackendRole", "paIntegration", "paIssuer", "paHeaderContract",
         "paEnvironmentBound", "paRuleKind")


def target_endpoint(target):
    """(host, port or None) of a site target "host:port" (a rendered UNBOUND:<role>[:port] too)."""
    head, sep, tail = target.rpartition(":") if isinstance(target, str) else ("", "", "")
    return (head, int(tail)) if sep and tail.isdigit() else (target, None)


def _site(d, item):
    """(settings, owned, notices): targets that are one role of the record become it and its port."""
    ends = tuple(target_endpoint(t) for t in item.get(TARGETS) or ())
    roles = {host_role(d, h) for h, _ in ends}
    ports = {p for _, p in ends}
    role = next(iter(roles)) if len(roles) == 1 and None not in roles and len(ports) == 1 else None
    if role:
        return {k: v for k, v in item.items() if k != TARGETS}, {"paBackendRole": (role,),
                                                                  "paPort": (str(next(iter(ports))),)}, ()
    return item, {}, (("its targets are no single service name in the record, so it sends requests to the same "
                       "place from every environment",) if ends else ())


def _virtual_host(d, item):
    role = host_role(d, item.get(HOST))
    return ({k: v for k, v in item.items() if k != HOST}, {"paServiceRole": (role,)}, ()) if role else \
        (item, {}, ("its host is no service name in the record, so it answers as the same name in every "
                    "environment",))


def _web_session(d, item, issuer):
    credentials = item.get(CLIENT_ID[0]) if isinstance(item.get(CLIENT_ID[0]), dict) else {}
    client = credentials.get(CLIENT_ID[1])
    found = next((i for i in integrations(d, "oidc-client") if client and one(i, "ciamClientId") == client), None)
    owned = {"paIntegration": (found.dn if found else None,), "paIssuer": (issuer,)}
    if found is None:
        return item, owned, ((f"it signs users in as client {client}, which no integration in the record is",)
                             if client else ())
    return {**item, CLIENT_ID[0]: {k: v for k, v in credentials.items() if k != CLIENT_ID[1]}}, owned, ()


def _identity_mapping(d, item):
    headers = tuple(dict.fromkeys(h for pattern in HEADER_FIELDS for h in leaves(item, pattern) if isinstance(h, str)))
    contracts = {(one(c, "ciamHeaderName") or "").lower(): c.dn
                 for c in children(d, HEADER_CONTRACTS, "ciamHeaderContract")}
    return item, {"paHeaderContract": tuple(contracts[h.lower()] for h in headers if h.lower() in contracts)}, \
        tuple(f"it sets header {h}, which no header contract in the record names" for h in headers
              if h.lower() not in contracts)


def _specific(d, kind, path, item, issuer):
    """(settings, owned attributes, notices) of what a kind holds apart from its settings."""
    if kind == "site":
        return _site(d, item)
    if kind == "virtual-host":
        return _virtual_host(d, item)
    if kind == "web-session":
        return _web_session(d, item, issuer)
    if kind == "identity-mapping":
        return _identity_mapping(d, item)
    if kind == "application":
        return {k: v for k, v in item.items() if k != CONTEXT_ROOT}, {"paContextRoot": (item.get(CONTEXT_ROOT),)}, ()
    if kind in ("rule", "rule-set"):
        return item, {"paRuleKind": (kind,)}, ()
    if kind != "held":
        return item, {}, ()
    return item, {"paObjectType": (path,), "paEnvironmentBound": ("TRUE" if collection(path).bound else None,)}, ()


def _uses(obj):
    """The DNs of the objects an object names, in DN order (the same whichever order its settings list them)."""
    return tuple(sorted({entry_dn(collection(p).kind, n, p) for p, n in obj.uses
                         if collection(p) is not None and collection(p).kind != "resource"}))


def _label(obj):
    return f"{obj.path.replace('{application}', obj.application or '?')} {obj.name}"


def _entry(d, obj, patterns, version, issuer):
    """(entry, notices) of one object."""
    kind = collection(obj.path).kind
    config, owned, said = _specific(d, kind, obj.path, obj.item, issuer)
    settings, held = withheld_settings(config, patterns)
    dn = entry_dn(kind, obj.name, obj.path, obj.application)
    existing = get(d, dn)
    # a read that records no version (a render read back) keeps the record's
    source = version or (one(existing, "paSourceVersion") if existing is not None else None)
    attrs = merged_attrs(existing, {"cn": (obj.name,), "paConfig": (canonical(settings),), "paWithheld": held,
                                    "paSourceVersion": (source,), "paUses": _uses(obj), **owned}, OWNED)
    entry = make_entry(dn, ("top", "ciamObject", KINDS[kind][1]), attrs)
    return entry, (*(f"{_label(obj)}: {s}" for s in said),
                   *(f"{_label(obj)}: names {t} id {i}, which the import doesn't hold: kept as the id"
                     for t, i in obj.unresolved),
                   *((f"{_label(obj)}: its secrets are withheld; set paCredentialRole to the secret role that "
                      "holds them",) if held and not one(entry, "paCredentialRole") else ()))


def _issuer(d, items):
    """The issuer of the OpenID provider PingAccess's token provider names (the read's, else the record's)."""
    read = (i.get(field) for path, field in ISSUERS for i in items.get(path, ()))
    held = (held_json(e, "paConfig").get(field) for path, field in ISSUERS
            for e in children(d, held_base(path), "paHeld"))
    return next((x for x in (*read, *held) if isinstance(x, str) and x), None)


def _usable(objs):
    """The objects that can be imported, and why the others can't."""
    keys = [(o.path, o.application, o.name) for o in objs]
    bad = tuple(o for o, k in zip(objs, keys) if not usable_name(o.name) or keys.count(k) > 1
                or (o.path == RESOURCES and not usable_name(o.application)))
    return tuple(o for o in objs if o not in bad), tuple(
        f"{o.path} {o.name!r}: " + ("its application isn't in the import" if o.path == RESOURCES and
                                    not usable_name(o.application) else
                                    "no usable name (none, a DN special character, a slash, or another object of its "
                                    "collection has it): not imported") for o in bad)


def _groups(d, read_paths, entries):
    """((scope, entries), ...): each branch or held collection read, replacing what the record holds there."""
    by_kind = reduce(lambda out, pe: {**out, pe[0]: (*out.get(pe[0], ()), pe[1])}, entries, {})
    modeled = [(c.kind, c.path) for c in map(collection, read_paths) if c.kind not in ("held", "resource")]
    apps = {e.dn for e in by_kind.get("applications", ())}
    kept_resources = () if RESOURCES in read_paths else tuple(
        r for a in apps for r in children(d, a, "paResource"))
    groups = [(KINDS[kind][0], (get(d, KINDS[kind][0]) or ou_entry(KINDS[kind][0]), *by_kind.get(path, ()),
                                *((*by_kind.get(RESOURCES, ()), *kept_resources) if path == "applications" else ())))
              for kind, path in modeled]
    held = [(held_base(p), (get(d, held_base(p)) or ou_entry(held_base(p)), *by_kind.get(p, ())))
            for p in read_paths if collection(p).kind == "held"]
    return (*groups, *held)


def imported(d, read, patterns):
    """Imported of a Read."""
    objs, unusable = _usable(resolved(d, read.items))
    issuer = _issuer(d, read.items)
    built = [(o.path, _entry(d, o, patterns, read.version, issuer)) for o in objs]
    lone = () if "applications" in read.items else tuple(o for o in objs if o.path == RESOURCES)
    entries = [(p, e) for p, (e, _) in built if not (p == RESOURCES and lone)]
    return Imported(containers=(ou_entry(PINGACCESS), ou_entry(HELD)),
                    groups=_groups(d, tuple(c.path for c in COLLECTIONS if c.path in read.items
                                            and (c.path != RESOURCES or not lone)), entries),
                    notices=(*((f"PingAccess {read.version}",) if read.version else ()), *read.notices, *unusable,
                             *(n for _, (_, ns) in built for n in ns),
                             *(("resources read without their applications: not imported",) if lone else ()),
                             *(() if objs or unusable else ("nothing found",))))


def read_admin_api(files, d, patterns, at=None):
    """Imported from saved Admin API responses (and this adapter's rendered requests)."""
    return imported(d, admin_api_read(files), patterns)


def read_export(files, d, patterns, at=None):
    """Imported from a saved configuration export."""
    return imported(d, export_read(files), patterns)


ADMIN_API = Importer("admin-api", "PingAccess Admin API v3 responses (collected read-only) or this adapter's "
                                  "requests.json", read_admin_api)
EXPORT = Importer("export", "a PingAccess configuration export (GET /config/export, saved by an Administrator)",
                  read_export)

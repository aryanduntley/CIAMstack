"""SiteMinder's policy store read into the record from an XPSExport (importer siteminder/xps), as the source of a
migration. Pure.

  policy domains, realms, rules, policies   -> ou=siteminder (policies.py): this adapter's own entries; realms,
  authentication schemes, user directories,    their rules and policies also projected onto the neutral
  agents                                       protected-application layer (neutral.py)
  federation partnerships, OIDC clients     -> standard integrations (federation.py)
  header responses                          -> edge header contracts (responses.py)
  what has no standard equivalent           -> source objects (carried.py)
Every *.xml file given is read (an export of the whole store, -xb, or of parts); a DOCTYPE or entity declaration is
refused. Sensitive settings are never stored, neither their value nor their ciphertext: the entry records that each
existed, what it is, and that the target re-provisions it (smWithheld). An export older or newer than the releases this
adapter reads (>=12.8,<13) is refused whole, its version named.
"""
import re
from functools import reduce
from types import MappingProxyType

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, ou_entry, rdn_of
from opsdir.core.sources import xml_document
from opsdir.core.versions import in_range, parsed
from opsdir.domains.edge.naming import HEADER_CONTRACTS
from opsdir.domains.federation.naming import IDENTITY_SERVICES, INTEGRATIONS
from opsdir.domains.governance.naming import SOURCE_OBJECTS
from opsdir.domains.webaccess.projection import after_import, merged_import
from .agents import FILE_KINDS, file_concerns
from .carried import CARRY, carried_entry, carried_name
from .entries import Export, cleaned, unique, with_rest
from .federation import PROTOCOLS, integration_groups, place, service_for
from .neutral import projection
from .naming import (ACCESS_GATEWAY, AGENTS, AUTH_SCHEMES, CARRIED, DOMAINS, SITEMINDER, USER_DIRECTORIES, name_of,
                     named)
from .policies import (agent_entry, agent_role, directory_entry, domain_group, is_custom_scheme, realms_of,
                       scheme_entry)
from .responses import header_entry, header_value, is_header, parts
from .routing import has_routes
from .xps import COOKIE_RESPONSE, export_objects, kind, links_of, name

VERSIONS = ">=12.8,<13"              # the SiteMinder releases this adapter reads (its products)
_TWO_DIGIT_MINOR = re.compile(r"^(\d+)\.(\d)(\d)(\..*|)$")
_FOLDED = ("policy-link", "user-policy", "response-attr", "certificate", "runtime-sp")   # read through their parents
_OWN_BASES = MappingProxyType({"auth-scheme": AUTH_SCHEMES, "user-directory": USER_DIRECTORIES, "agent": AGENTS})


def _ancestor(objects, o, k):
    """The nearest ancestor of o of kind k, or None."""
    p = objects.get(o.parent)
    return None if p is None else p if kind(p) == k else _ancestor(objects, p, k)


def _carried_kind(o):
    k = kind(o)
    return k if k in CARRY else "unknown"


def _response_kind(a):
    return "cookie" if parts(a)[0] == COOKIE_RESPONSE else "response"


def _taken(acc, base, n):
    """(dn, acc with the name taken): n made unique under base."""
    placed, taken = acc
    u = unique(base, n, taken)
    return named(base, u), (placed, taken | {(base, u.lower())})


def _place(objects, acc, o):
    """acc (({XID: DNs}, taken names)) with object o placed (and, for a response, each of its attributes)."""
    k = kind(o)
    domain = _ancestor(objects, o, "domain")
    domain_dn = acc[0].get(domain.xid, (None,))[0] if domain is not None else None
    if k in PROTOCOLS or k in _FOLDED:
        return acc
    if k == "domain":
        dn, acc = _taken(acc, DOMAINS, name_of(name(o)))
    elif k == "realm" and domain_dn:
        parent = objects.get(o.parent)
        prefix = f"{rdn_of(acc[0][parent.xid][0])}-" if parent is not None and kind(parent) == "realm" \
            and parent.xid in acc[0] else ""
        dn, acc = _taken(acc, f"ou=realms,{domain_dn}", prefix + name_of(name(o)))
    elif k == "rule" and objects.get(o.parent) is not None and o.parent in acc[0] \
            and kind(objects[o.parent]) == "realm":
        dn, acc = _taken(acc, acc[0][o.parent][0], name_of(name(o)))
    elif k == "policy" and domain_dn:
        dn, acc = _taken(acc, f"ou=policies,{domain_dn}", name_of(name(o)))
    elif k == "response":
        return _place_response(objects, acc, o, domain)
    elif k in _OWN_BASES:
        dn, acc = _taken(acc, _OWN_BASES[k], name_of(name(o)))
    else:
        dn, acc = _taken(acc, CARRIED, name_of(carried_name(_carried_kind(o), o)))
    return {**acc[0], o.xid: (dn,)}, acc[1]


def _place_response(objects, acc, o, domain):
    """Each attribute of a response placed: a header contract, or a source object; the response is all of them."""
    prefix = name_of(name(domain)) + "-" if domain is not None else ""

    def attr(a_acc, a):
        if is_header(a):
            dn, a_acc = _taken(a_acc, HEADER_CONTRACTS, prefix + name_of(parts(a)[1]))
        else:
            dn, a_acc = _taken(a_acc, CARRIED, name_of(f"{_response_kind(a)}-{prefix}{name(o)}-{parts(a)[1]}"))
        return {**a_acc[0], a.xid: (dn,)}, a_acc[1]
    attrs = tuple(objects[c] for c in o.children if c in objects and kind(objects[c]) == "response-attr")
    placed, taken = reduce(attr, attrs, acc)
    return {**placed, o.xid: tuple(placed[a.xid][0] for a in attrs)}, taken


def _extra(acc, xid, k, o):
    """acc with a second entry for an object: the source object an auth scheme or agent also is."""
    dn, acc = _taken(acc, CARRIED, name_of(carried_name(k, o)))
    return {**acc[0], f"{xid}#{k}": (dn,)}, acc[1]


def placements(d, objects, order):
    """{XID: DNs} of every object that becomes entries (and XID#<kind> of the source object an auth scheme or agent
    also is), {XID: integration the record holds}."""
    fed = tuple((kind(o), o) for o in order if kind(o) in PROTOCOLS)
    integrations, held = place(d, fed)
    acc = reduce(lambda a, o: _place(objects, a, o), order, (integrations, frozenset()))
    acc = reduce(lambda a, o: _extra(a, o.xid, "custom-scheme", o), (o for o in order
                 if kind(o) == "auth-scheme" and is_custom_scheme(o)), acc)
    acc = reduce(lambda a, o: _extra(a, o.xid, "routing", o), (o for o in order
                 if kind(o) == "agent" and agent_role(o) == ACCESS_GATEWAY), acc)
    return MappingProxyType(acc[0]), held


def _read(files):
    """(objects in order, versions, notices) of every XML file given."""
    docs = tuple((p, xml_document(text)) for p, text in sorted(files.items()) if p.lower().endswith(".xml"))
    read = tuple((p, export_objects(root)) for p, (root, _) in docs if root is not None)
    seen = reduce(lambda acc, o: acc if o.xid in acc else {**acc, o.xid: o},
                  (o for _, (objs, _) in read for o in objs if o.xid), {})
    return (tuple(seen.values()), tuple(dict.fromkeys(v for _, (_, v) in read if v)),
            tuple(f"{p}: {problem}, not read" for p, (root, problem) in docs if root is None))


def release(v):
    """A SiteMinder version as a PEP 440 one: a two-digit minor names a service pack of its first digit's release
    (12.51, 12.52 are 12.5 SP1, SP2: older than 12.6), so it is split (12.5.2); others are as they are."""
    m = _TWO_DIGIT_MINOR.match(v or "")
    return f"{m.group(1)}.{m.group(2)}.{m.group(3)}{m.group(4)}" if m else v


def _version_refused(versions):
    wrong = tuple(v for v in versions if parsed(release(v)) is None or not in_range(release(v), VERSIONS))
    return tuple(f"the export is from SiteMinder {v}; this adapter reads {VERSIONS}: nothing imported" for v in wrong)


def _concerning(d, x, order, xid, link):
    """The DNs of the realms whose agent or scheme link names this object."""
    return tuple(x.placed[r.xid][0] for r in order if kind(r) == "realm" and r.xid in x.placed
                 and xid in links_of(r, link))


def _routed(d, x, o, k):
    """Whether the source object of kind k of agent o is the routing the record already holds (the gateway's routes:
    its agent files)."""
    agent = get(d, x.placed[o.xid][0]) if k == "routing" else None
    return agent is not None and has_routes(d, agent)


def _carried_groups(d, x, order, at):
    singles = tuple((o, _carried_kind(o)) for o in order if kind(o) not in ("response", "response-attr")
                    and o.xid in x.placed and x.placed[o.xid][0].endswith(CARRIED))
    responses = tuple((a, _response_kind(a)) for o in order if kind(o) == "response"
                      for c in o.children if c in x.objects for a in (x.objects[c],)
                      if not is_header(a) and a.xid in x.placed)
    extras = tuple((o, k, x.placed[f"{o.xid}#{k}"][0], _concerning(d, x, order, o.xid,
                                                                       "scheme" if k == "custom-scheme" else "agent"))
                   for o in order for k in ("custom-scheme", "routing") if f"{o.xid}#{k}" in x.placed)
    keyed = any(kind(o) in ("agent", "trusted-host", "hco", "sp-partnership", "idp-partnership") for o in order)
    keys_dn = named(CARRIED, "keys")
    return (*(with_rest(d, x.placed[o.xid][0], (carried_entry(
                d, x, k, o, x.placed[o.xid][0], at,
                file_concerns(d, x.placed[o.xid][0]) if k in FILE_KINDS else ()),))
              for o, k in (*singles, *responses)),
            *((dn, ()) if _routed(d, x, o, k) else with_rest(d, dn, (carried_entry(d, x, k, o, dn, at, concerns),))
              for o, k, dn, concerns in extras),
            *((with_rest(d, keys_dn, (carried_entry(d, x, "keys", None, keys_dn, at),)),) if keyed else ()))


def _notices(x, order, unresolved, folded):
    fixed = tuple(f"the fixed value of header {parts(a)[1]}" for o in order if kind(o) == "response"
                  for c in o.children if c in x.objects for a in (x.objects[c],)
                  if is_header(a) and header_value(parts(a)[2])[2])
    withheld = (*(f"{w.split(':', 1)[0]} of {name(x.objects[xid])}" for xid in x.withheld for w in x.withheld[xid]),
                *fixed)
    runtime = sum(1 for o in order if kind(o) == "runtime-sp")
    return (*((f"{len(withheld)} sensitive setting(s) withheld, never stored: {', '.join(withheld)}. An XPSExport "
               "made with -npass holds them in CLEAR TEXT, one made with -pass encrypted: treat the export file as a "
               "secret, and re-provision each in the target",) if withheld else ()),
            *((f"{runtime} generated runtime object(s) (CA.SM::SAMLv2SP) are their partnerships' own: not read "
               "twice",) if runtime else ()),
            *unresolved, *folded)


def read_export(files, d, patterns, at=None):
    """Imported from SiteMinder XPSExport XML files."""
    order, versions, problems = _read(files)
    refused = _version_refused(versions)
    if refused or not order:
        return Imported((), (), (*problems, *refused, *(() if order else ("no SiteMinder XPSExport objects found "
                                                                             "(*.xml with <Object> elements)",))))
    objects = MappingProxyType({o.xid: o for o in order})
    clean = {o.xid: cleaned(o, patterns) for o in order}
    placed, held = placements(d, objects, order)
    x = Export(objects, order, MappingProxyType({k: v[0] for k, v in clean.items()}),
               MappingProxyType({k: v[1] for k, v in clean.items()}), placed)
    partnerships = tuple(o for o in order if kind(o) in ("sp-partnership", "idp-partnership"))
    served, service, service_notices = service_for(d, x, partnerships)
    fed_groups, fed_notices = integration_groups(d, x, tuple((kind(o), o) for o in order if kind(o) in PROTOCOLS),
                                                 held, served)
    dirs = tuple(directory_entry(d, x, o) for o in order if kind(o) == "user-directory")
    domains = tuple(domain_group(d, x, o) for o in order if kind(o) == "domain")
    headers = tuple(with_rest(d, x.placed[a.xid][0], (header_entry(d, x, a, x.placed[a.xid][0]),))
                    for o in order if kind(o) == "response" for c in o.children if c in objects
                    for a in (objects[c],) if is_header(a) and a.xid in placed)
    own = (*(with_rest(d, x.placed[o.xid][0], (agent_entry(d, x, o),)) for o in order if kind(o) == "agent"),
           *(with_rest(d, x.placed[o.xid][0], (scheme_entry(d, x, o),)) for o in order if kind(o) == "auth-scheme"),
           *(with_rest(d, e.dn, (e,)) for e, _ in dirs))
    carried = _carried_groups(d, x, order, at)
    unresolved = tuple(f"{o.cls} {name(o)}: links to {xid}, which the export doesn't hold (export it whole, -xb, or "
                       "with its dependencies): left out" for o in order for _, xids in o.links for xid in xids
                       if xid not in objects)
    orphans = tuple(f"{o.cls} {name(o)}: not inside a policy domain or realm the export holds: not read"
                    for o in order if kind(o) in ("realm", "rule", "policy") and o.xid not in placed)
    used = {b for b, present in ((DOMAINS, domains), (AUTH_SCHEMES, any(kind(o) == "auth-scheme" for o in order)),
                                 (USER_DIRECTORIES, dirs), (AGENTS, any(kind(o) == "agent" for o in order)))
            if present}
    containers = (SITEMINDER, *sorted(used), *((SOURCE_OBJECTS, CARRIED) if carried else ()),
                  *((INTEGRATIONS,) if fed_groups else ()), *((IDENTITY_SERVICES,) if service is not None else ()),
                  *((HEADER_CONTRACTS,) if headers else ()))
    own = Imported(
        containers=tuple(ou_entry(c) for c in containers),
        groups=(*domains, *own, *headers, *carried, *((with_rest(d, service.dn, (service,)),) if service else ()),
                *fed_groups),
        notices=(*problems, *(n for _, ns in dirs for n in ns), *service_notices, *fed_notices,
                 *_notices(x, order, unresolved, orphans)))
    return merged_import(own, projection(after_import(d, own), at))


XPS = Importer("xps", "a SiteMinder policy store export (XPSExport XML: domains, realms, rules, policies, responses, "
               "user directories, authentication schemes, agents and their configuration, federation partnerships)",
               read_export)

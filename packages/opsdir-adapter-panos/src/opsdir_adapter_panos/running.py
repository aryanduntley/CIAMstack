"""A Panorama's or PAN-OS firewall's RUNNING configuration, as the read-back reads it (milestone 6.2c; vendor facts:
research note on milestone 102). Pure.

Two forms, one per appliance folder:
  running-config.xml            an explicit running-configuration snapshot (a <config> document: a saved or exported
                                running configuration; a candidate one, or a CLI capture, is not running evidence)
  api/<scope>/<family>.xml      what the collector saves: the XML API's answer (<response status="success"><result>)
                                to type=config&action=show (the running configuration; action=get would be the
                                candidate) for one part of one scope
where <scope> is shared, device-group/<name> (Panorama) or vsys/<name> (a firewall), and <family> one of pre-rulebase,
post-rulebase (Panorama, and shared on Panorama), rulebase (a firewall's vsys), address, address-group, service,
service-group. The xpaths behind them are reconstructed from Palo Alto's documented examples (XPATHS): confirm them
in the appliance's /api/ browser.

Objects resolve in the rule's own scope, then shared (a device group's ancestors aren't read). An address object is
resolved when it is ip-netmask; ranges, wildcards, FQDNs and dynamic groups are named, never guessed; static groups
resolve recursively (a cycle is named). A service resolves to protocol and port when it is TCP or UDP on single ports;
any, application-default, port ranges and predefined services are named. Documents with a DOCTYPE are refused.
"""
import ipaddress
from typing import NamedTuple

from opsdir.core.sources import xml_document

SHARED = "shared"
SNAPSHOT = "running-config.xml"
API = "api/"
RULEBASES = ("pre-rulebase", "post-rulebase", "rulebase")
OBJECTS = ("address", "address-group", "service", "service-group")
FAMILIES = (*RULEBASES, *OBJECTS)
DEVICE = "/config/devices/entry[@name='localhost.localdomain']"
# Where each scope is in the configuration: reconstructed from Palo Alto's documented XPath examples (research note on
# milestone 102), to be confirmed in the appliance's /api/ browser
SCOPE_XPATHS = {"shared": "/config/shared", "device-group": DEVICE + "/device-group/entry[@name='{}']",
                "vsys": DEVICE + "/vsys/entry[@name='{}']"}
FAMILY_XPATHS = {"pre-rulebase": "/pre-rulebase/security/rules", "post-rulebase": "/post-rulebase/security/rules",
                 "rulebase": "/rulebase/security/rules", "address": "/address", "address-group": "/address-group",
                 "service": "/service", "service-group": "/service-group"}

# A security rule as it runs: its name and UUID, where it is (scope, rulebase), its sources, destinations and services
# (member names or literals, as written), action, whether disabled and negated, logging at session end (None: not
# written, PAN-OS's default yes), schedule and description
Rule = NamedTuple("Rule", [("name", str), ("uuid", object), ("scope", str), ("rulebase", str), ("sources", tuple),
                           ("destinations", tuple), ("services", tuple), ("action", object), ("disabled", bool),
                           ("negate_source", bool), ("negate_destination", bool), ("log_end", object),
                           ("schedule", object), ("description", object)])
# One scope's objects: addresses {name: (type, value)}, address groups {name: ("static", members) or ("dynamic",
# filter)}, services {name: (protocol, port text)}, service groups {name: members}
Scope = NamedTuple("Scope", [("addresses", dict), ("groups", dict), ("services", dict), ("service_groups", dict)])
# A running configuration: {scope: Scope}, the rules in each (scope, rulebase) in order, and the configuration's
# version when the snapshot names one
Running = NamedTuple("Running", [("scopes", dict), ("rules", dict), ("version", object)])


def xpath(scope, family):
    """The xpath of one family of one scope ('shared', 'device-group/<name>', 'vsys/<name>')."""
    kind, _, name = scope.partition("/")
    return SCOPE_XPATHS[kind].format(name) + FAMILY_XPATHS[family]


def _entries(e):
    return tuple(x for x in (e.findall("entry") if e is not None else ()) if x.get("name"))


def _text(e, path):
    found = e.find(path)
    return found.text.strip() if found is not None and found.text and found.text.strip() else None


def _members(e, path):
    found = e.find(path)
    return tuple(m.text.strip() for m in (found.findall("member") if found is not None else ()) if m.text)


def _yes(e, path):
    return _text(e, path) == "yes"


def _rule(e, scope, rulebase):
    return Rule(e.get("name"), e.get("uuid"), scope, rulebase, _members(e, "source"), _members(e, "destination"),
                _members(e, "service"), _text(e, "action"), _yes(e, "disabled"), _yes(e, "negate-source"),
                _yes(e, "negate-destination"), _text(e, "log-end"), _text(e, "schedule"), _text(e, "description"))


def _address(e):
    kind = next((k for k in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn") if _text(e, k)), None)
    return (kind, _text(e, kind)) if kind else ("unknown", None)


def _group(e):
    dynamic = e.find("dynamic") is not None
    return ("dynamic", _text(e, "dynamic/filter")) if dynamic else ("static", _members(e, "static"))


def _service(e):
    proto = next((p for p in ("tcp", "udp", "sctp") if e.find(f"protocol/{p}") is not None), None)
    return (proto, _text(e, f"protocol/{proto}/port")) if proto else (None, None)


def _scope(parts):
    """A Scope from {family: entries}."""
    return Scope({x.get("name"): _address(x) for x in parts.get("address", ())},
                 {x.get("name"): _group(x) for x in parts.get("address-group", ())},
                 {x.get("name"): _service(x) for x in parts.get("service", ())},
                 {x.get("name"): _members(x, "members") for x in parts.get("service-group", ())})


def _families(e):
    """{family: entries} of a scope element of a snapshot."""
    return {**{f: _entries(e.find(f)) for f in OBJECTS},
            **{f: _entries(e.find(f"{f}/security/rules")) for f in RULEBASES}}


def _snapshot(root):
    """{scope: {family: entries}} of a <config> document."""
    device = root.find("devices/entry")
    found = {SHARED: _families(root.find("shared"))} if root.find("shared") is not None else {}
    for kind in ("device-group", "vsys"):
        found.update({f"{kind}/{x.get('name')}": _families(x)
                      for x in (_entries(device.find(kind)) if device is not None else ())})
    return found


def _answer(path, root):
    """(entries, problem) of one API answer saved at api/<scope>/<family>.xml."""
    if root.tag != "response" or root.get("status") != "success":
        return (), f"{path}: not a successful XML API answer (<response status=\"success\">); not read"
    result = root.find("result")
    holder = next(iter(result), None) if result is not None else None
    return _entries(holder), None


def _api_place(path):
    """(scope, family) an api/ file is saved for, or None."""
    parts = path[len(API):].removesuffix(".xml").split("/")
    scope, family = "/".join(parts[:-1]), parts[-1]
    kinds = (SHARED,) if scope == SHARED else ("device-group", "vsys")
    ok = family in FAMILIES and (scope == SHARED or (scope.split("/")[0] in kinds and scope.count("/") == 1))
    return (scope, family) if ok else None


def _api_file(path, text):
    """((scope, family), entries, problem) of one api/ file."""
    place = _api_place(path)
    root, problem = xml_document(text)
    entries, refused = _answer(path, root) if root is not None else ((), None)
    if place is None or problem or refused:
        return None, (), refused or f"{path}: {problem or 'not api/<scope>/<family>.xml'}; not read"
    return place, entries, None


def _from_api(files):
    """({scope: {family: entries}}, problems) of the api/ answers."""
    read = [_api_file(p, t) for p, t in sorted(files.items())]
    ok = [(place, entries) for place, entries, problem in read if not problem]
    return ({s: {f: entries for (s2, f), entries in ok if s2 == s} for s in dict.fromkeys(s for (s, _), _ in ok)},
            tuple(problem for _, _, problem in read if problem))


def read_running(files):
    """(Running or None, notices) of one appliance's files ({path within its folder: text}): its running-config.xml
    snapshot, else its api/ answers. None when there is nothing to read or the snapshot can't be read: an incomplete
    read must never say a rule is missing."""
    if SNAPSHOT in files:
        root, problem = xml_document(files[SNAPSHOT])
        if problem or root.tag != "config":
            return None, (f"{SNAPSHOT}: {problem or 'not a <config> document'}; not read",)
        found, notices, version = _snapshot(root), tuple(f"{p}: beside {SNAPSHOT}; not read" for p in files
                                                         if p != SNAPSHOT), root.get("version")
    else:
        found, problems = _from_api({p: t for p, t in files.items() if p.startswith(API)})
        version = None
        notices = (*problems, *(f"{p}: neither {SNAPSHOT} nor under {API}; not read" for p in files
                                if p != SNAPSHOT and not p.startswith(API)))
        if problems:
            return None, (*notices, "the API answers are incomplete: nothing read from this appliance")
    if not found:
        return None, (*notices, "no running configuration found")
    return Running({s: _scope(parts) for s, parts in found.items()},
                   {(s, f): tuple(_rule(x, s, f) for x in parts.get(f, ())) for s, parts in found.items()
                    for f in RULEBASES if parts.get(f)}, version), tuple(notices)


def chain(scope):
    """The scopes a rule's objects resolve in, nearest first: its own, then shared."""
    return (scope,) if scope == SHARED else (scope, SHARED)


def _find(running, scopes, table, name):
    return next((getattr(running.scopes[s], table)[name] for s in scopes
                 if s in running.scopes and name in getattr(running.scopes[s], table)), None)


def _literal(member):
    try:
        return str(ipaddress.ip_network(member, strict=False))
    except ValueError:
        return None


def _addresses(running, scopes, member, seen):
    """((cidr, ...), (unresolved, ...)) of one source or destination member."""
    literal = _literal(member)
    if literal:
        return (literal,), ()
    address = _find(running, scopes, "addresses", member)
    if address is not None:
        kind, value = address
        net = _literal(value) if kind == "ip-netmask" and value else None
        return ((net,), ()) if net else ((), (f"{member} ({kind} {value})",))
    group = _find(running, scopes, "groups", member)
    if group is None:
        return (), (f"{member} (not in the export)",)
    if group[0] == "dynamic":
        return (), (f"{member} (dynamic group {group[1]})",)
    if member in seen:
        return (), (f"{member} (group cycle)",)
    parts = [_addresses(running, scopes, x, seen | {member}) for x in group[1]]
    return tuple(c for cs, _ in parts for c in cs), tuple(u for _, us in parts for u in us)


def resolve_addresses(running, scope, members):
    """((cidr, ...), (unresolved, ...)) of a rule's sources or destinations in scope: any is every address (0.0.0.0/0,
    ::/0); a literal, an ip-netmask object or a static group of them resolve; anything else is named."""
    if "any" in members:
        return ("0.0.0.0/0", "::/0"), ()
    parts = [_addresses(running, chain(scope), x, frozenset()) for x in members]
    return (tuple(sorted({c for cs, _ in parts for c in cs})), tuple(u for _, us in parts for u in us))


def _ports(member, proto, ports):
    each = tuple(p.strip() for p in (ports or "").split(","))
    if proto not in ("tcp", "udp") or not all(p.isdigit() for p in each):
        return (), (f"{member} ({proto or 'unknown'}/{ports})",)
    return tuple((proto, p) for p in each), ()


def _services(running, scopes, member, seen):
    service = _find(running, scopes, "services", member)
    if service is not None:
        return _ports(member, *service)
    group = _find(running, scopes, "service_groups", member)
    if group is None:
        return (), (f"{member} (not in the export: predefined or another scope's)",)
    if member in seen:
        return (), (f"{member} (group cycle)",)
    parts = [_services(running, scopes, x, seen | {member}) for x in group]
    return tuple(p for ps, _ in parts for p in ps), tuple(u for _, us in parts for u in us)


def resolve_services(running, scope, members):
    """(((protocol, port), ...), (unresolved, ...)) of a rule's services in scope: TCP and UDP service objects (and
    static groups of them) on single ports resolve; any, application-default and the rest are named."""
    named = tuple(m for m in members if m in ("any", "application-default"))
    parts = [_services(running, chain(scope), x, frozenset()) for x in members if x not in named]
    return (tuple(sorted({p for ps, _ in parts for p in ps})),
            (*named, *(u for _, us in parts for u in us)))

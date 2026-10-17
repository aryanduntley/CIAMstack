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

A Panorama's API answers can also hold (milestone 106; research docs/research m106):
  api/op/dg-hierarchy.xml                       show dg-hierarchy: each device group's parent
  api/op/devices.xml                            show devices all: each managed firewall (serial, host name, connected,
                                                software version, high availability, shared policy status)
  api/device-group/<name>/devices.xml           the device group's firewalls (serials, and their virtual systems)
  api/firewall/<serial>/<vsys>/<rulebase>.xml   pre-rulebase and post-rulebase of the policy Panorama pushed to one
                                                firewall (/config/panorama/vsys/...), read through Panorama (target)
  api/firewall/<serial>/<vsys>/hit-count.xml    show rule-hit-count of that virtual system's security rules
A snapshot's device-group parents are read from its readonly section when it holds them.

Objects resolve in the rule's own scope, then its device group's ancestors nearest first, then shared. An address
object is resolved when it is ip-netmask; ranges, wildcards, FQDNs and dynamic groups are named, never guessed;
static groups resolve recursively (a cycle is named). A service resolves to protocol and port when it is TCP or UDP
on single ports; any, application-default, port ranges and predefined services are named. Documents with a DOCTYPE
are refused.
"""
import datetime as dt
import ipaddress
from typing import NamedTuple

from opsdir.core.directory import gtime
from opsdir.core.sources import xml_document

SHARED = "shared"
SNAPSHOT = "running-config.xml"
API = "api/"
RULEBASES = ("pre-rulebase", "post-rulebase", "rulebase")
OBJECTS = ("address", "address-group", "service", "service-group")
DEVICES = "devices"                 # a device group's firewalls (config), and the op answer listing every one
FAMILIES = (*RULEBASES, *OBJECTS, DEVICES)
OP, FIREWALL = "op/", "firewall/"
PUSHED = ("pre-rulebase", "post-rulebase")
HITS = "hit-count"
# The operational commands the read sends (type=op): the only ones it ever sends; each only shows
OP_COMMANDS = {"devices": "<show><devices><all/></devices></show>",
               "dg-hierarchy": "<show><dg-hierarchy/></show>"}
PUSHED_XPATH = "/config/panorama/vsys/entry[@name={}]/{}/security/rules"
DEVICE = "/config/devices/entry[@name='localhost.localdomain']"
# Where each scope is in the configuration: reconstructed from Palo Alto's documented XPath examples (research note on
# milestone 102), to be confirmed in the appliance's /api/ browser
SCOPE_XPATHS = {"shared": "/config/shared", "device-group": DEVICE + "/device-group/entry[@name='{}']",
                "vsys": DEVICE + "/vsys/entry[@name='{}']"}
FAMILY_XPATHS = {"pre-rulebase": "/pre-rulebase/security/rules", "post-rulebase": "/post-rulebase/security/rules",
                 "rulebase": "/rulebase/security/rules", "address": "/address", "address-group": "/address-group",
                 "service": "/service", "service-group": "/service-group", DEVICES: "/devices"}

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
# A managed firewall as Panorama lists it (show devices all): host name, connected (True, False or None), software
# version, high availability ('active, peer <serial>'), shared policy status
Device = NamedTuple("Device", [("name", object), ("connected", object), ("version", object), ("ha", object),
                               ("policy", object)])
# A rule's hit counts on one firewall: count, first and last hit, when counting began (GeneralizedTime or None)
Hits = NamedTuple("Hits", [("count", object), ("first", object), ("last", object), ("since", object)])
# A running configuration: {scope: Scope}, the rules in each (scope, rulebase) in order, the configuration's version
# when the snapshot names one, the (scope, family) parts the API answers held (None: a snapshot), each device group's
# parent ({name: parent or None}; None: not read), Panorama's managed firewalls ({serial: Device}), each device
# group's firewalls ({name: ((serial, (vsys, ...)), ...)}), the policy pushed to each firewall ({(serial, vsys):
# {rulebase: (Rule, ...)}}) and its hit counts ({(serial, vsys): {rule name: Hits}})
Running = NamedTuple("Running", [("scopes", dict), ("rules", dict), ("version", object), ("parts", object),
                                 ("parents", object), ("devices", dict), ("members", dict), ("pushed", dict),
                                 ("hits", dict)])


def literal(name):
    """An XPath string literal of a name: quoted with ' or ", else concat() of both (no name breaks the path)."""
    if "'" not in name:
        return f"'{name}'"
    if '"' not in name:
        return f'"{name}"'
    return "concat(" + ", \"'\", ".join(f"'{p}'" for p in name.split("'")) + ")"


def xpath(scope, family):
    """The xpath of one family of one scope ('shared', 'device-group/<name>', 'vsys/<name>')."""
    kind, _, name = scope.partition("/")
    return SCOPE_XPATHS[kind].replace("'{}'", "{}").format(literal(name)) + FAMILY_XPATHS[family]


def pushed_xpath(vsys, rulebase):
    """The xpath of the policy Panorama pushed to a firewall's virtual system, read on that firewall."""
    return PUSHED_XPATH.format(literal(vsys), rulebase)


def hit_count_command(vsys):
    """The op command showing a virtual system's security rules' hit counts."""
    safe = vsys.replace("&", "").replace("<", "").replace('"', "")
    return (f'<show><rule-hit-count><vsys><vsys-name><entry name="{safe}"><rule-base><entry name="security">'
            "<rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>")


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


def _parents_snapshot(root):
    """{device group: parent} from a snapshot's readonly section, or None when it holds none."""
    holder = root.find("readonly/devices/entry/device-group")
    groups = _entries(holder)
    return {x.get("name"): _text(x, "parent-dg") for x in groups} if groups else None


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
    """(scope, family) an api/ config answer is saved for, or None."""
    if path.startswith(API + OP) or path.startswith(API + FIREWALL):
        return None
    parts = path[len(API):].removesuffix(".xml").split("/")
    scope, family = "/".join(parts[:-1]), parts[-1]
    kinds = (SHARED,) if scope == SHARED else ("device-group", "vsys")
    ok = family in FAMILIES and (scope == SHARED or (scope.split("/")[0] in kinds and scope.count("/") == 1))
    ok = ok and (family != DEVICES or scope.startswith("device-group/"))
    return (scope, family) if ok else None


def _flag(text):
    return {"yes": True, "no": False}.get((text or "").strip().lower())


def _device(e):
    peer = _text(e, "ha/peer/serial")
    ha = _text(e, "ha/state")
    return Device(_text(e, "hostname"), _flag(_text(e, "connected")), _text(e, "sw-version"),
                  f"{ha}{f', peer {peer}' if peer else ''}" if ha else None,
                  next((x.text.strip() for x in e.iter("shared-policy-status") if x.text and x.text.strip()), None))


def _hierarchy(result):
    """{device group: parent or None} of a show dg-hierarchy answer (nested <dg name=...>)."""
    found = {}
    def walk(e, parent):
        for dg in e.findall("dg"):
            if dg.get("name"):
                found[dg.get("name")] = parent
                walk(dg, dg.get("name"))
    walk(result.find("dg-hierarchy") if result.find("dg-hierarchy") is not None else result, None)
    return found


def _epoch(text):
    """GeneralizedTime of a PAN-OS epoch seconds value, None for none or 0 (never)."""
    try:
        n = int(text or 0)
    except ValueError:
        return None
    return gtime(dt.datetime.fromtimestamp(n, dt.timezone.utc)) if n > 0 else None


def _hits(result):
    """{rule name: Hits} of a show rule-hit-count answer."""
    def one_rule(e):
        reset, created = _epoch(_text(e, "last-reset-timestamp")), _epoch(_text(e, "rule-creation-timestamp"))
        count = _text(e, "hit-count")
        return Hits(int(count) if count and count.isdigit() else None, _epoch(_text(e, "first-hit-timestamp")),
                    _epoch(_text(e, "last-hit-timestamp")), max((t for t in (reset, created) if t), default=None))
    return {x.get("name"): one_rule(x) for x in result.iter("entry")
            if x.get("name") and x.find("hit-count") is not None}


def _success(path, text):
    """(<result> element, problem) of one saved API answer."""
    root, problem = xml_document(text)
    if problem or root is None:
        return None, f"{path}: {problem}; not read"
    if root.tag != "response" or root.get("status") != "success" or root.find("result") is None:
        return None, f"{path}: not a successful XML API answer (<response status=\"success\">); not read"
    return root.find("result"), None


def _extra(files):
    """(parents, devices, pushed, hits, problems) of the op/ and firewall/ answers."""
    parents, devices, pushed, hits, problems = None, {}, {}, {}, []
    for path, text in sorted(files.items()):
        rest = path[len(API):].removesuffix(".xml")
        if not (rest.startswith(OP) or rest.startswith(FIREWALL)):
            continue
        result, problem = _success(path, text)
        if problem:
            problems.append(problem)
            continue
        parts = rest.split("/")
        if parts == ["op", "dg-hierarchy"]:
            parents = _hierarchy(result)
        elif parts == ["op", "devices"]:
            holder = result.find("devices")
            devices = {x.get("name"): _device(x) for x in _entries(holder)}
        elif len(parts) == 4 and parts[0] == "firewall" and parts[3] in PUSHED:
            holder = next(iter(result), None)
            pushed.setdefault((parts[1], parts[2]), {})[parts[3]] = tuple(
                _rule(x, f"firewall/{parts[1]}/{parts[2]}", parts[3]) for x in _entries(holder))
        elif len(parts) == 4 and parts[0] == "firewall" and parts[3] == HITS:
            hits[(parts[1], parts[2])] = _hits(result)
        else:
            problems.append(f"{path}: not one of the answers the read knows; not read")
    return parents, devices, pushed, hits, tuple(problems)


def _api_file(path, text):
    """((scope, family), entries, problem) of one api/ file."""
    place = _api_place(path)
    root, problem = xml_document(text)
    entries, refused = _answer(path, root) if root is not None else ((), None)
    if place is None or problem or refused:
        return None, (), refused or f"{path}: {problem or 'not api/<scope>/<family>.xml'}; not read"
    return place, entries, None


def _from_api(files):
    """({scope: {family: entries}}, problems) of the api/ config answers."""
    read = [_api_file(p, t) for p, t in sorted(files.items())
            if not (p.startswith(API + OP) or p.startswith(API + FIREWALL))]
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
        parts, extra = None, (_parents_snapshot(root), {}, {}, {}, ())
    else:
        api = {p: t for p, t in files.items() if p.startswith(API)}
        found, problems = _from_api(api)
        extra = _extra(api)
        version, parts = None, frozenset((s, f) for s, fam in found.items() for f in fam)
        notices = (*problems, *extra[4], *(f"{p}: neither {SNAPSHOT} nor under {API}; not read" for p in files
                                           if p != SNAPSHOT and not p.startswith(API)))
        if problems or extra[4]:
            return None, (*notices, "the API answers are incomplete: nothing read from this appliance")
    if not found:
        return None, (*notices, "no running configuration found")
    parents, devices, pushed, hits, _ = extra
    members = {s.split("/", 1)[1]: tuple((x.get("name"), tuple(v.get("name") for v in _entries(x.find("vsys"))))
                                         for x in fam.get(DEVICES, ()))
               for s, fam in found.items() if s.startswith("device-group/") and DEVICES in fam}
    return Running({s: _scope(fam) for s, fam in found.items()},
                   {(s, f): tuple(_rule(x, s, f) for x in fam.get(f, ())) for s, fam in found.items()
                    for f in RULEBASES if fam.get(f)}, version, parts, parents, devices, members, pushed,
                   hits), tuple(notices)


def answered_hierarchy(text):
    """{device group: parent} of a saved show dg-hierarchy answer, or None when it isn't a successful one."""
    result, problem = _success("", text or "")
    return None if problem else _hierarchy(result)


def answered_members(text):
    """((serial, (vsys, ...)), ...) of a saved device-group devices answer, or () when it isn't a successful one."""
    result, problem = _success("", text or "")
    holder = None if problem else next(iter(result), None)
    return tuple((x.get("name"), tuple(v.get("name") for v in _entries(x.find("vsys")))) for x in _entries(holder))


def ancestors(running, scope):
    """A device-group scope's ancestor scopes, nearest first (none when the hierarchy wasn't read)."""
    if not scope.startswith("device-group/") or not running.parents:
        return ()
    def up(name, seen):
        parent = running.parents.get(name)
        return () if parent is None or parent in seen else (f"device-group/{parent}", *up(parent, seen | {parent}))
    return up(scope.split("/", 1)[1], frozenset({scope.split("/", 1)[1]}))


def chain(running, scope):
    """The scopes a rule's objects resolve in, nearest first: its own, its device group's ancestors, then shared."""
    return (scope,) if scope == SHARED else (scope, *ancestors(running, scope), SHARED)


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
    parts = [_addresses(running, chain(running, scope), x, frozenset()) for x in members]
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
    parts = [_services(running, chain(running, scope), x, frozenset()) for x in members if x not in named]
    return (tuple(sorted({p for ps, _ in parts for p in ps})),
            (*named, *(u for _, us in parts for u in us)))

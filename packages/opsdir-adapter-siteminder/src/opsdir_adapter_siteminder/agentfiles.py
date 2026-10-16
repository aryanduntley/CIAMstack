"""Each server's SiteMinder agent files read into the record (importer siteminder/agent-files), as the source of a
migration. Pure.

One folder per server, named by its hostname or record name (a server of role sm-agent or sm-access-gateway):
  WebAgent.conf (one per instance: a web server's, or each Access Gateway virtual host's), SmHost.conf,
  LocalConfig.conf     -> smWebAgent below the server (cn=<virtual host | ServerPath | webagent>): the agent identities
                          it acts as, its ACO, HCO and trusted host (the policy store export's source objects), its
                          environment's policy servers, a virtual host's names, its other settings; secrets withheld
                          whole (smWithheld: that each existed, what it is, that the target re-provisions it)
  server.conf          -> an Access Gateway's virtual hosts, each with its own WebAgent.conf (sminitfile), and the
                          proxy rules file every one of them uses (ServiceDispatcher rules_file)
  proxyrules.xml       -> its routes in order (smRoute below the server: proxyrules.py)
A file a WebAgent.conf (or server.conf) names is found by the tail of its path, else beside it. The import replaces
what the record says of each server's instances and routes; the ACO, HCO and trusted host source objects concern the
servers whose files name them; a gateway agent's routing source object is dropped once its routes are read; and
SiteMinder's one projection onto the neutral layer is run again (neutral.py). Read the policy store export (importer
xps) first: what the files name is linked only when the record holds it.
"""
from functools import reduce
from typing import NamedTuple

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import children, get, one, ou_entry, rdn_value, values
from opsdir.core.environment import server_location, server_named
from opsdir.core.jsondata import canonical
from opsdir.core.secrets import scan
from opsdir.core.sources import by_folder
from opsdir.domains.webaccess.projection import after_import, merged_import
from .agents import LINKED_KINDS, aco_parameters, agent_dn, carried_dn, file_concerns, identities, instances, on_server
from .conf import (DEFAULT_AGENT_FILE, DISPATCHER, HOSTNAMES, INIT_FILE, LOCAL_CONF, LOCAL_LABEL, MAPPED, NAMES,
                   PROXY_RULES, RULES_FILE, SERVER_CONF, SMHOST_CONF, VIRTUAL_HOST, VIRTUAL_HOST_DEFAULTS,
                   WEBAGENT_CONF, WEBAGENT_SECTION, allowed_local, attr, file_name, first, is_allowed, listed,
                   matching, named, sections, settings, settings_outside, within)
from .entries import entry, unique, with_rest
from .naming import ACCESS_GATEWAY, AGENT, AGENTS, CARRIED, POLICY_SERVER, ROUTES, SITEMINDER, WEB_AGENTS, name_of
from .neutral import projection
from .proxyrules import routes, rules_document
from .routing import has_routes, routing_objects
from .xps import is_true, purpose, sensitive

SERVER_KINDS = (AGENT, ACCESS_GATEWAY)
NO_FOLDERS = ("no server folders (one folder per server running a SiteMinder Web Agent or Access Gateway, named by "
              "its hostname, holding WebAgent.conf, SmHost.conf, LocalConfig.conf; a gateway's server.conf and "
              "proxyrules.xml too)",)

# An instance to read: its name, its WebAgent.conf, a gateway virtual host's names and settings, and the settings of
# its server.conf outside the virtual hosts (only their secrets are recorded, withheld: every instance of the gateway)
Plan = NamedTuple("Plan", [("name", str), ("path", str), ("hostnames", tuple), ("settings", tuple),
                           ("shared", tuple)])


def _of_kind(inner, kind):
    return tuple(sorted(p for p in inner if file_name(p) == kind))


def _folder(path):
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _near(paths, near):
    """The one of paths beside near (same folder), else the only one."""
    beside = tuple(p for p in paths if _folder(p) == _folder(near))
    return beside[0] if beside else (paths[0] if len(paths) == 1 else None)


def _found(paths, configured, near):
    return (matching(paths, configured) if configured else None) or _near(paths, near)


def _init_file(section):
    found = within(section, WEBAGENT_SECTION)
    return first(found[0].settings, INIT_FILE) if found else None


def _plans(inner):
    """The instances a server folder holds: a gateway's virtual hosts (server.conf), then every WebAgent.conf no
    virtual host claims (named by its ServerPath)."""
    agents = _of_kind(inner, WEBAGENT_CONF)
    conf = _of_kind(inner, SERVER_CONF)
    root = sections(inner[conf[0]]) if conf else None
    defaults = within(root, VIRTUAL_HOST_DEFAULTS) if root is not None else ()
    default_init = (_init_file(defaults[0]) if defaults else None) or DEFAULT_AGENT_FILE
    shared = settings_outside(root, VIRTUAL_HOST) if root is not None else ()
    hosts = tuple(Plan(attr(v, "name") or "default", matching(agents, _init_file(v) or default_init),
                       listed(named(v.settings, HOSTNAMES)), v.settings, shared)
                  for v in (within(root, VIRTUAL_HOST) if root is not None else ()))
    claimed = {p.path for p in hosts}
    rest = tuple(Plan(first(settings(inner[p]), NAMES["server_path"]) or "webagent", p, (), (), ())
                 for p in agents if p not in claimed)
    return tuple(p for p in (*hosts, *rest) if p.path)


def _withheld(label, pairs, patterns):
    """(names withheld, ("<file>: <name>: <what it is>; re-provision in the target", ...))."""
    held = tuple(dict.fromkeys(n for n, v in pairs if sensitive(n, (v,), patterns, scan)))
    return held, tuple(f"{label}: {n}: {purpose(n)}; re-provision in the target" for n in held)


def _kept(pairs, held):
    """{name: [values]} of the settings kept as other settings (not mapped to an attribute, not withheld)."""
    mapped = {m.lower() for m in MAPPED}
    names = tuple(dict.fromkeys(n for n, _ in pairs if n.lower() not in mapped and n not in held))
    return {n: [v for m, v in pairs if m == n] for n in names}


def _policy_servers(d, server, pairs):
    """(DNs of the policy servers of the server's environment its SmHost.conf names, the hosts the record lacks)."""
    hosts = tuple(v.split(",", 1)[0].strip() for v in named(pairs, NAMES["policy_server"]) if v.strip())
    env = server.dn.split(",", 1)[1]
    ours = tuple(s for s in children(d, env, "ciamServer") if one(s, "ciamServerRole") == POLICY_SERVER)
    found = tuple((h, next((s.dn for s in ours if h.lower() in ((one(s, "ciamHostname") or "").lower(),
                                                                   one(s, "ciamPrivateIp") or "")), None))
                  for h in hosts)
    return tuple(dict.fromkeys(dn for _, dn in found if dn)), tuple(h for h, dn in found if not dn)


def _source(d, kind, name):
    return get(d, carried_dn(kind, name)) if name else None


def _instance(d, server, inner, plan, dn, patterns):
    """(the smWebAgent entry at dn for a planned instance, notices)."""
    where = f"{rdn_value(server)}/{plan.name}"
    agent = settings(inner[plan.path])
    sm_path = _found(_of_kind(inner, SMHOST_CONF), first(agent, NAMES["host_config_file"]), plan.path)
    local_path = _found(_of_kind(inner, LOCAL_CONF), first(agent, NAMES["local_config_file"]), plan.path)
    smhost = settings(inner[sm_path]) if sm_path else ()
    local = settings(inner[local_path]) if local_path else ()
    names = {"aco": first(agent, NAMES["aco"]), "hco": first(smhost, NAMES["hco"]),
             "trusted-host": first(smhost, NAMES["trusted_host"])}
    linked = {k: _source(d, k, names[k]) for _, k in LINKED_KINDS}
    central = aco_parameters(linked["aco"])
    acting = identities(central, local)
    agents = tuple((n, get(d, agent_dn(n))) for n in acting)
    servers, unknown_hosts = _policy_servers(d, server, smhost)
    files = ((WEBAGENT_CONF, "WebAgent.conf", agent), (SMHOST_CONF, "SmHost.conf", smhost),
             (LOCAL_CONF, LOCAL_LABEL, local), (SERVER_CONF, "server.conf", plan.settings))
    held = tuple((key, label, pairs, *_withheld(label, pairs, patterns)) for key, label, pairs in files if pairs)
    kept = {label: _kept(pairs, names_held) for _, label, pairs, names_held, _ in held}
    _, shared_held = _withheld("server.conf", plan.shared, patterns)
    refused = tuple(n for n, _ in local if not is_allowed(allowed_local(central), n)) if linked["aco"] else ()
    e = entry(d, dn, ("top", "ciamObject", "smWebAgent"), {
        "cn": (dn.split(",", 1)[0].split("=", 1)[1],), "smServer": (server.dn,),
        "smEnabled": (("TRUE" if is_true(first(agent, NAMES["enabled"])) else "FALSE")
                      if first(agent, NAMES["enabled"]) else None,),
        "smActsAs": tuple(a.dn for _, a in agents if a is not None) or (None,),
        **{a: (linked[k].dn if linked[k] is not None else None,) for a, k in LINKED_KINDS},
        "smPolicyServer": servers or (None,), "smVirtualHost": plan.hostnames or (None,),
        "smConfig": (canonical({k: v for k, v in kept.items() if v}) if any(kept.values()) else None,),
        "smWithheld": tuple(dict.fromkeys((*(w for *_, ws in held for w in ws), *shared_held))) or (None,)})
    return e, (
        *(f"{where}: {kind.replace('-', ' ')} {names[kind]} isn't in the record: import the policy store export "
          "(siteminder/xps) first, then these files again" for _, kind in LINKED_KINDS
          if names[kind] and linked[kind] is None),
        *(f"{where}: acts as agent {n}, which the record doesn't hold: not linked" for n, a in agents if a is None),
        *((f"{where}: names no agent identity (DefaultAgentName, AgentName) the record can read",)
          if not acting and linked["aco"] is not None else ()),
        *(f"{where}: its policy server {h} isn't a server of role {POLICY_SERVER} in its environment: not linked"
          for h in unknown_hosts),
        *((f"{where}: LocalConfig.conf sets {', '.join(dict.fromkeys(refused))}, which ACO {names['aco']} doesn't "
           "allow local configuration of (AllowLocalConfig): the ACO's settings apply",) if refused else ()))


def _route_entries(d, server, inner, root):
    """(the smRoute entries of a gateway's proxy rules, notices)."""
    paths = _of_kind(inner, PROXY_RULES)
    dispatcher = within(root, DISPATCHER) if root is not None else ()
    path = (matching(paths, first(dispatcher[0].settings, RULES_FILE)) if dispatcher else None) or \
        (paths[0] if paths else None)
    if path is None:
        return (), (f"{rdn_value(server)}: an Access Gateway with no proxyrules.xml: its routes aren't read",)
    doc, why = rules_document(inner[path])
    if doc is None:
        return (), (f"{rdn_value(server)}: {path}: {why}, not read",)
    found, notes = routes(doc)
    return tuple(entry(d, f"cn={_prefix(server)}-route-{i},{ROUTES}", ("top", "ciamObject", "smRoute"), {
        "cn": (f"{_prefix(server)}-route-{i}",), "smServer": (server.dn,), "smCondition": r.conditions or (None,),
        "ciamOrder": (str(i),),
        "smRouteAction": (r.action,), "smRouteTarget": (r.target,),
        "smConfig": (canonical({"filter": r.filter}) if r.filter else None,)})
        for i, r in enumerate(found, 1)), tuple(f"{rdn_value(server)}: {n}" for n in notes)


def _prefix(server):
    """What a server's instances and routes are named after: <cloud>-<env>-<server>."""
    return name_of(f"{server_location(server).replace('/', '-')}-{rdn_value(server)}")


def _instance_dns(server, plans):
    """The DN of each planned instance (<cloud>-<env>-<server>-<instance>), its name made unique."""
    def step(acc, plan):
        dns, taken = acc
        n = unique(WEB_AGENTS, name_of(f"{_prefix(server)}-{plan.name}"), taken)
        return (*dns, f"cn={n},{WEB_AGENTS}"), taken | {(WEB_AGENTS, n.lower())}
    return reduce(step, plans, ((), frozenset()))[0]


def _server_groups(d, server, inner, patterns):
    """(groups, notices) for one server's folder: each instance and route it holds now, and an empty group for each
    the record holds of the server that it doesn't."""
    gateway = one(server, "ciamServerRole") == ACCESS_GATEWAY
    conf = _of_kind(inner, SERVER_CONF)
    root = sections(inner[conf[0]]) if conf and gateway else None
    plans = _plans(inner)
    made = tuple(_instance(d, server, inner, p, dn, patterns) for p, dn in zip(plans, _instance_dns(server, plans)))
    route_entries, route_notes = _route_entries(d, server, inner, root) if gateway else ((), ())
    now = (*(e for e, _ in made), *route_entries)
    mine = {e.norm for e in now}
    gone = tuple(e.dn for e in (*on_server(instances(d), server.dn), *on_server(children(d, ROUTES), server.dn))
                 if e.norm not in mine)
    return (*((e.dn, (e,)) for e in now), *((dn, ()) for dn in gone)), (
        *(n for _, ns in made for n in ns), *route_notes,
        *((f"{rdn_value(server)}: no WebAgent.conf: no agent instance read",) if not plans else ()),
        *((f"{rdn_value(server)}: holds server.conf or proxyrules.xml, but isn't an Access Gateway "
           f"({ACCESS_GATEWAY}): not read",)
          if not gateway and (conf or _of_kind(inner, PROXY_RULES)) else ()))


def _carried_updates(d, after):
    """The groups updating what the files change of the policy store export's source objects: the servers an ACO, HCO
    or trusted host concerns, and a gateway agent's routing dropped once its routes are read."""
    kinds = tuple(f"{k}-" for _, k in LINKED_KINDS)
    concerns = tuple(with_rest(d, so.dn, (entry(d, so.dn, so.classes, {"ciamConcerns": now or (None,)}),))
                     for so in children(d, CARRIED, "ciamSourceObject") if rdn_value(so).startswith(kinds)
                     for now in (file_concerns(after, so.dn),) if set(now) != set(values(so, "ciamConcerns")))
    routed = tuple((dn, ()) for a in children(after, AGENTS, "smAgent")
                   if one(a, "ciamTargetRole") == ACCESS_GATEWAY and has_routes(after, a)
                   for dn in routing_objects(after, a))
    return (*concerns, *routed)


def _unnamed_hosts(after):
    return tuple(f"trusted host {rdn_value(so)[len('trusted-host-'):]}: no server's SmHost.conf in the record names "
                 "it: import that server's files, or retire it" for so in children(after, CARRIED, "ciamSourceObject")
                 if rdn_value(so).startswith("trusted-host-") and not file_concerns(after, so.dn))


def read_agent_files(files, d, patterns, at=None):
    """Imported from SiteMinder agent and Access Gateway files, one folder per server."""
    folders = by_folder(files)
    placed = tuple((f, *server_named(d, f, SERVER_KINDS, "SiteMinder agent or Access Gateway server")) for f in folders)
    read = tuple(_server_groups(d, s, folders[f], patterns) for f, s, _ in placed if s is not None)
    containers = tuple(ou_entry(c) for c in (SITEMINDER, WEB_AGENTS, ROUTES)) if read else ()
    own = Imported(containers, tuple(g for gs, _ in read for g in gs), ())
    after = after_import(d, own)
    updates = _carried_updates(d, after)
    own = own._replace(groups=(*own.groups, *updates))
    after = after_import(d, own)
    held = sum(len(values(e, "smWithheld")) for gs, _ in read for _, es in gs for e in es if "smWebAgent" in e.classes)
    notices = (*(() if folders else NO_FOLDERS), *(why for _, s, why in placed if s is None),
               *(n for _, ns in read for n in ns), *(_unnamed_hosts(after) if read else ()),
               *((f"{held} sensitive setting(s) withheld, never stored (smWithheld names them): the agent files hold "
                  "them encrypted or in clear text: treat the files as secrets, and re-provision each in the target",)
                 if held else ()))
    return merged_import(own._replace(notices=notices), projection(after, at))


AGENT_FILES = Importer("agent-files", "SiteMinder Web Agent and Access Gateway files, one folder per server named by "
                                      "its hostname (WebAgent.conf, SmHost.conf, LocalConfig.conf; a gateway's "
                                      "server.conf and proxyrules.xml)", read_agent_files)

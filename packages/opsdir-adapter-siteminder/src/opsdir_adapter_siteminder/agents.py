"""SiteMinder's Web Agent instances as the record holds them (smWebAgent under ou=web-agents,ou=siteminder, each naming
its server: smServer; importer agent-files) and what they mean for the realms their agents protect. Pure.

  the agent identities an instance acts as    smActsAs (its effective DefaultAgentName and AgentName mappings)
  an agent's settings                         its ACO's parameters (the ACO's source object keeps them as smConfig),
                                              overlaid by an instance's LocalConfig.conf where the ACO allows it
                                              (conf.effective); every enabled instance acting as the agent, else
                                              the ACOs naming it
  what those settings pass through            IgnoreExt and IgnoreUrl: unprotected path resources of each application
                                              (realm) the agent enforces; settings its instances disagree on are
                                              narrowed to what they all pass through (the target leaves no more
                                              unprotected than the source), and a notice names them
  the servers a source object concerns        the servers whose files name an ACO, an HCO or a trusted host
  a server the record no longer holds         an instance or route naming it is reported (dangling), not linked
"""
import re

from opsdir.core.directory import children, follow, get, norm_dn, one, rdn_value, values
from opsdir.core.jsondata import held_json
from opsdir.domains.webaccess.naming import resource_dn
from opsdir.domains.webaccess.projection import neutral_entry
from .conf import ACO_PARAMETERS, LOCAL_LABEL, NAMES, agent_names, allowed_local, effective, listed, named, parameters
from .naming import AGENTS, CARRIED, ROUTES, WEB_AGENTS, name_of, named as dn_named

LINKS = ("smAgentConfig", "smHostConfig", "smTrustedHost")    # an instance's links to source objects
# the source object kinds an instance's files name, by the attribute naming them (carried.py names them <kind>-<name>)
LINKED_KINDS = (("smAgentConfig", "aco"), ("smHostConfig", "hco"), ("smTrustedHost", "trusted-host"))
FILE_KINDS = tuple(k for _, k in LINKED_KINDS)


def instances(d):
    """Every Web Agent instance the record holds, in DN order."""
    return children(d, WEB_AGENTS, "smWebAgent")


def server_of(d, e):
    """The server an instance runs on, or whose gateway a route is (smServer); None when the record no longer holds
    it."""
    return follow(d, e, "smServer")


def on_server(entries, server_dn):
    """The entries (instances, routes) naming a server."""
    return tuple(e for e in entries if norm_dn(one(e, "smServer") or "") == norm_dn(server_dn))


def server_label(d, e):
    """The name of the server an instance or route names (its DN when the record no longer holds it)."""
    s = server_of(d, e)
    return rdn_value(s) if s is not None else one(e, "smServer") or "?"


def dangling(d):
    """Notices for the instances and routes naming a server the record no longer holds."""
    return tuple(f"{rdn_value(e)}: its server {one(e, 'smServer')} isn't in the record: import that server's files "
                 "again under its new name, or remove the entry" for e in (*instances(d), *children(d, ROUTES))
                 if server_of(d, e) is None)


def carried_dn(kind, name):
    """The DN of the source object of kind named name (as the policy store export placed it)."""
    return dn_named(CARRIED, name_of(f"{kind}-{name}"))


def agent_dn(name):
    return dn_named(AGENTS, name_of(name))


def aco_parameters(aco):
    """((name, value), ...) of an ACO source object's parameters (none: no ACO)."""
    return parameters(held_json(aco, "smConfig").get(ACO_PARAMETERS) or ()) if aco is not None else ()


def local_settings(inst):
    """((name, value), ...) an instance's LocalConfig.conf sets (as smConfig keeps them)."""
    held = held_json(inst, "smConfig").get(LOCAL_LABEL) or {}
    return tuple((n, v) for n, vs in held.items() for v in vs)


def instance_settings(d, inst):
    """An instance's effective agent settings: its ACO's, overlaid by what its LocalConfig.conf may set."""
    central = aco_parameters(follow(d, inst, "smAgentConfig"))
    return effective(central, local_settings(inst), allowed_local(central))


def identities(central, local):
    """The agent names an instance acts as, from its ACO's parameters and its LocalConfig.conf settings."""
    return agent_names(effective(central, local, allowed_local(central)))


def acting_as(d, agent):
    """The enabled instances acting as an agent identity."""
    return tuple(i for i in instances(d) if one(i, "smEnabled") != "FALSE"
                 and any(get(d, a) is not None and get(d, a).norm == agent.norm for a in values(i, "smActsAs")))


def acos_naming(d, agent):
    """The ACO source objects whose parameters name an agent identity (DefaultAgentName, AgentName)."""
    return tuple(a for a in children(d, CARRIED, "ciamSourceObject") if rdn_value(a).startswith("aco-")
                 and any(name_of(n) == rdn_value(agent) for n in agent_names(aco_parameters(a))))


def _ignored(pairs):
    return listed(named(pairs, NAMES["ignore_ext"])), listed(named(pairs, NAMES["ignore_url"]))


def ignored_by(d, agent):
    """((extensions, URLs) an agent passes through unprotected, notices): what every enabled instance acting as it
    says (none: the ACOs naming it); what they don't all say is left out and named."""
    insts = acting_as(d, agent)
    found = tuple((rdn_value(i), _ignored(instance_settings(d, i))) for i in insts) \
        or tuple((rdn_value(a), _ignored(aco_parameters(a))) for a in acos_naming(d, agent))
    if not found:
        return ((), ()), ()
    exts, urls = (tuple(x for x in found[0][1][k] if all(x in f[1][k] for f in found)) for k in (0, 1))
    differ = tuple(w for w, (e, u) in found if set(e) != set(exts) or set(u) != set(urls))
    return (exts, urls), ((f"agent {rdn_value(agent)}: {', '.join(differ)} pass(es) more through unprotected "
                           f"(IgnoreExt, IgnoreUrl) than the rest; the record's applications pass through only what "
                           "they all do",) if differ else ())


def _relative(url, base):
    """A URL's path relative to a base path, or None when it isn't under it."""
    b = base.rstrip("/")
    return (url[len(b):] or "/") if url == b or url.startswith(b + "/") else None


def _ext_pattern(ext):
    return "/*" + (ext if ext.startswith(".") else "." + ext)


def ignored_resources(app, agent, ignored):
    """The unprotected path resources of an application an agent enforces: its ignored extensions anywhere below the
    base path (a wildcard), each ignored URL under it exactly (a URL takes no wildcard: KB 44956)."""
    exts, urls = ignored
    base = one(app, "ciamBasePath") or "/"
    found = (*((f"ignored-ext-{name_of(e.lstrip('.'))}", "wildcard", _ext_pattern(e)) for e in exts),
             *((f"ignored-url-{name_of(u.strip('/')) or 'root'}", *_exact(rel)) for u in urls
               for rel in (_relative(u, base),) if rel is not None))
    return tuple(neutral_entry(resource_dn(app.dn, cn), "ciamPathResource", {
        "cn": (cn,), "ciamPathPattern": (pattern,), "ciamMatchKind": (kind,), "ciamHttpMethod": (),
        "ciamAccessMode": ("unprotected",), "ciamRuleRef": (), "ciamProjectedFrom": (agent.dn,)})
        for cn, kind, pattern in found)


def _exact(path):
    """(match kind, pattern) matching exactly one path: a wildcard pattern with no '*', else an anchored regex."""
    return ("wildcard", path) if "*" not in path else ("regex", "^" + re.escape(path) + "$")


def file_concerns(d, dn):
    """The servers whose agent files name the source object at dn (an ACO, an HCO, a trusted host), in DN order (a
    server the record no longer holds is left out: dangling names it)."""
    return tuple(dict.fromkeys(server_of(d, i).dn for i in instances(d) if server_of(d, i) is not None
                               for a in LINKS if norm_dn(one(i, a) or "") == norm_dn(dn)))

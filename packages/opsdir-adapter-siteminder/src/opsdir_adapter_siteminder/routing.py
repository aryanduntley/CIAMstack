"""An Access Gateway's routes as the record holds them (smRoute under ou=routes,ou=siteminder, naming its server:
smServer; importer agent-files) and what they mean for the applications it protects. Pure.

  a realm's application, enforced by    the first route (in order) every request of the application takes (its virtual
  a gateway agent                       host's names and its base path decide host and uri conditions; a condition
                                        on anything else, or one only part of the application meets, is named in a
                                        notice) gives its backend role, port and TLS (the target host resolved in the
                                        record: a service name, an external host, a server) and the roles of the
                                        names it is published at; each only where it resolves
  a route no realm covers               traffic the gateway passes through unprotected: an application
                                        <agent>-<route> enforced by the gateway, no sign-on, one '/*' resource
                                        unprotected, with its backend
  a route sending another path          the neutral layer has no backend path: a blocking source object 'rewrite'
                                        (rebuild) concerning the application
  the gateway agent's routing           its source object (the policy store export's) is dropped once the record holds
                                        routes for a server acting as the agent
"""
from typing import NamedTuple, Optional
from urllib.parse import urlsplit

from opsdir.core.directory import children, get, gtime, norm_dn, one, rdn_value, values
from opsdir.core.environment import published_role
from opsdir.domains.webaccess.naming import app_dn, resource_dn
from opsdir.domains.webaccess.projection import neutral_entry
from .agents import acting_as, instances, on_server, server_label, server_of
from .entries import entry
from .naming import ACCESS_GATEWAY, CARRIED, ROUTES, name_of, named
from .proxyrules import parts

ROUTE_CLASS = "Access Gateway route"         # the source class of a rewrite's source object
_PORTS = {"http": "80", "https": "443"}

# A route sending an application's requests to another path: the application, where the route is, what it says
Rewrite = NamedTuple("Rewrite", [("app", str), ("route", str), ("conditions", tuple), ("target", str),
                                 ("base", str), ("path", str)])
# What the gateways say of the applications: {application DN: attributes}, uncovered applications with their resource,
# rewrites and notices
Gateways = NamedTuple("Gateways", [("attrs", dict), ("uncovered", tuple), ("rewrites", tuple), ("notices", tuple)])
Backend = NamedTuple("Backend", [("role", Optional[str]), ("host", str), ("port", str), ("tls", str), ("path", str)])


def routes_of(d, server_dn):
    """A gateway server's routes, in the order it tries them."""
    return tuple(sorted(on_server(children(d, ROUTES, "smRoute"), server_dn),
                        key=lambda r: (int(one(r, "ciamOrder") or 0), r.dn)))


def has_routes(d, agent):
    """Whether the record holds the routes of a server acting as a gateway agent."""
    return any(routes_of(d, one(i, "smServer")) for i in acting_as(d, agent) if one(i, "smServer"))


def routing_objects(d, agent):
    """The DNs of the routing source objects the policy store export carried for a gateway agent."""
    return tuple(o.dn for o in children(d, CARRIED, "ciamSourceObject") if one(o, "ciamSourceClass") == "CA.SM::Agent"
                 and one(o, "smXid") and one(o, "smXid") == one(agent, "smXid"))


def host_role(d, host):
    """The role a host is in the record: the binding role it is published as, else a server's role at that hostname or
    address; None when the record doesn't know it."""
    servers = (s for s in d.entries.values() if "ciamServer" in s.classes
               and host.lower() in ((one(s, "ciamHostname") or "").lower(), one(s, "ciamPrivateIp") or ""))
    return published_role(d, host) or next((one(s, "ciamServerRole") for s in servers), None)


def _host_meets(h, criteria, value):
    h, value = h.lower(), value.lower()
    return {"equals": h == value, "beginswith": h.startswith(value), "endswith": h.endswith(value),
            "contains": value in h, "exists": True}.get(criteria, False)


def _verdict(c, hosts, base):
    """'all', 'some' or 'none': how many of an application's requests (at hosts, below base) meet a condition."""
    kind, _, criteria, value = parts(c)
    if kind == "host" and hosts:
        met = tuple(_host_meets(h, criteria, value) for h in hosts)
        return "all" if all(met) else "some" if any(met) else "none"
    if kind == "uri" and criteria == "beginswith":
        return "all" if base.startswith(value) else "some" if value.startswith(base.rstrip("/")) else "none"
    if kind == "uri" and criteria == "equals":
        return "some" if value.startswith(base.rstrip("/")) else "none"
    return "some"


def coverage(conditions, hosts, base):
    found = tuple(_verdict(c, hosts, base) for c in conditions)
    return "none" if "none" in found else "all" if all(v == "all" for v in found) else "some"


def _prefix(conditions):
    return next((parts(c)[3] for c in conditions if parts(c)[0] == "uri" and parts(c)[2] == "beginswith"), "")


def backend(d, target, base, prefix):
    """The Backend a forward target sends requests below base to ($0 the request URI, $1 what follows prefix), or None
    when it names a regular expression's other groups or no host."""
    sent = target.replace("$0", base).replace("$1", base[len(prefix):] if base.startswith(prefix) else base)
    url = urlsplit(sent) if "$" not in sent else None
    if url is None or not url.hostname:
        return None
    return Backend(host_role(d, url.hostname), url.hostname, str(url.port) if url.port else _PORTS.get(url.scheme, ""),
                   "TRUE" if url.scheme == "https" else "FALSE", url.path or "/")


def _rewrites(path, base):
    return path.rstrip("/") != base.rstrip("/")


def _published(d, hosts):
    roles = tuple(published_role(d, h) for h in hosts)
    return tuple(dict.fromkeys(roles)) if roles and None not in roles else None


def _host_condition(conditions):
    return next((parts(c)[3] for c in conditions if parts(c)[0] == "host" and parts(c)[2] == "equals"), None)


def route_name(r):
    """What a route is called on its gateway: route-<its place among the routes>."""
    return f"route-{one(r, 'ciamOrder')}"


def _route_label(d, r):
    return f"{server_label(d, r)}/{route_name(r)}"


def _app_route(d, inst, base):
    """(the route every request of an application at an instance's virtual host takes, or None; the routes before it
    that take only some of them)."""
    hosts = values(inst, "smVirtualHost")
    found = tuple((r, coverage(values(r, "smCondition"), hosts, base)) for r in routes_of(d, one(inst, "smServer")))
    chosen = next((r for r, v in found if v == "all"), None)
    before = tuple(r for r, v in found[:next((i for i, (_, v) in enumerate(found) if v == "all"), len(found))]
                   if v == "some")
    return chosen, before


def _app_attrs(d, app, inst):
    """(attributes, rewrite or None, notices) a gateway instance's routes give an application it enforces."""
    base, name = one(app, "ciamBasePath") or "/", rdn_value(app)
    route, before = _app_route(d, inst, base)
    notes = tuple(f"protected application {name}: route {_route_label(d, r)} ({'; '.join(values(r, 'smCondition'))}) "
                  "takes only some of its requests: its backend is the first route taking them all" for r in before)
    if route is None:
        return {}, None, (*notes, f"protected application {name}: no route of {server_label(d, inst)} takes every "
                                  "request of it: its backend isn't known")
    conds = values(route, "smCondition")
    if one(route, "smRouteAction") != "forward":
        return {}, None, (*notes, f"protected application {name}: route {_route_label(d, route)} redirects it to "
                                  f"{one(route, 'smRouteTarget')}: rebuild the redirect in the target gateway")
    found = backend(d, one(route, "smRouteTarget"), base, _prefix(conds))
    if found is None:
        return {}, None, (*notes, f"protected application {name}: route {_route_label(d, route)} forwards to "
                                  f"{one(route, 'smRouteTarget')}, which names no host the record can read")
    hosts = values(inst, "smVirtualHost") or tuple(h for h in (_host_condition(conds),) if h)
    published = _published(d, hosts)
    attrs = {**({"ciamBackendRole": (found.role,)} if found.role else {}), "ciamBackendPort": (found.port,),
             "ciamBackendTls": (found.tls,), **({"ciamPublishedAs": published} if published else {})}
    rewrite = Rewrite(app.dn, route.dn, conds, one(route, "smRouteTarget"), base, found.path) \
        if _rewrites(found.path, base) else None
    return attrs, rewrite, (*notes, *((f"protected application {name}: its backend host {found.host} isn't in the "
                                       "record (a service name, an external host or a server): record its role",)
                                      if not found.role else ()),
                            *((f"protected application {name}: {', '.join(hosts) or 'its host'} isn't published by a "
                               "service name the record holds: record the role clients reach it at",)
                              if hosts and not published else ()))


def _is_gateway(d, inst):
    server = server_of(d, inst)
    return server is not None and one(server, "ciamServerRole") == ACCESS_GATEWAY


def _gateway_instances(d, agent):
    return tuple(i for i in acting_as(d, agent) if _is_gateway(d, i))


def _under(path, base):
    b = base.rstrip("/")
    return path.rstrip("/") == b or path.startswith(b + "/") or not b


def _covered(d, prefix, agents, apps):
    """Whether a realm of one of agents covers every request a route below prefix takes."""
    acting = {get(d, x).norm for x in agents if get(d, x) is not None}
    return any(agent and get(d, agent) is not None and get(d, agent).norm in acting
               and _under(prefix, one(a, "ciamBasePath") or "/") for a, agent in apps)


def _route_finding(d, r, insts, apps):
    """((application, resources) or None, rewrite or None, notices) of one route of a gateway server: an application
    when no realm of the agents serving it covers what it forwards."""
    conds = values(r, "smCondition")
    odd = tuple(c for c in conds if (parts(c)[0], parts(c)[2]) not in (("host", "equals"), ("uri", "beginswith"),
                                                                         ("uri", "equals")))
    if odd:
        return None, None, (f"route {_route_label(d, r)} ({'; '.join(conds)}): {one(r, 'smRouteAction')}s on "
                            "conditions the record can't place on an application: rebuild it in the target gateway",)
    host, prefix = _host_condition(conds), next((parts(c)[3] for c in conds if parts(c)[0] == "uri"), "/")
    serving = tuple(i for i in insts if host and host.lower() in (h.lower() for h in values(i, "smVirtualHost"))) \
        or tuple(i for i in insts if not host or not values(i, "smVirtualHost"))
    agents = tuple(a for i in serving for a in values(i, "smActsAs"))
    if _covered(d, prefix, agents, apps):
        return None, None, ()
    if one(r, "smRouteAction") != "forward":
        return None, None, (f"route {_route_label(d, r)} ({'; '.join(conds) or 'every request'}) redirects to "
                            f"{one(r, 'smRouteTarget')}: rebuild the redirect in the target gateway",)
    return _uncovered_app(d, r, prefix, host, serving, agents)


def _uncovered(d, server_dn, apps):
    """The findings of each route of a gateway server (_route_finding)."""
    insts = on_server(instances(d), server_dn)
    return tuple(_route_finding(d, r, insts, apps) for r in routes_of(d, server_dn))


def _uncovered_app(d, r, prefix, host, serving, agents):
    agent = get(d, agents[0]) if agents else None
    name = name_of(f"{rdn_value(agent) if agent is not None else server_label(d, r)}-{route_name(r)}")
    base = prefix if prefix.startswith("/") else "/" + prefix
    found = backend(d, one(r, "smRouteTarget"), base, _prefix(values(r, "smCondition")))
    hosts = (host,) if host else tuple(h for i in serving for h in values(i, "smVirtualHost"))
    published = _published(d, hosts)
    dn = app_dn(name)
    app = neutral_entry(dn, "ciamProtectedApp", {
        "cn": (name,), "ciamBasePath": (base,),
        "ciamEnforcedByRole": ((one(agent, "ciamTargetRole") if agent is not None else None) or ACCESS_GATEWAY,),
        "ciamSignOn": ("none",), **({"ciamBackendRole": (found.role,)} if found and found.role else {}),
        **({"ciamBackendPort": (found.port,), "ciamBackendTls": (found.tls,)} if found else {}),
        **({"ciamPublishedAs": published} if published else {}), "ciamRuleRef": (), "ciamProjectedFrom": (r.dn,)})
    resource = neutral_entry(resource_dn(dn, "all"), "ciamPathResource", {
        "cn": ("all",), "ciamPathPattern": ("/*",), "ciamMatchKind": ("wildcard",), "ciamHttpMethod": (),
        "ciamAccessMode": ("unprotected",), "ciamRuleRef": (), "ciamProjectedFrom": (r.dn,)})
    rewrite = Rewrite(dn, r.dn, values(r, "smCondition"), one(r, "smRouteTarget"), base, found.path) \
        if found is not None and _rewrites(found.path, base) else None
    return (app, (resource,)), rewrite, (
        f"route {_route_label(d, r)} ({'; '.join(values(r, 'smCondition')) or 'every request'}) passes {base} "
        f"through to {one(r, 'smRouteTarget')} with no realm protecting it: projected as unprotected application "
        f"{name}",
        *((f"protected application {name}: its backend host {found.host} isn't in the record (a service name, an "
           "external host or a server): record its role",) if found is not None and not found.role else ()),
        *((f"protected application {name}: {', '.join(hosts)} isn't published by a service name the record holds: "
           "record the role clients reach it at",) if hosts and not published else ()))


def gateways(d, apps):
    """Gateways of what the record's gateway servers say of apps ((realm application entry, agent DN), ...) and of the
    routes no realm covers."""
    told = tuple((app.dn, _app_attrs(d, app, inst)) for app, agent in apps if get(d, agent) is not None
                 for inst in _gateway_instances(d, get(d, agent))[:1])
    servers = tuple(dict.fromkeys(server_of(d, i).dn for i in instances(d) if _is_gateway(d, i)))
    loose = tuple(x for s in servers for x in _uncovered(d, s, apps))
    uncovered = tuple({a[0].norm: a for a, _, _ in loose if a is not None}.values())
    return Gateways({dn: attrs for dn, (attrs, _, _) in told},
                    uncovered, tuple(rw for rw in (*(rw for _, (_, rw, _) in told), *(rw for _, rw, _ in loose))
                                     if rw is not None),
                    (*(n for _, (_, _, ns) in told for n in ns), *(n for _, _, ns in loose for n in ns)))


def rewrite_entries(d, rewrites, at):
    """The groups of the rewrites' source objects (rewrite-<application> under ou=siteminder,ou=source-objects), and
    an empty group for each the record holds that no route makes now. Once recorded, a rewrite's handling is the
    record's."""
    def group(rw):
        dn = named(CARRIED, name_of(f"rewrite-{rw.app.split(',', 1)[0].split('=', 1)[1]}"))
        decided = {} if get(d, dn) is not None else {
            "ciamHandling": ("rebuild",), "ciamBlocking": ("TRUE",),
            "ciamHow": (f"the gateway sends {rw.base} to {rw.path} on the application, which the target's protected "
                        "application can't say (it has no backend path): rebuild the rewrite in the target gateway, "
                        f"or have the application answer at {rw.base}, before it moves",)}
        return dn, (entry(d, dn, ("top", "ciamObject", "ciamSourceObject"), {
            "cn": (rdn_value(get(d, dn)) if get(d, dn) is not None else dn.split(",", 1)[0].split("=", 1)[1],),
            "ciamSourceClass": (ROUTE_CLASS,), "ciamTargetRole": (ACCESS_GATEWAY,),
            "ciamSourceFact": (f"Route {_route_label(d, get(d, rw.route))}",
                               f"Conditions {'; '.join(rw.conditions) or 'none'}", f"Forward {rw.target}",
                               f"Path {rw.base} -> {rw.path}"),
            **decided, "ciamConcerns": (rw.app,), "ciamImportedAt": (gtime(at) if at else None,)}),)
    made = tuple(group(rw) for rw in rewrites)
    mine = {norm_dn(dn) for dn, _ in made}
    stale = tuple((o.dn, ()) for o in children(d, CARRIED, "ciamSourceObject")
                  if one(o, "ciamSourceClass") == ROUTE_CLASS and o.norm not in mine)
    return (*made, *stale)

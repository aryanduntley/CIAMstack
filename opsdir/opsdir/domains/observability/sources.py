"""Log sources: which lines of the logs products declare (core.contract.LogSource) a log route picks. Pure.

A log route selects log kinds (ciamLogKind) from server roles (ciamPublishedBy). A source holds the kinds its match
rules give and its own kind (the kind of lines no rule classifies). A collector ships a source whole when the route
wants every kind it holds, filters it by content when the route wants some of them (the rules in order, first match
wins, then the source's kind for the rest), and leaves it out otherwise.

A file's path is relative to its server's install root (ciamInstallRoot), which the record states per server and
nothing guesses: a server without one is named, and its files aren't collected.

What a provider adapter renders a collector from (shipments): for each collection with a source, where the route's
logs go in the environment (the binding its ciamLogDestinationRole names) and, on servers, the absolute file glob per
install root with the servers sharing that root (a collector configuration is the same for them, and differs from
the others').
"""
from collections import namedtuple

from ...core.directory import one, rdn_value, values
from ...core.environment import one_role, servers_with_role
from ..access.principals import permits, principals
from ..compute.workloads import kubernetes_roles
from .naming import LOG_KINDS

LOG_PLACES = ("servers", "kubernetes")          # LogSource.on
LOG_FORMATS = ("json-lines", "text", "mixed")   # LogSource.format
ALL, SOME, NONE = "all", "some", "none"         # what a route picks from a source
COLLECTION_HEADERS = ("log route", "server role", "runs on", "log", "lines", "status")

# What an environment collects for a log route from one server role in one place (on, as LogSource.on): source the
# LogSource it picks lines from (ALL or SOME: lines), or None when the products declare no log of the route's kinds
# there (lines NONE; held then the kinds the role's logs there do hold); unrooted the names of the role's servers
# recording no install root (on servers only).
Collection = namedtuple("Collection", ("route", "role", "on", "source", "lines", "unrooted", "held"),
                        defaults=((),))
# What a collector ships for a Collection with a source: destination the binding of the environment the route's
# ciamLogDestinationRole names (None when it binds none); on servers, path the source's file glob under the install
# root root, and hosts the names of the role's servers installed there (on kubernetes: root and path None, hosts ()).
Shipment = namedtuple("Shipment", ("route", "role", "on", "source", "lines", "destination", "root", "path",
                                   "hosts"))


def kinds_of(source):
    """The kinds a source's lines can have: its match rules' kinds, then its own, once each."""
    return tuple(dict.fromkeys((*(kind for _, _, kind in source.match), source.kind)))


def kind_of(source, record):
    """The kind of one line of a source: record is the line's JSON object (a dict), or None for a text line. The
    first rule whose field (a top-level string) starts with its prefix gives it; otherwise the source's kind."""
    rule = next((kind for field, prefix, kind in source.match
                 if record is not None and isinstance(record.get(field), str) and record[field].startswith(prefix)),
                None)
    return rule or source.kind


def picks(source, kinds):
    """What a route wanting kinds picks from a source: ALL its lines, SOME (filtered by content), or NONE."""
    held = kinds_of(source)
    wanted = tuple(k for k in held if k in kinds)
    return ALL if len(wanted) == len(held) else SOME if wanted else NONE


# One way a route keeps a line of a source it picks SOME of: match a (JSON field, value prefix) rule the line must
# satisfy ("" prefix: the field is there), or None for lines no rule matches; excluded the rules the line must not
# satisfy. A line is kept when any clause holds. Providers write it in their filter syntax.
Clause = namedtuple("Clause", ("match", "excluded"))


def kept_clauses(source, kinds):
    """The Clauses keeping exactly the lines of a source whose kind (kind_of: first matching rule, else the source's
    kind) a route wants: per wanted rule, its match without the earlier unwanted rules; for the source's own kind, no
    unwanted rule. Rules of wanted kinds are never excluded (a line they match is kept either way)."""
    def unwanted(rules):
        return tuple(dict.fromkeys((f, p) for f, p, k in rules if k not in kinds))
    return (*(Clause((f, p), unwanted(source.match[:i])) for i, (f, p, k) in enumerate(source.match) if k in kinds),
            *((Clause(None, unwanted(source.match)),) if source.kind in kinds else ()))


def route_sources(sources, roles, kinds, on=None):
    """((source, ALL | SOME), ...): the sources of the server roles (and, given on, of that place) a route wanting
    kinds picks lines from, in declaration order."""
    return tuple((s, p) for s in sources
                 if s.server_role in roles and (on is None or s.on == on)
                 for p in (picks(s, kinds),) if p != NONE)


def unrooted(m, role):
    """The names of environment m's servers of a role that record no install root (ciamInstallRoot)."""
    return tuple(rdn_value(s) for s in servers_with_role(m, role) if not one(s, "ciamInstallRoot"))


def _places(m, role):
    return (*(("servers",) if servers_with_role(m, role) else ()),
            *(("kubernetes",) if role in kubernetes_roles(m) else ()))


def collections(m, routes, sources):
    """The Collections of environment m for log routes, given the LogSources its products declare: for each route,
    each server role it collects from that m runs, and each place m runs it, the sources the route picks lines from
    (one Collection with source None when there are none)."""
    def of(r, role, on):
        missing = unrooted(m, role) if on == "servers" else ()
        found = tuple(Collection(r, role, on, s, lines, missing)
                      for s, lines in route_sources(sources, (role,), values(r, "ciamLogKind"), on))
        held = tuple(dict.fromkeys(k for s in sources if s.server_role == role and s.on == on for k in kinds_of(s)))
        return found or (Collection(r, role, on, None, NONE, (), held),)
    return tuple(c for r in routes for role in values(r, "ciamPublishedBy") for on in _places(m, role)
                 for c in of(r, role, on))


def under(root, path):
    """A path relative to an install root, made absolute under it."""
    return f"{root.rstrip('/')}/{path.lstrip('/')}"


def _roots(m, role):
    """((install root, (server names, ...)), ...) of the role's servers that record one, in record order."""
    rooted = [(one(s, "ciamInstallRoot"), rdn_value(s)) for s in servers_with_role(m, role)
              if one(s, "ciamInstallRoot")]
    return tuple((root, tuple(n for r, n in rooted if r == root)) for root in dict.fromkeys(r for r, _ in rooted))


def shipments(m, routes, sources):
    """The Shipments of environment m for log routes, given the declared LogSources: one per collection with a source
    and, on servers, per install root its role's servers record (none for a role whose servers record none)."""
    def of(c):
        dest = one_role(m, one(c.route, "ciamLogDestinationRole") or "")
        if c.on == "kubernetes":
            return (Shipment(c.route, c.role, c.on, c.source, c.lines, dest, None, None, ()),)
        return tuple(Shipment(c.route, c.role, c.on, c.source, c.lines, dest, root, under(root, c.source.path), hosts)
                     for root, hosts in _roots(m, c.role))
    return tuple(x for c in collections(m, routes, sources) if c.source is not None for x in of(c))


def unpermitted(m, found):
    """((server role, destination role), ...) of host Shipments whose role's servers no workload principal lets write
    to the route's destination: none acting for the role (ciamTargetRole) holds the permit `write-logs <role>`. For
    clouds whose agents write as the server's own identity."""
    def allowed(role, dest):
        return any(f"write-logs {dest}" in permits(m.d, p) for p in principals(m.d)
                   if one(p, "ciamPrincipalKind") == "workload" and one(p, "ciamTargetRole") == role)
    pairs = dict.fromkeys((x.role, one(x.route, "ciamLogDestinationRole")) for x in found if x.on == "servers")
    return tuple((role, dest) for role, dest in pairs if not allowed(role, dest))


def uncollected(c):
    """Why nothing ships a Collection without a source, in words."""
    return f"its logs here hold only {', '.join(c.held)}" if c.held else "no product declares its logs here"


def _status(c):
    if c.source is None:
        return uncollected(c)
    kinds = values(c.route, "ciamLogKind")
    switched = c.source.requires and any(k in kinds for _, _, k in c.source.match)
    return "; ".join((*((f"no install root: {', '.join(c.unrooted)}",) if c.unrooted else ()),
                      *((f"needs {c.source.requires}",) if switched else ())))


def _output(source):
    return f"container {source.container} output" if source.container else "container output"


def collection_rows(m, routes, sources):
    """One row per Collection of environment m (COLLECTION_HEADERS): where each log route's logs come from, whether
    all of a log's lines or those its content marks as the route's kinds, and what stops them shipping."""
    return [(rdn_value(c.route), c.role, c.on, "" if c.source is None else c.source.path or _output(c.source),
             {ALL: "all", SOME: "by content"}.get(c.lines, ""), _status(c))
            for c in collections(m, routes, sources)]


def declaration_problems(source):
    """What is wrong with a declared source, in words: () when nothing is."""
    return (*((f"kind `{k}` is not a log kind" for k in kinds_of(source) if k not in LOG_KINDS)),
            *((f"place `{source.on}` is not one of {', '.join(LOG_PLACES)}",) if source.on not in LOG_PLACES else ()),
            *((f"format `{source.format}` is not one of {', '.join(LOG_FORMATS)}",)
              if source.format not in LOG_FORMATS else ()),
            *(("a file on servers needs a path relative to the install root",)
              if source.on == "servers" and not source.path else ()),
            *(("container output has no path",) if source.on == "kubernetes" and source.path else ()),
            *(("a file on servers has no container",) if source.on == "servers" and source.container else ()),
            *(("match rules need JSON lines",) if source.match and source.format == "text" else ()))

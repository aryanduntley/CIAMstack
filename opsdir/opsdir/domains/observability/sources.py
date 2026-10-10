"""Log sources: which lines of the logs products declare (core.contract.LogSource) a log route picks. Pure.

A log route selects log kinds (ciamLogKind) from server roles (ciamPublishedBy). A source holds the kinds its match
rules give and its own kind (the kind of lines no rule classifies). A collector ships a source whole when the route
wants every kind it holds, filters it by content when the route wants some of them (the rules in order, first match
wins, then the source's kind for the rest), and leaves it out otherwise.

A file's path is relative to its server's install root (ciamInstallRoot), which the record states per server and
nothing guesses: a server without one is named, and its files aren't collected.
"""
from collections import namedtuple

from ...core.directory import one, rdn_value, values
from ...core.environment import servers_with_role
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


def collection_rows(m, routes, sources):
    """One row per Collection of environment m (COLLECTION_HEADERS): where each log route's logs come from, whether
    all of a log's lines or those its content marks as the route's kinds, and what stops them shipping."""
    return [(rdn_value(c.route), c.role, c.on, "" if c.source is None else c.source.path or "container output",
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
            *(("match rules need JSON lines",) if source.match and source.format == "text" else ()))

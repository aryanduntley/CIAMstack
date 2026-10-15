"""The dependency graph around an entry (milestone 6.4): what it depends on and what depends on it, from what the
record already says, as data the front ends write as JSON, DOT or a tree. Pure.

An edge says its source names its target: by a dn-valued attribute (kind dn: an integration's certificate, an ACI's
grantee consumer, an application's part), or by a binding role an attribute names (kind role: a canary's checked
service, a job's secret role) to a role node, role:<name>, which each environment binds its own way (kind binding: the
bindings realizing it in the environment asked for, and a binding's own role wherever it is), or by a server role
(ciamTargetRole) to server-role:<name>, run by the environment's servers of that role. Down follows what the root
names; up, what names the root. Owners, change records, incidents and rotation work instructions point at an entry
without the entry depending on them (as the blast-radius report skips them): they are no edges; a node names its
owners.
"""
import re
from functools import reduce
from typing import NamedTuple, Optional

from ..core.directory import get, rdn_value, referrers, value_type, values
from ..core.environment import by_role, servers_with_role
from ..core.naming import env_label

# A node: id (an entry's DN, role:<name> or server-role:<name>), kind (an entry's object class, role or server-role),
# label (an entry's RDN value, the role's name), owner (its owners' names, '' for none)
Node = NamedTuple("Node", [("id", str), ("kind", str), ("label", str), ("owner", str)])
# An edge: source names target, via that attribute; kind dn, role (an entry naming a role) or binding (a role realized)
Edge = NamedTuple("Edge", [("source", str), ("target", str), ("via", str), ("kind", str)])
# The graph around root: direction (down, up, both), depth, environment (the label roles were bound in, or None)
Graph = NamedTuple("Graph", [("root", str), ("direction", str), ("depth", int), ("environment", Optional[str]),
                             ("nodes", tuple), ("edges", tuple)])

DIRECTIONS = ("down", "up", "both")
MAX_DEPTH = 6
# what points at an entry without the entry depending on it (as graph.sql's dependents() skips them)
NOT_DEPENDENCIES = frozenset({"ciamOwner", "ciamChangeRef", "ciamInvolved", "ciamRotationRunbook"})
# an entry's own role (a binding's, a server's): what it realizes, not what it names
OWN_ROLES = frozenset({"ciamBindingRole", "ciamServerRole"})
SERVER_ROLE_REFS = frozenset({"ciamTargetRole"})
CHECKED = "ciamCheckedService"                 # a canary's checked service: a binding role by another name
ROLE, SERVER_ROLE = "role:", "server-role:"
_IN_ENVIRONMENT = re.compile(r",env=[^,]+,cloud=[^,]+,ou=environments,.*$", re.I)


def role_attributes(d):
    """The attributes naming a binding role (or, SERVER_ROLE_REFS, a server role): every ...Role attribute but an
    entry's own role (OWN_ROLES), and a canary's checked service."""
    return frozenset(a for a in d.types if (a.endswith("Role") and a not in OWN_ROLES) or a == CHECKED)


def owners_of(d, e):
    """The names of an entry's owners (ciamOwner), comma-joined; '' for none."""
    return ", ".join(rdn_value(o) if o is not None else v for v in values(e, "ciamOwner") for o in (get(d, v),))


def _role_node(attr, role):
    return (SERVER_ROLE if attr in SERVER_ROLE_REFS else ROLE) + role


def _named(d, e, roles):
    """The edges of what entry e names (down): its dn-valued attributes' targets, its role attributes' role nodes."""
    return (*(Edge(e.dn, get(d, v).dn, a, "dn") for a, vs in sorted(e.attrs.items()) if a not in NOT_DEPENDENCIES
              and value_type(d, a) == "dn" for v in vs if get(d, v) is not None),
            *(Edge(e.dn, _role_node(a, v), a, "role") for a, vs in sorted(e.attrs.items()) if a in roles for v in vs))


def _naming(d, e):
    """The edges of what names entry e (up): dn-valued references to it, and the role node of a binding's or a
    server's own role (realized here)."""
    refs = sorted((Edge(r.dn, e.dn, a, "dn") for a, r in referrers(d, e) if a not in NOT_DEPENDENCIES),
                  key=lambda x: (x.source, x.via))
    return (*refs, *(Edge(ROLE + r, e.dn, "ciamBindingRole", "binding") for r in values(e, "ciamBindingRole")),
            *(Edge(SERVER_ROLE + r, e.dn, "ciamServerRole", "binding") for r in values(e, "ciamServerRole")))


def _bindings(m, node):
    """The edges from a role node to what realizes it in environment model m (None: none, the role is a leaf)."""
    if m is None:
        return ()
    if node.startswith(SERVER_ROLE):
        return tuple(Edge(node, s.dn, "ciamServerRole", "binding")
                     for s in servers_with_role(m, node[len(SERVER_ROLE):]))
    return tuple(Edge(node, b.dn, "ciamBindingRole", "binding") for b in by_role(m, node[len(ROLE):]))


def _role_users(d, node, roles):
    """The edges of what names a role node (up): every entry naming that role in an attribute of its kind."""
    server = node.startswith(SERVER_ROLE)
    role = node.split(":", 1)[1]
    return tuple(Edge(e.dn, node, a, "role") for e in sorted(d.entries.values(), key=lambda x: x.dn)
                 for a in sorted(roles) if (a in SERVER_ROLE_REFS) == server and role in values(e, a))


def _step(d, node, way, roles, m):
    """The edges one step from a node, down (what it names) or up (what names it)."""
    is_role = node.startswith((ROLE, SERVER_ROLE))
    if way == "down":
        return _bindings(m, node) if is_role else _named(d, get(d, node), roles)
    return _role_users(d, node, roles) if is_role else _naming(d, get(d, node))


def _walk(d, root, way, depth, roles, m):
    """The edges within depth steps of root in one direction, breadth first, each once."""
    def grow(acc, _):
        seen, frontier, edges = acc
        fresh = tuple(dict.fromkeys(x for n in frontier for x in _step(d, n, way, roles, m) if x not in edges))
        reached = tuple(dict.fromkeys(x.target if way == "down" else x.source for x in fresh))
        return seen | set(reached), tuple(n for n in reached if n not in seen), (*edges, *fresh)
    return reduce(grow, range(depth), (frozenset({root}), (root,), ()))[2]


def _depth(d, oc):
    return 1 + _depth(d, d.supers[oc]) if d.supers.get(oc) else 1


def entry_kind(d, e):
    """An entry's kind as a node shows it: its most specific object class (the longest line of superclasses; an
    auxiliary class added to it, such as a product's settings, sits right under top)."""
    return max(e.classes, key=lambda oc: _depth(d, oc))


def _node(d, node):
    if node.startswith((ROLE, SERVER_ROLE)):
        kind, name = node.split(":", 1)
        return Node(node, kind, name, "")
    e = get(d, node)
    return Node(e.dn, entry_kind(d, e), node_label(e), owners_of(d, e))


def node_label(e):
    """An entry's label: its RDN value, and the environment it is in (cloud/env) for one under an environment (its
    bindings and servers have the same names from one environment to the next)."""
    found = _IN_ENVIRONMENT.search(e.dn)
    return rdn_value(e) + (f" [{env_label(found.group(0)[1:])}]" if found else "")


def dependency_graph(d, dn, direction="both", depth=3, m=None):
    """The Graph around entry dn of record d: what it depends on (down), what depends on it (up) or both, depth steps
    out (at most MAX_DEPTH); role nodes linked to their bindings in environment model m (None: roles are leaves, but a
    binding's own role still links to it). SystemExit for an entry the record doesn't hold, an unknown direction or a
    depth outside 1..MAX_DEPTH."""
    e = get(d, dn)
    if e is None:
        raise SystemExit(f"no entry {dn} in the record")
    if direction not in DIRECTIONS:
        raise SystemExit(f"unknown direction {direction!r} (one of {', '.join(DIRECTIONS)})")
    if not 1 <= depth <= MAX_DEPTH:
        raise SystemExit(f"depth {depth}: give 1 to {MAX_DEPTH}")
    roles = role_attributes(d)
    ways = ("down", "up") if direction == "both" else (direction,)
    edges = tuple(dict.fromkeys(x for way in ways for x in _walk(d, e.dn, way, depth, roles, m)))
    ids = tuple(dict.fromkeys((e.dn, *(n for x in edges for n in (x.source, x.target)))))
    return Graph(e.dn, direction, depth, m.label if m is not None else None,
                 tuple(sorted((_node(d, n) for n in ids), key=lambda x: x.id)),
                 tuple(sorted(edges, key=lambda x: (x.source, x.target, x.via))))


# ------------------------------------------------------------------ as the front ends write it
def graph_document(g):
    """The graph as a JSON-ready document: root, direction, depth, environment, nodes and edges (sorted: stable)."""
    return {"root": g.root, "direction": g.direction, "depth": g.depth, "environment": g.environment,
            "nodes": [n._asdict() for n in g.nodes], "edges": [x._asdict() for x in g.edges]}


def _dot_id(v):
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def graph_dot(g):
    """The graph in Graphviz DOT: a digraph, a box per entry (label: its name and class, the root bold), an ellipse
    per role, an edge per reference labelled by its attribute, role and binding edges dashed."""
    label = next(n.label for n in g.nodes if n.id == g.root)
    nodes = (f"  {_dot_id(n.id)} [label={_dot_id(n.label + chr(10) + n.kind)}"
             f"{', style=bold' if n.id == g.root else ''}"
             f"{', shape=ellipse' if n.kind in ('role', 'server-role') else ''}];" for n in g.nodes)
    edges = (f"  {_dot_id(x.source)} -> {_dot_id(x.target)} [label={_dot_id(x.via)}"
             f"{', style=dashed' if x.kind != 'dn' else ''}];" for x in g.edges)
    return "\n".join((f"digraph {_dot_id(label)} {{", "  node [shape=box];", *nodes, *edges, "}")) + "\n"


def graph_lines(g):
    """The graph as an indented tree for a terminal: what the root depends on (->), then what depends on it (<-),
    each node expanded once (a repeat marked, not expanded again)."""
    labels = {n.id: n.label + f" ({n.kind}{', ' + n.owner if n.owner else ''})" for n in g.nodes}

    def tree(node, way, level, seen):
        """(lines, seen) of the nodes one step from node in one direction and, the first time each is shown, theirs."""
        def visit(acc, x):
            lines, shown = acc
            other = x.target if way == "down" else x.source
            line = f"{'  ' * level}{'->' if way == 'down' else '<-'} {labels[other]} [{x.via}]"
            if other in shown:
                return (*lines, line + " (above)"), shown
            below, after = tree(other, way, level + 1, shown | {other})
            return (*lines, line, *below), after
        return reduce(visit, (x for x in g.edges if (x.source if way == "down" else x.target) == node), ((), seen))
    down = tree(g.root, "down", 1, frozenset({g.root}))[0] if g.direction != "up" else ()
    up = tree(g.root, "up", 1, frozenset({g.root}))[0] if g.direction != "down" else ()
    return "\n".join((labels[g.root], *down, *up)) + "\n"

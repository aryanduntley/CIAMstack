"""Multi-factor authentication in the authentication policies the record holds: which IdP adapter instances are a
second factor, and the routes through a policy tree that reach success without one. Pure.

An IdP adapter instance is an MFA adapter when its class is one MFA_ADAPTERS names (the classes the adapter knows; a
second factor of another class isn't seen as one); a policy fragment running one is an MFA step as a whole. A tree
holding an MFA step is an MFA tree. A route around MFA is a path from an enabled MFA tree's root to a completion (a
policy contract mapping, done after a success, or an authentication source with nothing after it) passing no MFA
step.

PingFederate's audit log names the adapter an attempt was made with (AUTHN_ATTEMPT's adapterid), never the policy path,
so a route is watched by an adapter on it whose success can lead nowhere but past MFA: an exit. An adapter instance is
an exit when, wherever the record's policies run it (its occurrences), it is an enabled MFA tree's source not under an
MFA step whose successes lead only to completions passing no MFA step. One run anywhere else (a tree without MFA, a
fragment, a route on to MFA) means its successful attempts can't tell a route around MFA from one through it: a route
with no exit on it is unwatched, and the planner names it."""
from collections import namedtuple

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.jsondata import held_json
from .naming import DEFAULT_POLICY, FRAGMENTS, IDP_ADAPTERS, named

# IdP adapter classes that are a second factor (PingID, Duo Security)
MFA_ADAPTERS = ("com.pingidentity.adapters.pingid.PingIDAdapter", "com.pingidentity.adapters.duo.DuoSecurityAdapter")
SUCCESS, FAIL = "Success", "Fail"         # the results of an authentication source a child's context names

# A route around MFA: the tree it is in, its nodes from the root ((label, context of the node), ...), and the exits
# watching it (adapter ids, () when none)
Route = namedtuple("Route", ("tree", "path", "exits"))
# The record's policies' MFA: the MFA adapters' ids, the MFA trees (entries), the exits (adapter ids, each once) and
# the routes around MFA (Routes)
PolicyMfa = namedtuple("PolicyMfa", ("adapters", "trees", "exits", "routes"))


def mfa_adapters(d):
    """The ids of the record's IdP adapter instances whose class is an MFA adapter's (MFA_ADAPTERS)."""
    return tuple(rdn_value(e) for e in children(d, IDP_ADAPTERS, "pingfedPlugin")
                 if one(e, "pingfedPluginType") in MFA_ADAPTERS)


def mfa_fragments(d, adapters):
    """The ids of the record's policy fragments that run an MFA adapter (pingfedUses)."""
    held = {named(IDP_ADAPTERS, a).lower() for a in adapters}
    return tuple(rdn_value(f) for f in children(d, FRAGMENTS, "pingfedAuthPolicy")
                 if {u.lower() for u in values(f, "pingfedUses")} & held)


def _action(node):
    return node.get("action") if isinstance(node.get("action"), dict) else {}


def _below(node):
    return tuple(c for c in node.get("children") or () if isinstance(c, dict))


def source_adapter(node):
    """The IdP adapter id a tree node authenticates with, or None (another kind of node)."""
    action = _action(node)
    source = action.get("authenticationSource") if isinstance(action.get("authenticationSource"), dict) else {}
    ref = source.get("sourceRef") if isinstance(source.get("sourceRef"), dict) else {}
    return ref.get("id") if action.get("type") == "AUTHN_SOURCE" and source.get("type") == "IDP_ADAPTER" else None


def _fragment(node):
    ref = _action(node).get("fragment")
    return ref.get("id") if _action(node).get("type") == "FRAGMENT" and isinstance(ref, dict) else None


def is_mfa_step(node, adapters, fragments):
    """Whether a tree node is an MFA step: it authenticates with an MFA adapter, or runs a fragment running one."""
    return source_adapter(node) in adapters or _fragment(node) in fragments


def _completes(node):
    kind = _action(node).get("type")
    return kind == "APC_MAPPING" or (kind == "DONE" and _action(node).get("context") != FAIL) or \
        (kind == "AUTHN_SOURCE" and not _below(node))


def label(node):
    """A tree node in words: what it runs (an adapter, connection, selector, fragment or contract's id), else its
    action's type."""
    action = _action(node)
    refs = [action.get(k) for k in ("authenticationSelectorRef", "fragment", "authenticationPolicyContractRef")]
    source = action.get("authenticationSource") if isinstance(action.get("authenticationSource"), dict) else {}
    ref = next((r for r in (source.get("sourceRef"), *refs) if isinstance(r, dict) and r.get("id")), None)
    return ref["id"] if ref else str(action.get("type") or "?")


def _free_paths(node, adapters, fragments):
    """The paths from node to a completion passing no MFA step (node included): ((node, ...), ...)."""
    if is_mfa_step(node, adapters, fragments):
        return ()
    below = _below(node)
    here = ((node,),) if _completes(node) else ()
    return (*here, *((node, *p) for c in below for p in _free_paths(c, adapters, fragments)))


def _holds_mfa(node, adapters, fragments):
    return is_mfa_step(node, adapters, fragments) or any(_holds_mfa(c, adapters, fragments) for c in _below(node))


def _successes(node):
    return tuple(c for c in _below(node) if _action(c).get("context") == SUCCESS)


def _free_exit(node, adapters, fragments):
    """Whether an adapter node's successes lead only to completions passing no MFA step (or it has nothing after it)."""
    after = _successes(node)
    return not _below(node) or (bool(after) and not any(_holds_mfa(c, adapters, fragments) for c in after)
                                and any(_free_paths(c, adapters, fragments) for c in after))


def _occurrences(node, adapters, fragments, mfa_tree, passed=False):
    """(adapter id, whether this run of it is an exit) for each IdP adapter node at or below node."""
    here = source_adapter(node)
    own = ((here, mfa_tree and not passed and here not in adapters and _free_exit(node, adapters, fragments)),) \
        if here else ()
    later = passed or is_mfa_step(node, adapters, fragments)
    return (*own, *(o for c in _below(node) for o in _occurrences(c, adapters, fragments, mfa_tree, later)))


def _exits_on(path, exits):
    return tuple(dict.fromkeys(source_adapter(n) for n, nxt in zip(path, (*path[1:], None))
                               if source_adapter(n) in exits and (nxt is None or nxt in _successes(n))))


def policy_mfa(d):
    """The PolicyMfa of the record's authentication policies: its MFA adapters, enabled MFA trees, exits and routes
    around MFA (the module's docstring says which)."""
    adapters = mfa_adapters(d)
    fragments = mfa_fragments(d, adapters)
    trees = tuple(t for t in children(d, DEFAULT_POLICY, "pingfedAuthPolicy")
                  if one(t, "pingfedEnabled", "TRUE") == "TRUE")
    roots = tuple((t, held_json(t, "pingfedPolicyTree")) for t in trees)
    mfa_trees = tuple((t, r) for t, r in roots if _holds_mfa(r, adapters, fragments))
    runs = (*(o for t, r in roots for o in _occurrences(r, adapters, fragments, (t, r) in mfa_trees)),
            *(o for f in children(d, FRAGMENTS, "pingfedAuthPolicy")
              for o in _occurrences(held_json(f, "pingfedPolicyTree"), adapters, fragments, False)))
    exits = tuple(a for a in dict.fromkeys(a for a, _ in runs) if all(free for x, free in runs if x == a))
    routes = tuple(Route(t, tuple((label(n), _action(n).get("context")) for n in p), _exits_on(p, exits))
                   for t, r in mfa_trees for p in _free_paths(r, adapters, fragments))
    return PolicyMfa(adapters, tuple(t for t, _ in mfa_trees), exits, routes)


def route_text(route):
    """A route around MFA in words: its tree and nodes, each with the result that led to it (by-network, Yes:
    htmlform, Success: default-apc)."""
    steps = " -> ".join(f"{ctx}: {name}" if ctx else name for name, ctx in route.path)
    return f"tree {rdn_value(route.tree)}: {steps}"

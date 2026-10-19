"""Multi-factor authentication in the journeys the record holds: which nodes check a second factor, and the routes a
sign-in can take around them to success. Pure.

A journey is an MFA journey when it holds a node taking part in a second factor (MFA_STEPS: making, sending or
registering one, opting out) or checking one (VERIFIERS); a page node counts as the nodes it shows, and an inner tree
evaluator running an MFA-checking journey of the same realm checks one too. A node checking a factor passes it by any
outcome but false (a decision node's outcome when what it checks fails). The node types are AM's node reference's;
the adapter knows only these, so a journey checking a factor with a node of another type (a scripted decision) isn't
seen as one.

The routes around MFA (bypass_edges) are node outcomes, each named by a node event AM's authentication audit topic
writes (AM-NODE-LOGIN-COMPLETED: entries[].info.nodeId and nodeOutcome), so a detection can watch them one event at a
time without joining a sign-in's events: an outcome taken before any pass (no pass leads to its node) onto a node from
which success is reached and no pass can follow, where its node could still have reached one (the route turns away
from MFA there). A sign-in taking one never passes MFA, before or after. When no pass can be reached from the
journey's entry at all, the routes are the outcomes ending in success. A route around MFA that leaves through none of
them (one looping back past a pass, which a single event can't tell) is uncaught: the planner names it."""
from collections import namedtuple

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.jsondata import held_json
from .naming import JOURNEYS, realm_container
from .realms import SUCCESS_NODE, realms

# AM node types that check a second factor (a one-time code, a WebAuthn device, an OATH or push device, a recovery code)
VERIFIERS = ("OneTimePasswordCollectorDecisionNode", "WebAuthnAuthenticationNode", "OathTokenVerifierNode",
             "PushResultVerifierNode", "RecoveryCodeCollectorDecisionNode")
# AM node types taking part in a second factor without checking it: making or sending a code, registering a device,
# offering or skipping MFA, showing recovery codes
MFA_STEPS = ("OneTimePasswordGeneratorNode", "OneTimePasswordSmtpSenderNode", "OneTimePasswordSmsSenderNode",
             "WebAuthnRegistrationNode", "OathRegistrationNode", "PushRegistrationNode", "PushAuthenticationSenderNode",
             "MfaRegistrationOptionsNode", "OptOutMultiFactorAuthenticationNode", "RecoveryCodeDisplayNode",
             "GetAuthenticatorAppNode")
INNER_TREE = "InnerTreeEvaluatorNode"       # runs another journey of the realm (its config's tree)
FAILED = "false"                            # a decision node's outcome when what it checks fails

# One outcome of a journey's node: the node's id, the outcome's id, the node it leads to
Edge = namedtuple("Edge", ("node", "outcome", "to"))
# An MFA journey of a realm AM serves: the realm's identity service, the journey, its nodes ({id: entry}), the ids
# of those checking a factor and of those taking part in one, its routes around MFA (Edges), and whether a route
# around MFA leaves through none of them (uncaught)
MfaJourney = namedtuple("MfaJourney", ("service", "journey", "nodes", "verifiers", "steps", "bypass", "uncaught"))


def node_types(n):
    """The node types a journey's node is: its own, and for a page node those of the nodes it shows."""
    shown = held_json(n, "pingamNodeConfig").get("nodes")
    return (one(n, "pingamNodeType"), *(c.get("nodeType") for c in shown if isinstance(c, dict))) \
        if isinstance(shown, list) else (one(n, "pingamNodeType"),)


def journey_nodes(d, j):
    """{node id: entry} of a journey's nodes."""
    return {rdn_value(n): n for n in children(d, j.dn, "pingamNode")}


def edges(nodes):
    """The Edges of a journey's nodes ({id: entry}): every outcome and the node it leads to, in node order."""
    return tuple(Edge(nid, o, to) for nid, n in nodes.items() for o, _, to in
                 (x.partition("=") for x in values(n, "pingamOutcome")))


def _checks_mfa(d, j, seen):
    nodes = journey_nodes(d, j)
    return any(_verifies(d, j, n, seen) for n in nodes.values())


def _verifies(d, j, n, seen):
    if set(node_types(n)) & set(VERIFIERS):
        return True
    tree = held_json(n, "pingamNodeConfig").get("tree") if one(n, "pingamNodeType") == INNER_TREE else None
    inner = next((x for x in children(d, j.dn.split(",", 1)[1], "pingamJourney") if rdn_value(x) == tree), None)
    return inner is not None and inner.dn not in seen and _checks_mfa(d, inner, seen | {j.dn})


def verifier_ids(d, j, nodes):
    """The ids of a journey's nodes checking a second factor (VERIFIERS, shown on a page, or run as an inner journey of
    the same realm that checks one)."""
    return tuple(nid for nid, n in nodes.items() if _verifies(d, j, n, frozenset((j.dn,))))


def step_ids(nodes):
    """The ids of a journey's nodes taking part in a second factor without checking it (MFA_STEPS)."""
    return tuple(nid for nid, n in nodes.items() if set(node_types(n)) & set(MFA_STEPS))


def _reach(starts, pairs):
    """Every node reached from starts (themselves included) along pairs ((from, to), ...)."""
    found, todo = set(starts), list(starts)
    while todo:
        here = todo.pop()
        new = {b for a, b in pairs if a == here} - found
        found |= new
        todo.extend(new)
    return frozenset(found)


def passes(e, verifiers):
    """Whether taking an outcome passes MFA: a node checking a factor left by any outcome but false."""
    return e.node in verifiers and e.outcome != FAILED


def bypass_edges(entry, found, verifiers):
    """(the routes around MFA, whether one is uncaught) of a journey: its entry node's id, its Edges, the ids of its
    nodes checking a factor (the module's docstring says which outcomes are routes)."""
    pairs = tuple((e.node, e.to) for e in found)
    passing = tuple(e for e in found if passes(e, verifiers))
    after = _reach({e.to for e in passing}, pairs)                     # nodes a pass may have come before
    can_pass = _reach({e.node for e in passing}, tuple((b, a) for a, b in pairs))     # nodes a pass can follow
    to_success = _reach({SUCCESS_NODE}, tuple((b, a) for a, b in pairs))
    reached = _reach({entry}, pairs)
    around = tuple(e for e in found if e not in passing and e.node in reached and e.node not in after
                   and e.to not in can_pass and e.to in to_success)
    routes = tuple(e for e in around if e.node in can_pass) if entry in can_pass else \
        tuple(e for e in around if e.to == SUCCESS_NODE)
    rest = tuple((e.node, e.to) for e in found if e not in passing and e not in routes)
    return routes, SUCCESS_NODE in _reach({entry}, rest)


def _mfa_journey(d, service, j):
    nodes = journey_nodes(d, j)
    verifiers, steps = verifier_ids(d, j, nodes), step_ids(nodes)
    if not verifiers and not steps:
        return None
    routes, uncaught = bypass_edges(one(j, "pingamEntryNode"), edges(nodes), verifiers)
    return MfaJourney(service, j, nodes, verifiers, tuple(s for s in steps if s not in verifiers), routes, uncaught)


def mfa_journeys(d):
    """The MfaJourneys of the realms AM serves: their enabled journeys holding a node that takes part in or checks a
    second factor, in realm and record order."""
    return tuple(x for s in realms(d) for j in children(d, realm_container(JOURNEYS, rdn_value(s)), "pingamJourney")
                 if one(j, "pingamEnabled", "TRUE") == "TRUE" for x in (_mfa_journey(d, s, j),) if x is not None)


def node_label(x, nid):
    """A node of an MFA journey by its name in the journey, else its id."""
    return one(x.nodes[nid], "pingamDisplayName") or nid if nid in x.nodes else nid

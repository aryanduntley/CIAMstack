"""PingAM's MFA detections, derived from the journeys the record holds: which nodes take part in or check a second
factor, the node outcomes a sign-in takes around the check (watched one node event at a time), a route only a loop
reaches named for the planner instead, a configuration-change detection per realm holding MFA journeys, every one
unverified and able to be offered as an alert rule; on the unit export and on the showcase's synthetic estate."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import core_fragments
from opsdir.core.contract import declared_detections
from opsdir.core.directory import get
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir.domains.observability.detections import detection_problems, product_field, product_values
from opsdir_adapter_pingam.adapter import ADAPTER
from opsdir_adapter_pingam.checks import check_mfa_routes
from opsdir_adapter_pingam.detections import DETECTIONS, record_detections
from opsdir_adapter_pingam.mfa import MFA_STEPS, VERIFIERS, Edge, bypass_edges, mfa_journeys
from opsdir_adapter_pingam.naming import journey_dn
from opsdir_adapter_pingam.realms import FAILURE_NODE, SUCCESS_NODE
from opsdir_adapter_pingam.schema import FRAGMENT
from support import build_directory

HERE = Path(__file__).resolve().parent
EXPORT = HERE / "amster-export"
SHOWCASE = HERE.parents[2] / "examples" / "showcase"
REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
TOP = """dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=identity-services,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: identity-services
"""
CUSTOMERS = """dn: cn=customers,ou=identity-services,dc=ciam-ops
objectClass: top
objectClass: ciamIdentityService
objectClass: pingamRealm
cn: customers
ciamBaseUrl: https://login.example.test
ciamTargetRole: am
pingamRealmPath: /customers
"""
LOGIN = journey_dn("customers", "Login")
SENDER = "a1b2c3d4-0000-4000-8000-000000000005"        # the unit export's Login emails a code it never checks
S, F = SUCCESS_NODE, FAILURE_NODE


def files_of(root):
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def imported(base, files):
    d = build_directory(REGISTRY, parse(base))
    changes, _ = preview_import(d, "pingam", files, (ADAPTER,))
    return build_directory(REGISTRY, parse(base), changes)


def _ids(dets):
    return [det.id for det in dets]


@pytest.fixture(scope="module")
def unit():
    return imported(TOP + "\n" + CUSTOMERS, files_of(EXPORT))


def _showcase_realms():
    """The showcase's AM realms (identity services that are pingamRealm), as its data records them."""
    text = (SHOWCASE / "data" / "74-identity-services.ldif").read_text()
    return "\n".join(block for block in text.split("\n\n") if "objectClass: pingamRealm" in block)


@pytest.fixture(scope="module")
def showcase():
    return imported(TOP + "\n" + _showcase_realms() + "\n", files_of(SHOWCASE / "exports" / "amster"))


def test_routes_around_mfa_are_the_outcomes_turning_away_from_the_check():
    # password, then a choice: skip to success, or a code checked (true passes it, false fails)
    opt_out = (Edge("pw", "true", "choice"), Edge("pw", "false", F), Edge("choice", "skip", S),
               Edge("choice", "mfa", "otp"), Edge("otp", "true", S), Edge("otp", "false", F))
    assert bypass_edges("pw", opt_out, ("otp",)) == ((Edge("choice", "skip", S),), False)
    # the check's failure leads to success anyway: that outcome is the route
    lenient = (Edge("pw", "true", "otp"), Edge("otp", "true", S), Edge("otp", "false", S))
    assert bypass_edges("pw", lenient, ("otp",)) == ((Edge("otp", "false", S),), False)
    # passing first, then a shared node to success: no route around it
    shared = (Edge("pw", "true", "otp"), Edge("otp", "true", "props"), Edge("props", "outcome", S),
              Edge("otp", "false", F))
    assert bypass_edges("pw", shared, ("otp",)) == ((), False)
    # nothing checks a factor: the outcomes ending in success are the routes
    unchecked = (Edge("pw", "true", "send"), Edge("send", "outcome", S), Edge("pw", "false", F))
    assert bypass_edges("pw", unchecked, ()) == ((Edge("send", "outcome", S),), False)


def test_a_route_around_mfa_only_a_loop_reaches_is_uncaught():
    # pw -> a or otp; passing leads back to pw, so pw -> a is taken after a pass too: no single outcome tells a
    # sign-in that skipped the check, yet pw -> a -> success does
    looped = (Edge("pw", "direct", "a"), Edge("pw", "mfa", "otp"), Edge("otp", "true", "back"),
              Edge("back", "outcome", "pw"), Edge("a", "outcome", S), Edge("otp", "false", F))
    routes, uncaught = bypass_edges("pw", looped, ("otp",))
    assert routes == () and uncaught


def test_the_unit_exports_journey_emails_a_code_it_never_checks(unit):
    (x,) = mfa_journeys(unit)
    assert (x.journey.dn, x.verifiers, x.steps) == (LOGIN, (), (SENDER,))
    assert x.bypass == (Edge(SENDER, "outcome", SUCCESS_NODE),) and not x.uncaught
    bypass, config = record_detections(unit)
    assert (bypass.id, config.id) == (f"mfa-bypass.customers.login.{SENDER}", "mfa-config.customers")
    assert bypass.selector == (("action", ("login-step",)), ("step", (SENDER,)), ("step-outcome", ("outcome",)))
    assert "none: no node of it checks a second factor" in bypass.description
    assert config.selector == (("action", ("config-change",)), ("realm", ("/customers",)))
    assert "Email a code" in config.description and any("device" in p for p in config.prerequisites)
    assert check_mfa_routes(SimpleNamespace(d=unit)).actions == ()


def test_every_derived_detection_is_unverified_and_can_be_offered(unit, showcase):
    for d in (unit, showcase):
        derived = record_detections(d)
        assert derived and declared_detections(ADAPTER, d) == (*DETECTIONS, *derived)
        assert all(det.validation == "unverified" and detection_problems(ADAPTER.name, det) == ()
                   for det in derived)
        assert len(set(_ids(declared_detections(ADAPTER, d)))) == len(declared_detections(ADAPTER, d))
        assert all(u.startswith("https://docs.pingidentity.com/") for det in derived for u in det.evidence)


def test_a_route_is_watched_by_its_node_event_in_the_products_fields(unit):
    bypass, _ = record_detections(unit)
    mp = next(m for m in bypass.mappings if m.product == "PingAM")
    assert product_values(mp, "action", "login-step") == ("AM-NODE-LOGIN-COMPLETED",)
    assert (product_field(mp, "step"), product_field(mp, "step-outcome")) == (
        "entries[].info.nodeId", "entries[].info.nodeOutcome")
    assert bypass.threshold is None and bypass.severity == "sev2" and "T1556.006" in bypass.techniques


def _added(d, journey, node, node_type, outcomes, entry=None):
    """d with a node of a journey added (and its entry node moved to it, entry given)."""
    rec = (f"dn: cn={node},{journey}\nchangetype: add\nobjectClass: top\nobjectClass: ciamObject\n"
           f"objectClass: pingamNode\ncn: {node}\npingamNodeType: {node_type}\npingamDisplayName: {node}\n"
           + "".join(f"pingamOutcome: {o}\n" for o in outcomes))
    move = f"\ndn: {journey}\nchangetype: modify\nreplace: pingamEntryNode\npingamEntryNode: {entry}\n-\n" \
        if entry else ""
    return parse(rec + move)


def test_checking_the_code_with_an_opt_out_leaves_one_route_and_a_loop_is_named(unit):
    # the sender now leads to a code check; an opt-out node in front of it can skip to success
    sender_to_check = parse(f"dn: cn={SENDER},{LOGIN}\nchangetype: modify\nreplace: pingamOutcome\n"
                            "pingamOutcome: outcome=check\n-\n")
    changes = (*sender_to_check,
               *_added(unit, LOGIN, "check", "OneTimePasswordCollectorDecisionNode",
                       (f"true={SUCCESS_NODE}", f"false={FAILURE_NODE}")),
               *_added(unit, LOGIN, "opt", "OptOutMultiFactorAuthenticationNode",
                       (f"skip={SUCCESS_NODE}", f"mfa={SENDER}"), entry="opt"))
    base = TOP + "\n" + CUSTOMERS
    d = build_directory(REGISTRY, parse(base), (*preview_import(build_directory(REGISTRY, parse(base)), "pingam",
                                                                  files_of(EXPORT), (ADAPTER,))[0], *changes))
    (x,) = mfa_journeys(d)
    assert x.verifiers == ("check",) and x.bypass == (Edge("opt", "skip", SUCCESS_NODE),)
    assert _ids(record_detections(d)) == ["mfa-bypass.customers.login.opt", "mfa-config.customers"]
    assert check_mfa_routes(SimpleNamespace(d=d)).actions == ()
    # passing the check now leads back to the opt-out node: its skip is reached after a pass too, so no single
    # outcome tells a sign-in that skipped it; the planner names the journey
    looped = build_directory(REGISTRY, parse(base), (
        *preview_import(build_directory(REGISTRY, parse(base)), "pingam", files_of(EXPORT), (ADAPTER,))[0],
        *changes, *parse(f"dn: cn=check,{LOGIN}\nchangetype: modify\nreplace: pingamOutcome\npingamOutcome: true=opt"
                         f"\npingamOutcome: false={FAILURE_NODE}\n-\n")))
    (y,) = mfa_journeys(looped)
    assert y.bypass == () and y.uncaught
    (action,) = check_mfa_routes(SimpleNamespace(d=looped)).actions
    assert action[0] == "Journey" and action[1].startswith("Journey `Login` of realm /customers can reach success")
    assert _ids(record_detections(looped)) == ["mfa-config.customers"]


def _exported_journeys(root):
    """{(realm, journey): (node types by id, outcomes ((node id, outcome, target), ...))} of an Amster export's trees,
    read from its files (what the showcase's tests expect, independent of the adapter)."""
    trees = {}
    for path in sorted(root.rglob("AuthTree/*.json")):
        doc = json.loads(path.read_text())
        nodes = doc["data"]["nodes"]
        trees[(doc["metadata"]["realm"], doc["data"]["_id"])] = (
            {nid: n["nodeType"] for nid, n in nodes.items()},
            tuple((nid, o, to) for nid, n in nodes.items() for o, to in n["connections"].items()))
    return trees


def test_the_showcase_journeys_mfa_is_watched_as_its_export_shows(showcase):
    trees = _exported_journeys(SHOWCASE / "exports" / "amster")
    mfa = {k: v for k, v in trees.items() if set(v[0].values()) & {*VERIFIERS, *MFA_STEPS}}
    assert mfa and {(x.service.attrs["pingamRealmPath"][0], x.journey.dn.split(",")[0][3:])
                    for x in mfa_journeys(showcase)} == set(mfa)
    # a journey whose only outcomes into success pass a checking node has no route around MFA
    checked_only = {k for k, (types, outs) in mfa.items()
                    if all(types[n] in VERIFIERS and o != "false" for n, o, to in outs if to == SUCCESS_NODE)}
    derived = record_detections(showcase)
    bypassed = {d.id.split(".")[2] for d in derived if d.id.startswith("mfa-bypass.")}
    assert not bypassed & {name.lower() for _, name in checked_only}
    realms = {realm for realm, _ in mfa}
    assert sorted(d.selector[1][1][0] for d in derived if d.id.startswith("mfa-config.")) == sorted(realms)
    assert check_mfa_routes(SimpleNamespace(d=showcase)).actions == ()
    assert get(showcase, journey_dn("partners", "PartnerLogin")) is not None

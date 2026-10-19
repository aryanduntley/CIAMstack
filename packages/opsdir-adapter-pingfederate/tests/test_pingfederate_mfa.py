"""PingFederate's MFA detections, derived from the authentication policies the record holds: which adapter instances
are a second factor, the routes through a policy tree reaching success without one, an adapter instance whose
successes lead only past MFA watched by its successful attempts (unverified, able to be offered as an alert rule), and
what no detection watches (changes to the MFA adapters and trees, a route through an adapter that also leads on to
MFA) named for the planner; on unit exports and on the showcase's synthetic estate."""
import datetime as dt
import json
from pathlib import Path

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import core_fragments
from opsdir.core.contract import PlanContext, declared_detections
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir.domains.observability.detections import detection_problems, product_field, product_values
from opsdir_adapter_pingfederate.adapter import ADAPTER
from opsdir_adapter_pingfederate.checks import check_mfa_watch
from opsdir_adapter_pingfederate.detections import DETECTIONS, record_detections
from opsdir_adapter_pingfederate.mfa import MFA_ADAPTERS, policy_mfa
from opsdir_adapter_pingfederate.schema import FRAGMENT
import mini_estate
from support import build_directory

SHOWCASE = Path(__file__).resolve().parents[3] / "examples" / "showcase"
REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
FORM = "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter"
DUO = "com.pingidentity.adapters.duo.DuoSecurityAdapter"
CIDR = "com.pingidentity.pf.selectors.cidr.CIDRAdapterSelector"


def _plugin(pid, cls):
    return {"id": pid, "name": pid.upper(), "pluginDescriptorRef": {"id": cls},
            "configuration": {"tables": [], "fields": []}}


def _node(action, *below):
    return {"action": action, **({"children": list(below)} if below else {})}


def _source(adapter, context=None):
    return {"type": "AUTHN_SOURCE", **({"context": context} if context else {}),
            "authenticationSource": {"type": "IDP_ADAPTER", "sourceRef": {"id": adapter}}}


def _mapped(context="Success"):
    return _node({"type": "APC_MAPPING", "context": context, "authenticationPolicyContractRef": {"id": "default-apc"}})


SELECTOR = {"type": "AUTHN_SELECTOR", "authenticationSelectorRef": {"id": "by-network"}}
# on the internal network ("Yes") the form, then the MFA fragment; otherwise (the branch each test chooses)
ON_NETWORK = _node(_source("htmlform", "Yes"),
                   _node({"type": "FRAGMENT", "context": "Success", "fragment": {"id": "mfa"}}, _mapped()),
                   _node({"type": "DONE", "context": "Fail"}))
MFA = {"id": "mfa", "name": "MFA", "rootNode": _node(_source("duo"), _node({"type": "DONE", "context": "Success"})),
       "inputs": {"id": "default-apc"}, "outputs": {"id": "default-apc"}}


def export(*off_network, extra_trees=()):
    tree = {"name": "Workforce", "enabled": True, "rootNode": _node(SELECTOR, ON_NETWORK, *off_network)}
    ops = (("/idp/adapters", [_plugin("htmlform", FORM), _plugin("htmlform-internal", FORM), _plugin("duo", DUO)]),
           ("/authenticationSelectors", [_plugin("by-network", CIDR)]),
           ("/authenticationPolicyContracts", [{"id": "default-apc", "name": "Default",
                                                "coreAttributes": [{"name": "subject"}]}]),
           ("/authenticationPolicies/default", [{"failIfNoSelection": False,
                                                 "authnSelectionTrees": [tree, *extra_trees]}]),
           ("/authenticationPolicies/fragments", [MFA]))
    return {"data.json": json.dumps({"operations": [{"operationType": "SAVE", "resourceType": r, "items": list(items)}
                                                     for r, items in ops]})}


def imported(files):
    records = tuple(parse(mini_estate.LDIF))
    changes, _ = preview_import(build_directory(REGISTRY, records), "pingfederate/bulk", files, (ADAPTER,))
    return build_directory(REGISTRY, records, changes)


def _plan(d):
    return check_mfa_watch(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None,
                                       dt.date(2026, 10, 19), {}, {}, ()))


def test_a_tree_whose_only_route_passes_mfa_needs_no_detection_but_its_changes_are_unwatched():
    d = imported(export())
    found = policy_mfa(d)
    assert (found.adapters, [t.dn.split(",")[0] for t in found.trees], found.exits, found.routes) == (
        ("duo",), ["cn=Workforce"], (), ())
    assert record_detections(d) == () and declared_detections(ADAPTER, d) == DETECTIONS
    (action,) = _plan(d).actions
    assert action[0] == "PingFederate" and "adapters duo; trees Workforce" in action[1]
    assert "admin-api.log" in action[1] and "routes around MFA" not in action[1]


def test_an_adapter_instance_only_a_route_around_mfa_runs_is_watched_by_its_successful_attempts():
    d = imported(export(_node(_source("htmlform-internal", "No"), _mapped())))
    found = policy_mfa(d)
    assert found.exits == ("htmlform-internal",) and [r.exits for r in found.routes] == [("htmlform-internal",)]
    (det,) = record_detections(d)
    assert det.id == "mfa-bypass.htmlform-internal" and det.validation == "unverified"
    assert detection_problems(ADAPTER.name, det) == () and declared_detections(ADAPTER, d) == (*DETECTIONS, det)
    assert det.selector == (("action", ("login",)), ("outcome", ("success",)), ("step", ("htmlform-internal",)))
    (mp,) = det.mappings
    assert product_field(mp, "step") == "adapterid" and product_values(mp, "action", "login") == ("AUTHN_ATTEMPT",)
    assert product_values(mp, "outcome", "success") == ("success",) and "tree Workforce" in det.description
    assert "routes around MFA" not in _plan(d).actions[0][1]


def test_a_route_through_an_adapter_that_also_leads_on_to_mfa_is_named_unwatched():
    d = imported(export(_node(_source("htmlform", "No"), _mapped())))
    found = policy_mfa(d)
    assert found.exits == () and [r.exits for r in found.routes] == [()]
    assert record_detections(d) == ()
    (action,) = _plan(d).actions
    assert "tree Workforce: by-network -> No: htmlform -> Success: default-apc" in action[1]


def test_an_adapter_a_tree_without_mfa_runs_too_is_no_exit():
    other = {"name": "Kiosk", "enabled": True, "rootNode": _node(_source("htmlform-internal"), _mapped())}
    d = imported(export(_node(_source("htmlform-internal", "No"), _mapped()), extra_trees=(other,)))
    assert policy_mfa(d).exits == () and record_detections(d) == ()
    assert [t.dn.split(",")[0] for t in policy_mfa(d).trees] == ["cn=Workforce"]


def test_the_showcase_policies_hold_no_mfa_adapter_so_nothing_is_derived():
    files = {"data.json": (SHOWCASE / "exports" / "pingfederate" / "data.json").read_text()}
    ops = json.loads(files["data.json"])["operations"]
    classes = {i["pluginDescriptorRef"]["id"] for o in ops if o["resourceType"] == "/idp/adapters"
               for i in o["items"]}
    d = imported(files)
    expected_mfa = bool(classes & set(MFA_ADAPTERS))
    assert bool(policy_mfa(d).adapters) == expected_mfa
    if not expected_mfa:
        assert record_detections(d) == () and _plan(d).actions == ()
    assert all(detection_problems(ADAPTER.name, det) == () and det.validation == "unverified"
               for det in record_detections(d))

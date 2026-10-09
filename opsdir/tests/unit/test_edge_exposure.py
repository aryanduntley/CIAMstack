"""A service name's exposure (core edge.exposure): its address decides, else its recorded ciamExposure; a name with
neither is a target blocker and a source action, and an address that contradicts the attribute is an action."""
import datetime as dt

from opsdir.connectors.plan import plan
from opsdir.core.directory import rdn_value
from opsdir.core.environment import env_model, of_class
from opsdir.core.interchange.ldif import parse
from opsdir.domains.edge.exposure import exposure_unknown, is_internal, service_exposure
import mini_estate
from mini_estate import FAKE

AS_OF = dt.date(2026, 1, 1)
ALPHA, BETA = "alpha/prod", "beta/prod"


def _sso(env, change=""):
    d = mini_estate.directory(tuple(parse(change)) if change else ())
    return d, next(s for s in of_class(env_model(d, env), "ciamServiceName") if rdn_value(s) == "svc-sso")


def _modify(env, body):
    cloud, stage = env.split("/")
    return (f"dn: cn=svc-sso,ou=bindings,env={stage},cloud={cloud},ou=environments,dc=ciam-ops\n"
            f"changetype: modify\n{body}")


def _edge_findings(p):
    return [b[1] for b in p.blockers if "ciamExposure" in b[1]], [a[1] for a in p.actions if "ciamExposure" in a[1]]


def test_the_address_decides_then_the_recorded_exposure():
    _, svc = _sso(ALPHA)
    assert service_exposure(svc) == "internet" and not is_internal(svc)
    _, svc = _sso(ALPHA, _modify(ALPHA, "add: ciamFrontendIp\nciamFrontendIp: 10.0.0.9\n-\n"))
    assert service_exposure(svc) == "internal" and is_internal(svc)


def test_a_name_with_neither_is_unknown_and_named_in_the_render_comment():
    _, svc = _sso(ALPHA, _modify(ALPHA, "delete: ciamExposure\n-\n"))
    assert service_exposure(svc) is None
    assert exposure_unknown(svc).startswith("# UNBOUND:sso-service-exposure: service name `svc-sso`")


def test_unknown_exposure_blocks_the_target_and_is_an_action_in_the_source():
    d, _ = _sso(BETA, _modify(BETA, "delete: ciamExposure\n-\n"))
    blockers, actions = _edge_findings(plan(d, ALPHA, BETA, AS_OF, (FAKE,)))
    assert len(blockers) == 1 and "in beta/prod records no frontend address" in blockers[0] and not actions
    blockers, actions = _edge_findings(plan(d, BETA, ALPHA, AS_OF, (FAKE,)))
    assert not blockers and len(actions) == 1 and "in beta/prod" in actions[0]


def test_an_address_contradicting_the_exposure_is_an_action():
    d, _ = _sso(BETA, _modify(BETA, "add: ciamFrontendIp\nciamFrontendIp: 10.0.0.9\n-\n"))
    blockers, actions = _edge_findings(plan(d, ALPHA, BETA, AS_OF, (FAKE,)))
    assert not blockers and actions == ["`sso.example.test` in beta/prod records exposure `internet` but its frontend "
                                        "address 10.0.0.9 is internal: the address decides. Correct or remove "
                                        "ciamExposure."]

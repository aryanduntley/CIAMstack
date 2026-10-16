"""What a source product holds that the standard model has no equivalent for (source objects), the integrations an
identity service the target won't run serves, and the planner hook that runs a source-only adapter's checks: each
held by a role the source runs and the target doesn't becomes an action for its owner, or a blocker when the move
waits for it; a target still running the role keeps it in place."""
import datetime as dt

from opsdir.connectors import plan as planner
from opsdir.core.contract import Adapter, PlanContext
from opsdir.core.environment import env_model
from opsdir.core.findings import findings
from opsdir.core.interchange.ldif import parse
from opsdir.domains.federation.domain import DOMAIN as FEDERATION
from opsdir.domains.federation.served import check_served_integrations
from opsdir.domains.governance.domain import DOMAIN as GOVERNANCE
from opsdir.domains.governance.schema import HANDLINGS
from opsdir.domains.governance.source_objects import (AREA, SOURCE_OBJECT_HEADERS, check_source_objects,
                                                      source_object_rows)
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
TEAM = "cn=ops,ou=owners,dc=ciam-ops"
BRANCH = "ou=legacy,ou=source-objects,dc=ciam-ops"
AS_OF, CUTOVER = dt.date(2026, 10, 1), dt.date(2026, 11, 1)


def _server(env, cn, role):
    return (f"dn: cn={cn},{env}\nobjectClass: top\nobjectClass: ciamServer\ncn: {cn}\nciamServerRole: {role}\n"
            f"ciamHostname: {cn}.example.test\nciamSubnet: cn=net,ou=bindings,{env}\n")


def _object(cn, cls, role, handling, *facts, **attrs):
    return (f"dn: cn={cn},{BRANCH}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamSourceObject\n"
            f"cn: {cn}\nciamSourceClass: {cls}\nciamTargetRole: {role}\nciamHandling: {handling}\n"
            + "".join(f"ciamSourceFact: {f}\n" for f in facts) + "".join(f"{k}: {v}\n" for k, v in attrs.items()))


def _integration(cn, served_by):
    return (f"dn: cn={cn},ou=integrations,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\n"
            f"objectClass: ciamIntegration\ncn: {cn}\nciamProtocolType: saml2-sp\nciamEntityId: urn:example:{cn}\n"
            f"ciamAcsUrl: https://{cn}.example.test/acs\nciamServedBy: {served_by}\nciamOwner: {TEAM}\n")


LEGACY = "cn=legacy,ou=identity-services,dc=ciam-ops"
RECORD = (
    "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    f"dn: {TEAM}\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n",
    _server(ALPHA, "ps-1", "legacy-ps"), _server(ALPHA, "web-1", "web"), _server(BETA, "web-b1", "web"),
    "dn: ou=source-objects,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: source-objects\n",
    f"dn: {BRANCH}\nobjectClass: top\nobjectClass: organizationalUnit\nou: legacy\n",
    _object("hco-main", "Legacy::HostConfig", "legacy-ps", "retire", "PolicyServer 10.0.1.5", "FailOver true",
            ciamHow="the target's gateways don't use it", ciamOwner=TEAM),
    _object("auth-custom", "Legacy::AuthScheme", "legacy-ps", "rebuild", "Library customauth",
            ciamHow="rebuild the sign-on as a journey", ciamBlocking="TRUE"),
    _object("web-cache", "Legacy::CacheConfig", "web", "review"),
    f"dn: {LEGACY}\nobjectClass: top\nobjectClass: ciamIdentityService\ncn: legacy\n"
    "ciamBaseUrl: https://legacy.example.test\nciamEntityId: urn:example:legacy\nciamTargetRole: legacy-ps\n",
    "dn: ou=integrations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: integrations\n",
    _integration("parts", LEGACY),
    _integration("portal", "cn=sso,ou=identity-services,dc=ciam-ops"),
)


def _directory():
    return build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *RECORD)))))


def _ctx(src="alpha/prod", dst="beta/prod"):
    d = _directory()
    return PlanContext(d, env_model(d, src), env_model(d, dst), CUTOVER, AS_OF, {}, {}, ())


def test_the_domains_check_and_report_them():
    assert check_source_objects in GOVERNANCE.checks and "source-objects" in GOVERNANCE.reports
    assert check_served_integrations in FEDERATION.checks
    assert HANDLINGS == ("rebuild", "re-provision", "re-register", "replace", "retire", "review")


def test_a_source_object_the_target_leaves_behind_is_an_action_or_a_blocker():
    found = check_source_objects(_ctx())
    assert found.blockers == ((AREA, "Source object `auth-custom` (Legacy::AuthScheme: Library customauth) is held "
                                     "by `legacy-ps`, which beta/prod doesn't run: rebuild: rebuild the sign-on as a "
                                     "journey. The move waits for it (ciamBlocking).", "**NO OWNER**"),)
    assert found.actions == ((AREA, "Source object `hco-main` (Legacy::HostConfig: PolicyServer 10.0.1.5; FailOver "
                                    "true) is held by `legacy-ps`, which beta/prod doesn't run: retire: the target's "
                                    "gateways don't use it.", "ops", CUTOVER),)
    assert found.ok == ("Source object `web-cache` (Legacy::CacheConfig) stays with `web`, which beta/prod still "
                        "runs.",)


def test_a_source_that_doesnt_run_the_role_has_nothing_to_carry():
    assert check_source_objects(_ctx("beta/prod", "alpha/prod")).blockers == ()
    assert check_source_objects(_ctx("beta/prod", "alpha/prod")).actions == ()


def test_the_report_lists_every_source_object():
    rows = source_object_rows(_directory())
    assert len(SOURCE_OBJECT_HEADERS) == len(rows[0])
    assert [r[0] for r in rows] == ["auth-custom", "hco-main", "web-cache"]
    assert rows[1] == ("hco-main", "Legacy::HostConfig", "legacy-ps", "retire", "no", "ops",
                       "the target's gateways don't use it", "PolicyServer 10.0.1.5; FailOver true")


def test_an_integration_served_by_a_service_the_target_doesnt_run_blocks_and_the_rest_is_silent():
    found = check_served_integrations(_ctx())
    assert found.blockers == (("Federation", "Integration `parts` (saml2-sp) is served by identity service `legacy`, "
                               "whose `legacy-ps` servers beta/prod doesn't run: its users and partners lose sign-on. "
                               "Re-home it to an identity service the target runs (ciamServedBy; there: `sso`): it "
                               "keeps its entity ID or client ID, and the partner takes the new service's metadata or "
                               "issuer.", "ops"),)
    assert found.actions == () and found.ok == ()
    assert check_served_integrations(_ctx("beta/prod", "alpha/prod")) == findings()


def test_the_planner_runs_the_source_checks_of_the_adapters_applying_to_the_source():
    seen = []

    def legacy_check(ctx):
        seen.append((ctx.src.label, ctx.dst.label))
        return findings(actions=[("Legacy", "retire the legacy product", "ops", None)])
    legacy = Adapter(name="legacy", kind="product", applies=None, required_roles=(),
                     render_neutral=None, render_env=None, checks=(), ref_schemes=(), secret_schemes={},
                     renders="", neutral_label="", vocabulary={}, schema=None, formats=(), products=(),
                     secret_patterns=(), importers=(), profile_terms=None, access=None, source_checks=(legacy_check,))
    assert Adapter._field_defaults["source_checks"] == ()
    d = mini_estate.directory(tuple(parse(
        f"dn: cn=legacy,ou=stack,{ALPHA}\nchangetype: add\nobjectClass: top\nobjectClass: ciamStackComponent\n"
        "cn: legacy\nciamStackRole: access\nciamAdapter: legacy\nciamAdapterVersion: >=0.1,<1\n")))
    p = planner.plan(d, "alpha/prod", "beta/prod", AS_OF, installed=(mini_estate.FAKE, legacy))
    assert seen == [("alpha/prod", "beta/prod")]
    assert [a for a in p.actions if "retire the legacy product" in str(a)]
    seen.clear()
    planner.plan(d, "beta/prod", "alpha/prod", AS_OF, installed=(mini_estate.FAKE, legacy))
    assert seen == []

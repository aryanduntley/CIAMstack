"""Overlays and overrides in rendering and planning (in memory, on the mini estate): alpha/stage is an overlay of
alpha/prod and overrides a shared value. Renderers see the environment's value, the MANIFEST lists the override, the
planner explains the difference instead of blocking on it, and roles the target must bind but doesn't are blockers."""
import datetime as dt
import json

from opsdir.connectors.plan import checks, plan
from opsdir.core.contract import PlanContext
from opsdir.connectors.render import render_env
from opsdir.connectors.stack import stack_rows
from opsdir.core.directory import get, one
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.infrastructure.reports import override_rows
import mini_estate
from mini_estate import FAKE, VERSIONS

PROD = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
STAGE = "env=stage,cloud=alpha,ou=environments,dc=ciam-ops"
SSO = "cn=sso,ou=identity-services,dc=ciam-ops"
AS_OF = dt.date(2026, 9, 1)
# the fake adapter's environment-neutral file shows a shared value, so an override changes it
READS_INTENT = FAKE._replace(render_neutral=lambda d: {"fake/neutral.txt": f"{one(get(d, SSO), 'description')}\n"})


def add(dn, *classes, **attrs):
    lines = "".join(f"{k}: {v}\n" for k, v in attrs.items())
    return f"dn: {dn}\nchangetype: add\nobjectClass: top\n" + "".join(f"objectClass: {c}\n" for c in classes) + lines


def estate(*records):
    """alpha/stage, an overlay of alpha/prod, overriding the identity service's description."""
    return mini_estate.directory(tuple(parse("\n".join((
        f"dn: {SSO}\nchangetype: modify\nadd: description\ndescription: shared\n-\n",
        add(STAGE, "ciamEnvironment", env="stage", ciamOverlayOf=PROD),
        add(f"ou=overrides,{STAGE}", "organizationalUnit", ou="overrides"),
        add(f"ou=stack,{STAGE}", "organizationalUnit", ou="stack"),
        add(f"cn=tier,ou=overrides,{STAGE}", "ciamOverride", cn="tier", ciamOverrides=SSO,
            ciamOverrideAttribute="description", ciamOverrideValue="stage", description="a smaller stage"),
        *records)))))


def test_renderers_see_the_environments_value_and_the_manifest_lists_the_override():
    d = estate()
    _, stage = render_env(d, "alpha/stage", (READS_INTENT,))
    _, prod = render_env(d, "alpha/prod", (READS_INTENT,))
    assert (stage["fake/neutral.txt"], prod["fake/neutral.txt"]) == ("stage\n", "shared\n")
    assert json.loads(stage["MANIFEST.json"])["overrides"] == [
        {"entry": SSO, "attribute": "description", "values": ["stage"], "from": "alpha/stage"}]
    assert "overrides" not in json.loads(prod["MANIFEST.json"])


def test_the_planner_explains_a_difference_the_overrides_make_instead_of_blocking():
    p = plan(estate(), "alpha/prod", "alpha/stage", AS_OF, (READS_INTENT,))
    assert not [b for b in p.blockers if b[0] == "Intent"]
    assert "Environment-neutral outputs fake/neutral.txt differ only by the environments' overrides (see the " \
           "Overrides actions); the shared intent is identical." in p.ok
    assert [t for a, t, _, _ in p.actions if a == "Overrides"] == [
        f"`description` of `{SSO}`: alpha/prod runs `shared` (the shared value), alpha/stage runs `stage` (its "
        "override: a smaller stage). Confirm the target should behave differently, or align the overrides."]


def test_a_neutral_difference_no_override_explains_is_still_a_blocker():
    d = mini_estate.directory()
    ctx = PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF,
                      {"fake/neutral.txt": "a\n"}, {"fake/neutral.txt": "b\n"}, ("fake/neutral.txt",))
    (area, text, _), = checks((), ())[0](ctx).blockers
    assert (area, text) == ("Intent", "Environment-neutral outputs differ: fake/neutral.txt")


def test_a_role_the_target_declares_but_doesnt_bind_is_a_blocker_naming_why():
    required = add(f"cn=waf,ou=stack,{STAGE}", "ciamRequiredRole", cn="waf", ciamBindingRole="waf",
                   description="public login pages sit behind a WAF")
    p = plan(estate(required), "alpha/prod", "alpha/stage", AS_OF, (READS_INTENT,))
    assert ("Binding", "Role `waf` is required in alpha/stage (declared by alpha/stage: public login pages sit "
                       "behind a WAF) but nothing binds it.", "**NO OWNER**") in p.blockers


def test_the_overrides_report_and_the_stack_check_show_the_overlay():
    d = estate()
    assert override_rows(d) == [("alpha/stage", SSO, "description", "shared", "stage", "alpha/stage",
                                 "a smaller stage")]
    rows, problems = stack_rows(env_model(d, "alpha/stage"), (FAKE,), VERSIONS)
    assert rows[0] == ("alpha/stage", "-", "-", "overlay of alpha/prod: inherits the bindings, stack, required roles "
                                                "and overrides it doesn't set itself") and problems == 0

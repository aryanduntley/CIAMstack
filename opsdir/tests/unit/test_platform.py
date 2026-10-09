"""Environments, declared stacks, rendering, planning and migration, exercised with a fake adapter on a mini estate:
the core works without any real adapter or the showcase installed."""
import datetime as dt
import json

import pytest

from opsdir.connectors import migration
from opsdir.connectors.plan import plan
from opsdir.connectors.registry import (core_fragments, environment, environment_specs, schema_fragments,
                                       secret_command, services, vocabulary)
from opsdir.connectors.render import render_env
from opsdir.connectors.stack import declared_adapters, stack_rows
from opsdir.core.environment import StackComponent
from opsdir.connectors.workspace import cutover_changes
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir.domains.federation.checks import published_hosts
from opsdir.store.postgres import schema_rows
import mini_estate
from mini_estate import FAKE, FAKE_ARC, FAKE_SCHEMA, VERSIONS

AS_OF = dt.date(2026, 1, 1)
ALPHA, BETA = "alpha/prod", "beta/prod"


@pytest.fixture(scope="module")
def d():
    return mini_estate.directory()


def test_environments_and_their_stacks(d):
    assert environment_specs(d) == (ALPHA, BETA)
    m = env_model(d, ALPHA)
    assert (m.provider, [(c.role, c.adapter) for c in m.stack]) == ("fakecloud", [("provider", "fake-cloud")])


def test_the_declared_adapter_renders_and_required_roles_resolve(d):
    m, adapters = environment(d, ALPHA, (FAKE,))
    assert adapters == (FAKE,) and m.unbound == ()
    assert environment(d, BETA, (FAKE,))[0].unbound == ("disk-encryption",)


def test_rendering_uses_the_adapter_and_its_secret_resolver(d):
    m, files = render_env(d, ALPHA, (FAKE,))
    assert files["fake/env.txt"] == "alpha/prod: fake-cli get secrets/admin\n"
    manifest = json.loads(files["MANIFEST.json"])
    assert manifest["provider"] == "fakecloud"
    assert {p: f["scope"] for p, f in manifest["files"].items()} == {"fake/env.txt": "environment-specific",
                                                                      "fake/neutral.txt": "environment-neutral"}


def test_secret_references_resolve_through_the_given_adapters():
    assert secret_command("fake://x", (FAKE,)) == services((FAKE,)).secret_command("fake://x") == "fake-cli get x"
    with pytest.raises(SystemExit, match="no resolver"):
        secret_command("fake://x", ())


def test_stack_check_against_what_is_installed(d):
    m = env_model(d, ALPHA)
    assert stack_rows(m, (FAKE,), VERSIONS) == (((ALPHA, "provider", "fake-cloud", "ok (installed 0.5)"),), 0)
    rows, problems = stack_rows(m, (), {})
    assert problems == 1 and rows[0][3] == "NOT INSTALLED; get it from https://example.test/fake-cloud"


def test_an_installed_adapters_schema_joins_the_store_but_not_the_published_file():
    assert schema_fragments(adapters=(FAKE,)) == (*core_fragments(), FAKE_SCHEMA)
    assert FAKE_SCHEMA not in core_fragments() and schema_fragments(adapters=()) == core_fragments()
    ats, _ = schema_rows(registry_ldif(schema_fragments(adapters=(FAKE,))))
    assert next(a for a in ats if a["name"] == "fakeTier")["oid"] == f"{FAKE_ARC}.1.1"


# A generic adapter for a standard: every compliant environment would match it, so it is never inferred.
GENERIC = FAKE._replace(name="generic", kind="product", applies=None, ref_schemes=(), secret_schemes={}, vocabulary={})


def test_an_environment_renders_without_a_provider_adapter(d):
    """What an environment's other adapters render doesn't wait for an adapter that renders its infrastructure (a
    cluster on the operator's own hardware); an environment nothing renders for is refused."""
    product = FAKE._replace(kind="product")
    m, files = render_env(d, ALPHA, (product,))
    assert files["fake/env.txt"] == "alpha/prod: fake-cli get secrets/admin\n"
    assert json.loads(files["MANIFEST.json"])["provider"] == "fakecloud"
    with pytest.raises(SystemExit, match="nothing renders alpha/prod: no installed adapter that renders applies"):
        render_env(d, ALPHA, (product._replace(render_neutral=None, render_env=None),))


def test_a_declaration_only_adapter_is_never_inferred(d):
    m = env_model(d, ALPHA)
    assert declared_adapters(m._replace(stack=()), (FAKE, GENERIC)) == (FAKE,)
    assert stack_rows(m, (FAKE, GENERIC), {**VERSIONS, "generic": "1.0"})[1] == 0     # undeclared: not a problem


def test_a_declaration_only_adapter_renders_where_a_stack_declares_it(d):
    m = env_model(d, ALPHA)
    declared = m._replace(stack=(*m.stack, StackComponent("directory", "generic", None, None)))
    assert declared_adapters(declared, (FAKE, GENERIC)) == (FAKE, GENERIC)
    rows, problems = stack_rows(declared, (FAKE, GENERIC), {**VERSIONS, "generic": "1.0"})
    assert problems == 0 and rows[-1][2:] == ("generic", "ok (installed 1.0)")


def test_the_plan_blocks_a_move_that_loses_a_role(d):
    p = plan(d, ALPHA, BETA, AS_OF, (FAKE,))
    assert [b[1] for b in p.blockers] == ["Role `disk-encryption` is bound in alpha/prod but not in beta/prod."]
    assert "fake check ran for beta/prod" in p.ok
    assert any("render identically" in ok for ok in p.ok)


def test_the_identity_service_keeps_its_published_address(d):
    p = plan(d, BETA, ALPHA, AS_OF, (FAKE,))
    assert "Identity service `sso` keeps its published address in alpha/prod (sso.example.test served by the " \
           "`web` service name)." in p.ok
    assert p.blockers == ()


def test_a_renamed_service_name_is_blocked_once_by_the_contract_check(d):
    rename = parse("dn: cn=svc-sso,ou=bindings,env=prod,cloud=alpha,ou=environments,dc=ciam-ops\n"
                   "changetype: modify\nreplace: ciamFqdn\nciamFqdn: sso.alpha.example.test\n-\n")
    p = plan(mini_estate.directory(rename), BETA, ALPHA, AS_OF, (FAKE,))
    assert [b[0] for b in p.blockers] == ["Contract"]


def test_a_published_address_no_service_name_serves_is_blocked(d):
    moved = parse("dn: cn=sso,ou=identity-services,dc=ciam-ops\nchangetype: modify\nreplace: ciamBaseUrl\n"
                  "ciamBaseUrl: https://login.example.test\n-\n")
    r = migration.run(mini_estate.directory(moved), BETA, ALPHA, AS_OF, (FAKE,), VERSIONS)
    assert r.ready is False
    ((area, text, _),) = r.plan.blockers
    assert area == "Identity service"
    assert text.startswith("`sso` publishes `login.example.test`, which no service name for `web` serves "
                           "(beta/prod: `sso.example.test`; alpha/prod: `sso.example.test`)")


def test_published_hosts_are_the_url_contracts_hosts_once_each():
    (service,) = [e for e in mini_estate.directory().entries.values() if e.dn.startswith("cn=sso,")]
    assert published_hosts(service) == ("sso.example.test",)         # the URN entity ID has no host


@pytest.mark.parametrize("src, dst, ready", [(ALPHA, BETA, False), (BETA, ALPHA, True)])
def test_migration_runs_in_both_directions(d, src, dst, ready):
    r = migration.run(d, src, dst, AS_OF, (FAKE,), VERSIONS)
    assert r.ready is ready
    assert migration.output_files(r)["target/fake/env.txt"].startswith(f"{dst}:")


def test_migration_stops_when_the_declared_adapter_is_missing(d):
    r = migration.run(d, ALPHA, BETA, AS_OF, (), {})
    assert (r.plan, r.ready, r.stack_problems) == (None, False, 2)


def test_the_fake_adapter_owns_its_vocabulary():
    assert ("ciamCloudProvider", "fakecloud", "fake-cloud") in vocabulary(domains=(), adapters=(FAKE,))


def test_workspace_changes_and_conflicts_on_the_mini_estate(d):
    edit = parse("dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\nreplace: ciamRegion\n"
                 "ciamRegion: region-2\n-\n")
    edited = mini_estate.directory(edit)
    changes, conflicts = cutover_changes(d, d, edited)
    assert [(r.changetype, r.dn) for r in changes] == [("modify", "cloud=beta,ou=environments,dc=ciam-ops")]
    assert conflicts == ()
    assert cutover_changes(d, edited, edited)[1] == ("cloud=beta,ou=environments,dc=ciam-ops",)

"""Environments, declared stacks, rendering, planning and migration, exercised with a fake adapter on a mini estate:
the core works without any real adapter or the showcase installed."""
import datetime as dt
import json

import pytest

from opsdir.connectors import migration
from opsdir.connectors.plan import plan
from opsdir.connectors.registry import environment, environment_specs, secret_command, services, vocabulary
from opsdir.connectors.render import render_env
from opsdir.connectors.stack import stack_rows
from opsdir.connectors.workspace import cutover_changes
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
import mini_estate
from mini_estate import FAKE, VERSIONS

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


def test_the_plan_blocks_a_move_that_loses_a_role(d):
    p = plan(d, ALPHA, BETA, AS_OF, (FAKE,))
    assert [b[1] for b in p.blockers] == ["Role `disk-encryption` is bound in alpha/prod but not in beta/prod."]
    assert "fake check ran for beta/prod" in p.ok
    assert any("render identically" in ok for ok in p.ok)


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

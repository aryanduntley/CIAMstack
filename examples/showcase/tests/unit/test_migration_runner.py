"""The migration runner on the showcase, in both directions (pure)."""
import json

import pytest

from opsdir.cli import migrate_text
from opsdir.connectors import migration
from opsdir.connectors.registry import ADAPTER_VERSIONS, ADAPTERS
from opsdir.domains.directory.drift import drift
from showcase_support import GOLDEN
from support import read_tree

SRC, DST = "source/prod", "target/prod"


def _run(estate, as_of, src, dst, state="before", adapters=ADAPTERS):
    return migration.run(estate[state], src, dst, as_of, adapters, ADAPTER_VERSIONS)


@pytest.mark.parametrize("src, dst, provider", [(SRC, DST, "azure"), (DST, SRC, "aws")])
def test_both_directions_render_the_target_with_its_own_provider(estate, as_of, src, dst, provider):
    r = _run(estate, as_of, src, dst)
    assert r.stack_problems == 0 and r.plan is not None
    manifest = json.loads(migration.output_files(r)["target/MANIFEST.json"])
    assert manifest["provider"] == provider and manifest["environment"].startswith(f"env=prod,cloud={dst.split('/')[0]}")


def test_forward_outputs_are_the_golden_plan_and_render(estate, as_of):
    files = migration.output_files(_run(estate, as_of, SRC, DST, "after"))
    assert {p[len("target/"):]: t for p, t in files.items() if p.startswith("target/")} == \
        read_tree(GOLDEN / "render-after" / "target-prod")
    assert {p: t for p, t in files.items() if not p.startswith("target/")} == read_tree(GOLDEN / "plan-after")


def test_blockers_make_the_run_not_ready(estate, as_of):
    r = _run(estate, as_of, SRC, DST)
    assert r.plan.blockers and not r.ready


def test_a_missing_adapter_stops_the_run_before_planning(estate, as_of):
    r = _run(estate, as_of, SRC, DST, adapters=tuple(a for a in ADAPTERS if a.name != "azure"))
    assert r.plan is None and not r.ready and r.stack_problems == 1
    assert migration.output_files(r) == {}
    assert migration.summary(r, "out") == "stopped: 1 stack problem(s); nothing rendered"


def test_the_cli_text_and_exit_status(estate, as_of):
    text, files, status = migrate_text(estate["before"], SRC, DST, as_of, "out/m")
    assert status == 1 and text.endswith("NOT READY (7 blockers, 11 actions); 21 target files, PLAN.md and "
                                         "3 request draft(s) in out/m")
    assert "PLAN.md" in files


def test_drift_is_scoped_to_the_servers_given(estate):
    d = estate["before"]
    everywhere = drift(d)
    assert everywhere and drift(d, []) == []
    servers = {row[0] for row in everywhere}
    assert {row[0] for row in drift(d, [e.dn for e in d.entries.values() if "ciamServer" in e.classes])} == servers

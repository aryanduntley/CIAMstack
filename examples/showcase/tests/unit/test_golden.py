"""The synthetic estate, built in memory, renders and plans exactly what tests/golden recorded through Postgres."""
import json

import pytest

from opsdir.cli import export_text, format_table, search_text
from opsdir.connectors.plan import plan, request_drafts, to_markdown
from opsdir.connectors.render import render_env
from opsdir.core.naming import SUFFIX
from opsdir.domains.directory.drift import DRIFT_HEADERS, drift
from showcase_support import APPROVED, DATA, GOLDEN, cmd_output
from support import read_tree

SRC, DST = "source/prod", "target/prod"
# (fixture state, environment spec) -> golden render directory
RENDERS = (("before", SRC, "render-before/source-prod"), ("before", DST, "render-before/target-prod"),
           ("after", DST, "render-after/target-prod"), ("before", "standby/prod", "render-before/standby-prod"))


@pytest.mark.parametrize("state, spec, golden", RENDERS)
def test_render_matches_golden(estate, state, spec, golden):
    _, files = render_env(estate[state], spec)
    assert files == read_tree(GOLDEN / golden)


@pytest.mark.parametrize("state", ["before", "after"])
def test_plan_matches_golden(estate, as_of, state):
    p = plan(estate[state], SRC, DST, as_of)
    assert {"PLAN.md": to_markdown(p), **request_drafts(p)} == read_tree(GOLDEN / f"plan-{state}")


@pytest.mark.parametrize("state, applied", [("before", set()), ("after", {cid for cid, _ in APPROVED})])
def test_planner_finds_exactly_what_was_planted(estate, as_of, check_findings, state, applied):
    expected = json.loads((DATA / "expected-findings.json").read_text())
    results = check_findings.check(expected, plan(estate[state], SRC, DST, as_of), applied)
    assert all(check_findings.passed(r) for r in results), \
        "\n".join(line for r in results for line in check_findings.result_lines(r))


def test_drift_report_matches_golden(estate):
    text = format_table(drift(estate["before"]), DRIFT_HEADERS)
    assert cmd_output(text) == (GOLDEN / "cmd" / "03-report-drift.txt").read_text()


def test_search_table_matches_golden(estate):
    text = search_text(estate["before"], "ou=consumers,dc=ciam-ops",
                       "(&(objectClass=ciamConsumer)(!(ciamMigrationStatus=tested)))",
                       attrs=("ciamMigrationStatus", "ciamOwner"))
    assert cmd_output(text) == (GOLDEN / "cmd" / "04-search-table.txt").read_text()


def test_search_ldif_matches_golden(estate):
    text = search_text(estate["before"], "ou=integrations,dc=ciam-ops", "(objectClass=ciamIntegration)")
    assert cmd_output(text) == (GOLDEN / "cmd" / "04-search-ldif.txt").read_text()


def test_export_after_changes_matches_golden(estate):
    assert export_text(estate["after"], SUFFIX) + "\n" == (GOLDEN / "export.ldif").read_text()

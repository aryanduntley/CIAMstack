"""Every command run through the CLI against Postgres, where the store's rules (R1-R10) run in its triggers:
the outputs reproduce tests/golden, the guardrails hold regardless of the baseline, and the database agrees with
the in-memory estate the unit suite uses."""
import pytest

from opsdir.cli import export_text
from opsdir.connectors.render import render_env
from opsdir.core.naming import SUFFIX
from support import APPROVED, GOLDEN, read_tree

pytestmark = pytest.mark.integration

GOLDEN_TREE = read_tree(GOLDEN)
# guardrail write (snapshot command name) -> why the store must refuse it
REJECTED = {"07-reject-unapproved": "is not an approved change record",
            "07-reject-cert-in-use": "is still referenced",
            "07-reject-secret-value": "is not a valid ref-uri",
            "07-reject-missing-attr": "is missing required attribute"}


@pytest.mark.parametrize("path", sorted(GOLDEN_TREE))
def test_output_matches_golden(snapshot, path):
    assert snapshot.get(path) == GOLDEN_TREE[path]


def test_no_outputs_beyond_golden(snapshot):
    assert sorted(set(snapshot) - set(GOLDEN_TREE)) == []


@pytest.mark.parametrize("name, reason", sorted(REJECTED.items()))
def test_guardrail_rejects_the_write(snapshot, name, reason):
    text = snapshot[f"cmd/{name}.txt"]
    assert text.startswith("REJECTED by the directory:") and reason in text and text.endswith("exit 1\n"), text


@pytest.mark.parametrize("change", [cid for cid, _ in APPROVED])
def test_approved_change_applies_and_is_in_history(snapshot, change):
    text = snapshot[f"cmd/08-apply-{change.lower()}.txt"]
    assert text.startswith(f"{change}: ") and text.endswith("exit 0\n"), text
    assert change in snapshot["cmd/09-history.txt"]


@pytest.mark.parametrize("name", ["06-check-before", "11-check-after", "00-generated-diff"])
def test_checks_pass(snapshot, name):
    text = snapshot[f"cmd/{name}.txt"]
    assert text.endswith("exit 0\n"), text


def test_database_agrees_with_the_in_memory_estate(snapshot, estate):
    """Rejected writes left nothing behind: after the approved changes the store holds exactly what applying only
    those changes in memory gives, and renders the same target."""
    assert snapshot["export.ldif"] == export_text(estate["after"], SUFFIX) + "\n"
    _, files = render_env(estate["after"], "target/prod")
    assert {p: snapshot.get(f"render-after/target-prod/{p}") for p in files} == files

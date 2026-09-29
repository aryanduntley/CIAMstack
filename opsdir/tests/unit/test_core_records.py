"""Small core records: findings, network arithmetic, naming, and how a plan describes what a target renders to."""
import pytest

from opsdir.connectors.plan import render_summary
from opsdir.core.contract import Adapter
from opsdir.core.findings import Findings, findings, merge_findings
from opsdir.core.naming import SUFFIX, branch
from opsdir.core.network import covers, is_private


def test_findings_merge_concatenates_each_column_in_order():
    a = findings(blockers=[("A", "a", "o")], ok=["fine"])
    b = findings(actions=[("B", "b", "o", None)], ok=["also"], requests=[("r",)])
    assert merge_findings([a, b]) == Findings((("A", "a", "o"),), (("B", "b", "o", None),), ("fine", "also"), (("r",),))
    assert merge_findings([]) == findings()


@pytest.mark.parametrize("cidrs, addr, expected", [
    (["10.20.0.0/16"], "10.20.1.5", True), (["10.20.0.0/16"], "10.20.1.0/24", True),
    (["10.20.1.0/24"], "10.20.0.0/16", False), (["192.0.2.0/24", "198.51.100.7/32"], "198.51.100.7/32", True),
    ([], "10.0.0.1", False)])
def test_covers(cidrs, addr, expected):
    assert covers(cidrs, addr) is expected


def test_is_private():
    assert is_private("10.1.2.3/32") and not is_private("9.9.9.9")


def test_branch_names():
    assert branch("consumers") == f"ou=consumers,{SUFFIX}"
    assert branch("declared", branch("config")) == f"ou=declared,ou=config,{SUFFIX}"


def _adapter(renders, neutral_label):
    return Adapter("x", "product", None, (), None, None, (), (), {}, renders, neutral_label, {}, None, (), (), (), ())


def test_render_summary_reads_like_a_sentence():
    assert render_summary(()) == "nothing"
    assert render_summary((_adapter("infrastructure code", None),)) == "infrastructure code"
    assert render_summary((_adapter("infrastructure code", None), _adapter("scripts", "A"), _adapter(None, "B"))) == \
        "infrastructure code, scripts, and the environment-neutral A/B configuration"

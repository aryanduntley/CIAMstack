"""Small core records: findings, network arithmetic, naming, and how a plan describes what a target renders to."""
import pytest

from opsdir.connectors.plan import render_summary
from opsdir.core.contract import Adapter
from opsdir.core.findings import Findings, all_clear, each_checked, findings, merge_findings
from opsdir.core.naming import SUFFIX, branch
from opsdir.core.network import covers, is_private


def test_findings_merge_concatenates_each_column_in_order():
    a = findings(blockers=[("A", "a", "o")], ok=["fine"])
    b = findings(actions=[("B", "b", "o", None)], ok=["also"], requests=[("r",)])
    assert merge_findings([a, b]) == Findings((("A", "a", "o"),), (("B", "b", "o", None),), ("fine", "also"),
                                              (("r",),), ())
    assert merge_findings([]) == findings()


def test_a_check_says_all_is_well_only_when_nothing_is_a_blocker_or_an_action():
    fine, blocked = findings(ok=["a holds"]), findings(blockers=[("A", "b broken", "ops")])
    assert all_clear([fine, findings()], "all hold") == findings(ok=["a holds", "all hold"])
    assert all_clear([fine, blocked], "all hold") == merge_findings([fine, blocked])
    assert all_clear([findings(actions=[("A", "do c", "ops", None)])], "all hold").ok == ()
    judge = lambda n: blocked if n < 0 else fine                                     # noqa: E731
    assert each_checked((), judge, "all hold") == findings()                         # nothing to check: nothing said
    assert each_checked((1, 2), judge, "2 hold") == findings(ok=["a holds", "a holds", "2 hold"])
    assert each_checked((1, -1), judge, "2 hold").blockers == blocked.blockers


@pytest.mark.parametrize("cidrs, addr, expected", [
    (["10.20.0.0/16"], "10.20.1.5", True), (["10.20.0.0/16"], "10.20.1.0/24", True),
    (["10.20.1.0/24"], "10.20.0.0/16", False), (["192.0.2.0/24", "198.51.100.7/32"], "198.51.100.7/32", True),
    ([], "10.0.0.1", False)])
def test_covers(cidrs, addr, expected):
    assert covers(cidrs, addr) is expected


def test_is_private():
    assert is_private("10.1.2.3/32") and not is_private("9.9.9.9")
    assert all(is_private(a) for a in ("172.31.0.5", "192.168.1.1", "100.64.0.1", "fd00::1"))
    assert not any(is_private(a) for a in ("198.51.100.20", "203.0.113.10", "192.0.2.1", "2001:db8::1", "172.32.0.1"))


def test_branch_names():
    assert branch("consumers") == f"ou=consumers,{SUFFIX}"
    assert branch("declared", branch("config")) == f"ou=declared,ou=config,{SUFFIX}"


def _adapter(renders, neutral_label):
    return Adapter("x", "product", None, (), None, None, (), (), {}, renders, neutral_label, {}, None, (), (), (), (),
                   None, None)


def test_render_summary_reads_like_a_sentence():
    assert render_summary(()) == "nothing"
    assert render_summary((_adapter("infrastructure code", None),)) == "infrastructure code"
    assert render_summary((_adapter("infrastructure code", None), _adapter("scripts", "A"), _adapter(None, "B"))) == \
        "infrastructure code, scripts, and the environment-neutral A/B configuration"

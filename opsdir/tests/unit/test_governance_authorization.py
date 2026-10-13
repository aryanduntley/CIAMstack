"""The authorization hook (decisions 2727, 2728): the operations layer asks one policy whether a requester may do an
action over an area before the operation runs; allow_all is today's default, 7.7 plugs its grants in as the policy."""
import pytest

from opsdir import operations as ops
from opsdir.core.environment import ENVIRONMENT, Scope
from opsdir.domains.governance.authorization import Area, allow_all, area_text, refusal

KEEPER = Scope("keeper", ("cn=net-team,ou=owners,dc=ciam-ops",))


def _refuse(requester, action, area):
    return "no grant (test policy)"


def test_allow_all_refuses_no_one():
    assert refusal(allow_all, "anyone", "render", Area("target/prod")) is None


def test_a_refusal_names_the_requester_the_action_and_the_area():
    assert refusal(_refuse, "ci-bot", "render", Area("target/prod", KEEPER)) == \
        "ci-bot may not render target/prod (keeper cn=net-team,ou=owners,dc=ciam-ops): no grant (test policy)"
    assert area_text(Area("target/prod", ENVIRONMENT, "source/prod")) == "target/prod (from source/prod)"


def test_the_policy_is_asked_with_what_the_operation_acts_on():
    asked = []
    refusal(lambda *a: asked.append(a), "ci-bot", "migrate", Area("target/prod", ENVIRONMENT, "source/prod"))
    assert asked == [("ci-bot", "migrate", Area("target/prod", ENVIRONMENT, "source/prod"))]


# conn=None: the record is never loaded, so a refusal is raised before anything is computed
def test_a_refusing_policy_stops_a_render_before_the_record_is_loaded():
    with pytest.raises(SystemExit, match="ci-bot may not render target/prod \\(keeper "):
        ops.render(None, "target/prod", scope=KEEPER, requester="ci-bot", policy=_refuse)


def test_a_refusing_policy_stops_a_migration_before_the_record_is_loaded():
    with pytest.raises(SystemExit, match="ci-bot may not migrate target/prod \\(from source/prod\\)"):
        ops.migrate(None, "source/prod", "target/prod", None, requester="ci-bot", policy=_refuse)

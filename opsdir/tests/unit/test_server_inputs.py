"""A target server that records no image or size (both optional in its class) is the planner's blocker: its render
writes UNBOUND values there (core environment.recorded)."""
from opsdir.core.directory import get
from opsdir.core.environment import recorded
from opsdir.domains.infrastructure.checks import check_server_inputs
from network_fixtures import ALPHA, context, model


def test_recorded_or_unbound_naming_the_entry():
    d, _, _ = model()
    s = get(d, f"cn=web-1,{ALPHA}")
    assert recorded(s, "ciamHostname", "host") == "web-1.example.test"
    assert recorded(s, "ciamImageRef", "image") == "UNBOUND:web-1-image"


def test_a_target_server_without_image_or_size_blocks():
    d, alpha, beta = model(beta=())
    f = check_server_inputs(context(d, alpha, beta))
    assert [b[1] for b in f.blockers][0] == (
        "Server `ds-1` in beta/prod records no image or size (ciamImageRef, ciamInstanceSize): its render writes "
        "UNBOUND values there, so applying it fails. Record them.")
    assert len(f.blockers) == 3 and not f.actions

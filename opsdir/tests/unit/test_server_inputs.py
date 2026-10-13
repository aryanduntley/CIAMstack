"""A target server that records no image or size (both optional in its class) is the planner's blocker: its render
writes UNBOUND values there (core environment.recorded). So is a compute group without an image, a size or a subnet
its environment binds; a designed group records no provider ref."""
from opsdir.core.directory import get
from opsdir.core.environment import recorded
from opsdir.domains.infrastructure.checks import check_server_inputs
from opsdir.domains.compute.hosts import group_subnets, groups_with_role, run_roles, runs_role
from network_fixtures import ALPHA, context, entry, model


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


def _group(cn, role="web", **attrs):
    return entry("env=prod,cloud=beta,ou=environments,dc=ciam-ops", cn, "ciamComputeGroup", ciamBindingRole=cn,
                 ciamTargetRole=role, **attrs)


def test_a_designed_compute_group_runs_its_role_in_its_subnets():
    d, _, beta = model(beta=(_group("asg-app", "app", ciamSubnetRole=("subnet-web", "subnet-ds")),))
    (g,) = groups_with_role(beta, "app")
    assert runs_role(beta, "app") and runs_role(beta, "ds") and not runs_role(beta, "db")
    assert run_roles(beta) == ("ds", "web", "app")                  # servers' roles first, then the groups'
    assert [b.dn.split(",")[0] for b in group_subnets(beta, g)] == ["cn=subnet-web", "cn=subnet-ds"]


def test_a_target_compute_group_without_image_size_or_bound_subnet_blocks():
    d, alpha, beta = model(beta=(_group("asg-a"), _group("asg-b", ciamSubnetRole="subnet-gone"),
                                 _group("asg-ok", ciamSubnetRole="subnet-web", ciamImageRef="img-1",
                                        ciamInstanceSize="m.large")))
    f = check_server_inputs(context(d, alpha, beta))
    groups = [b[1] for b in f.blockers if b[0] == "Compute"]
    assert groups == [
        "Compute group `asg-a` in beta/prod records no image or size (ciamImageRef, ciamInstanceSize): its render "
        "writes UNBOUND values there, so applying it fails. Record them.",
        "Compute group `asg-a` in beta/prod names no subnet its instances sit in (ciamSubnetRole): its render can't "
        "place them. Record the subnet roles, one per zone it spans.",
        "Compute group `asg-b` in beta/prod records no image or size (ciamImageRef, ciamInstanceSize): its render "
        "writes UNBOUND values there, so applying it fails. Record them.",
        "Compute group `asg-b` in beta/prod names subnet role(s) `subnet-gone` that beta/prod doesn't bind: its "
        "instances can't be placed there. Bind them, or name bound subnets."]

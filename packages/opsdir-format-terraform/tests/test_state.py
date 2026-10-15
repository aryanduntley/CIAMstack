"""Terraform state (format version 4) read as resource instances, sensitive attributes dropped before anything reads
them; anything else refused with why. What the cloud importers share: a state's (type, attributes) pairs with the
types they don't read named, its resources as a cloud reads the pairs, and the collection steps fetching the states."""
import json

from opsdir_format_terraform.state import read_state, state_pairs, state_resources, state_steps


def test_resource_instances_are_read_without_their_sensitive_attributes():
    doc = {"version": 4, "resources": [
        {"mode": "managed", "type": "random_password", "name": "db", "instances": [
            {"attributes": {"id": "none", "result": "p4ss", "length": 24},
             "sensitive_attributes": [[{"type": "get_attr", "value": "result"}]]}]},
        {"mode": "data", "type": "aws_vpc", "name": "main", "instances": [{"attributes": {"id": "vpc-1"}}]}]}
    found, problem = read_state(json.dumps(doc))
    assert problem is None
    assert [(r.mode, r.type, r.name, dict(r.attributes)) for r in found] == [
        ("managed", "random_password", "db", {"id": "none", "length": 24}),
        ("data", "aws_vpc", "main", {"id": "vpc-1"})]


def test_what_is_not_a_version_4_state_is_refused():
    assert read_state("{") == ((), "not JSON")
    assert read_state(json.dumps({"version": 3, "modules": []})) == ((), "not a Terraform state (format version 4)")


STATE = json.dumps({"version": 4, "resources": [
    {"mode": "managed", "type": "random_password", "name": "a", "instances": [{"attributes": {"id": "1"}},
                                                                              {"attributes": {"id": "2"}}]},
    {"mode": "managed", "type": "aws_vpc", "name": "main", "instances": [{"attributes": {"id": "vpc-1"}}]}]})
SKIPPED = ("random_password",)


def test_a_states_pairs_name_the_types_not_read():
    pairs, notices = state_pairs(STATE, SKIPPED)
    assert pairs == (("random_password", {"id": "1"}), ("random_password", {"id": "2"}), ("aws_vpc", {"id": "vpc-1"}))
    assert notices == ("random_password (2): not read (holds secret values, or isn't modeled yet)",)
    renamed, _ = state_pairs(STATE, SKIPPED, names=lambda t, a: {"name": a["id"]})        # the readers' names
    assert renamed[-1] == ("aws_vpc", {"name": "vpc-1"})
    assert state_pairs("[]", SKIPPED) == ((), ("not a Terraform state (format version 4)",))


def test_a_states_resources_as_the_cloud_reads_its_pairs_the_skipped_named_after_or_first():
    def read(pairs):
        return tuple(t for t, _ in pairs if t not in SKIPPED), ("read",)
    skipped = "random_password (2): not read (holds secret values, or isn't modeled yet)"
    assert state_resources(STATE, SKIPPED, read) == (("aws_vpc",), ("read", skipped))
    assert state_resources(STATE, SKIPPED, read, skipped_first=True) == (("aws_vpc",), (skipped, "read"))


def test_the_state_collection_steps_pull_or_fetch_each_source_location():
    from opsdir.core.contract import Command
    from opsdir.core.directory import make_entry
    from network_fixtures import ALPHA, model
    _, m, _ = model()
    sources = tuple(make_entry(f"cn=tf-{i},ou=bindings,{ALPHA}", ("top", "ciamCollectionSource"),
                               {"cn": (f"tf-{i}",), "ciamBindingRole": (f"tf-{i}",),
                                "ciamImporter": ("x/terraform-state",), "ciamSourceRef": (loc,)})
                    for i, loc in enumerate(("mem://b/k/ciam.tfstate", "mem://b/dir/", "mem://skip", "other://b/x")))
    with_sources = m._replace(bindings=(*m.bindings, *sources))

    def fetch(loc):
        return None if loc.endswith("skip") else Command(("cat", loc))
    assert state_steps(with_sources, "x/terraform-state", "mem://", fetch, {}) == (
        ("alpha/prod/ciam.tfstate", Command(("cat", "mem://b/k/ciam.tfstate"))),
        ("alpha/prod/terraform.tfstate", Command(("cat", "mem://b/dir/"))))
    assert state_steps(m, "x/terraform-state", "mem://", fetch, {}) == ()
    (pull,) = state_steps(with_sources, "x/terraform-state", "mem://", fetch, {"terraform_dir": "/work"})
    assert pull == ("alpha/prod/terraform.tfstate", Command(("terraform", "-chdir=/work", "state", "pull")))

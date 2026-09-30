"""Terraform state (format version 4) read as resource instances, sensitive attributes dropped before anything reads
them; anything else refused with why."""
import json

from opsdir_format_terraform.state import read_state


def test_resource_instances_are_read_without_their_sensitive_attributes():
    doc = {"version": 4, "resources": [
        {"mode": "managed", "type": "random_password", "name": "db", "instances": [
            {"attributes": {"id": "none", "result": "p4ss", "length": 24},
             "sensitive_attributes": [[{"type": "get_attr", "value": "result"}]]}]},
        {"mode": "data", "type": "aws_vpc", "name": "main", "instances": [{"attributes": {"id": "vpc-1"}}]}]}
    found, problem = read_state(json.dumps(doc))
    assert problem is None
    assert [(r.mode, r.type, r.name, dict(r.attributes)) for r in found] == [
        ("managed", "random_password", "db", {"id": "none", "length": 24}), ("data", "aws_vpc", "main", {"id": "vpc-1"})]


def test_what_is_not_a_version_4_state_is_refused():
    assert read_state("{") == ((), "not JSON")
    assert read_state(json.dumps({"version": 3, "modules": []})) == ((), "not a Terraform state (format version 4)")

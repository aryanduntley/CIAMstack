"""The estate's tag policy and account on AWS: the provider block tags every resource with the policy (default_tags)
and makes Terraform refuse any account but the recorded one on the platform's own roots."""
import json

import pytest

from opsdir.connectors.importing import import_changes
from opsdir.connectors.prerequisites import prerequisite_rows
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_aws.account import provider_block
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.regions import read_regions, region_rows
from opsdir_adapter_aws.tags import state_tags
from estate_fixtures import estate as _pair

REGIONS = {"Regions": [
    {"Endpoint": "ec2.us-east-1.amazonaws.com", "RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
    {"Endpoint": "ec2.af-south-1.amazonaws.com", "RegionName": "af-south-1", "OptInStatus": "not-opted-in"},
    {"Endpoint": "ec2.eu-south-2.amazonaws.com", "RegionName": "eu-south-2", "OptInStatus": "opted-in"}]}


def test_the_aws_provider_tags_everything_and_runs_against_the_recorded_account():
    _, d, alpha, beta = _pair(account="123456789012")
    assert provider_block(alpha) == """provider "aws" {
  region              = "region-1"
  allowed_account_ids = ["123456789012"]
  default_tags {
    tags = {
      Cloud       = "alpha"
      CostCenter  = "CC-1234"
      DataClass   = "confidential"
      Environment = "alpha/prod"
      Estate      = "example"
      Owner       = "platform"
    }
  }
}"""
    assert "allowed_account_ids" not in provider_block(alpha, own_account=False)
    assert "allowed_account_ids" not in provider_block(beta)                   # beta's cloud records no account
    assert "default_tags" not in provider_block(env_model(_pair(rules=())[1], "alpha/prod"))
    assert "use_fips_endpoint" not in provider_block(alpha)


def test_the_provider_uses_fips_endpoints_when_the_cloud_says_so():
    fips = LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {},
                      (("add", "objectClass", ("ciamCloudEndpoints",)), ("replace", "ciamFipsEndpoints", ("TRUE",))))
    _, d, alpha, _ = _pair(extra=(fips,))
    assert "  use_fips_endpoint = true\n" in provider_block(alpha)


def test_the_region_list_reads_describe_regions():
    assert region_rows(REGIONS) == (("us-east-1", None, None, "available", "public"),
                                    ("af-south-1", None, None, "opt-in", "public"),
                                    ("eu-south-2", None, None, "opt-in", "public"))
    _, d, *_ = _pair()
    imported = read_regions({"regions.json": json.dumps(REGIONS), "notes.txt": "not json"}, d, ())
    assert [r.dn for r in import_changes(d, imported)] == [
        "ou=regions,dc=ciam-ops", "cn=aws,ou=regions,dc=ciam-ops",
        *(f"cn={r},cn=aws,ou=regions,dc=ciam-ops" for r in ("af-south-1", "eu-south-2", "us-east-1"))]
    assert imported.notices[-1] == "notes.txt: not `aws ec2 describe-regions` output; not read"
    with pytest.raises(SystemExit, match="aws: the export lists no regions"):
        read_regions({"notes.txt": "{}"}, d, ())


def test_the_region_list_is_a_prerequisite_fetched_by_running_the_aws_cli():
    importer = next(i for i in ADAPTER.importers if i.name == "regions")
    assert importer.commands == (("regions.json", ("aws", "ec2", "describe-regions", "--all-regions", "--output",
                                                   "json")),)
    _, d, *_ = _pair()
    assert prerequisite_rows(d, (ADAPTER,)) == (
        ("aws-regions", "aws", "not needed yet", "opsdir import aws/regions --run",
         "aws ec2 describe-regions --all-regions --output json > regions.json"),)
    assert ADAPTER.prerequisites[0].met(d) is False


def test_state_tags_include_the_provider_s_default_tags():
    assert state_tags({"tags": {"Role": "ds"}, "tags_all": {"Role": "ds", "Owner": "platform"}}) == {
        "Role": "ds", "Owner": "platform"}
    assert state_tags({}) == {}

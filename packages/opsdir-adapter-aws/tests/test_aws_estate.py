"""The estate's tag policy and account on AWS: the provider block tags every resource with the policy (default_tags)
and makes Terraform refuse any account but the recorded one on the platform's own roots."""
from opsdir.core.environment import env_model
from opsdir_adapter_aws.account import provider_block
from opsdir_adapter_aws.tags import state_tags
from estate_fixtures import estate as _pair


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


def test_state_tags_include_the_provider_s_default_tags():
    assert state_tags({"tags": {"Role": "ds"}, "tags_all": {"Role": "ds", "Owner": "platform"}}) == {
        "Role": "ds", "Owner": "platform"}
    assert state_tags({}) == {}

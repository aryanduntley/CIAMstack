"""The estate's tag policy and subscription on Azure: the policy's tags merged under every resource's own tags (azurerm
has no provider-wide default), the recorded subscription as each root's subscription_id default, and the environment's
resource group when the network binding names none."""
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_azure.account import subscription_variable, tagged
from opsdir_adapter_azure.plumbing import network_data
from estate_fixtures import ALPHA, estate


def test_the_policy_s_tags_under_the_resource_s_own():
    _, d, alpha, beta = estate(account="00000000-1111-2222-3333-444444444444")
    assert tagged(alpha, {"Role": "ds", "Owner": "someone-else"}) == {
        "Cloud": "alpha", "CostCenter": "CC-1234", "DataClass": "confidential", "Environment": "alpha/prod",
        "Estate": "example", "Owner": "someone-else", "Role": "ds"}
    assert tagged(env_model(estate(rules=())[1], "alpha/prod"), {"Role": "ds"}) == {"Role": "ds"}


def test_the_recorded_subscription_is_the_default():
    _, d, alpha, beta = estate(account="00000000-1111-2222-3333-444444444444")
    assert subscription_variable(alpha, described=True) == """variable "subscription_id" {
  type        = string
  description = "The subscription prod runs in"
  default     = "00000000-1111-2222-3333-444444444444"
}"""
    assert subscription_variable(beta) == 'variable "subscription_id" {\n  type = string\n}'


def test_the_environment_s_resource_group_when_the_network_names_none():
    _, d, alpha, _ = estate()
    assert "UNBOUND: neither the network binding nor the environment names a resource group" in network_data(alpha)[0]
    grouped = estate(extra=(LdifRecord(ALPHA, "modify", {}, (("replace", "ciamResourceGroup", ("rg-ciam-prod",)),)),))
    assert 'name = "rg-ciam-prod"' in network_data(env_model(grouped[1], "alpha/prod"))[0]

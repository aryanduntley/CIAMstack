"""The estate's tag policy and subscription on Azure: the policy's tags merged under every resource's own tags (azurerm
has no provider-wide default), the recorded subscription as each root's subscription_id default, and the environment's
resource group when the network binding names none."""
import json

import pytest

from opsdir.connectors.importing import import_changes
from opsdir.connectors.prerequisites import prerequisite_rows
from opsdir.core.environment import env_model, of_class
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_azure.account import provider_block, subscription_variable, tagged
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.inventory import state_resources
from opsdir_adapter_azure.dns import service_record
from network_fixtures import entry, model
from opsdir_adapter_azure.regions import read_regions, region_rows
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


LOCATIONS = [
    {"name": "eastus2", "displayName": "East US 2", "regionalDisplayName": "(US) East US 2", "type": "Region",
     "metadata": {"regionType": "Physical", "geography": "United States", "geographyGroup": "US",
                  "pairedRegion": [{"name": "centralus"}]}},
    {"name": "westeurope", "displayName": "West Europe", "type": "Region",
     "metadata": {"regionType": "Physical", "geography": "Europe", "geographyGroup": "Europe"}},
    {"name": "unitedstates", "displayName": "United States", "type": "Region",
     "metadata": {"regionType": "Logical", "geographyGroup": "US"}}]


def test_the_region_list_reads_list_locations_physical_regions_only():
    assert region_rows(LOCATIONS) == (("eastus2", "East US 2", "United States", "available", None),
                                      ("westeurope", "West Europe", "Europe", "available", None))
    _, d, *_ = estate()
    imported = read_regions({"regions.json": json.dumps(LOCATIONS), "other.json": "{}"}, d, ())
    assert [r.dn for r in import_changes(d, imported)][2:] == [
        "cn=eastus2,cn=azure,ou=regions,dc=ciam-ops", "cn=westeurope,cn=azure,ou=regions,dc=ciam-ops"]
    assert imported.notices[-2:] == ("azure: 1 logical location(s) left out (geographies, not regions): unitedstates",
                                     "other.json: not `az account list-locations` output; not read")
    with pytest.raises(SystemExit, match="azure: the export lists no regions"):
        read_regions({"regions.json": json.dumps(LOCATIONS[2:])}, d, ())


def test_the_region_list_is_a_prerequisite_fetched_by_running_the_azure_cli():
    _, d, *_ = estate()
    assert prerequisite_rows(d, (ADAPTER,)) == (
        ("azure-regions", "azure", "not needed yet", "opsdir import azure/regions --run",
         "az account list-locations -o json > regions.json"),)


def test_the_provider_notes_that_azure_has_no_fips_endpoints_to_switch_to():
    fips = LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {},
                      (("add", "objectClass", ("ciamCloudEndpoints",)), ("replace", "ciamFipsEndpoints", ("TRUE",)),
                       ("replace", "ciamCloudEnvironment", ("usgovernment",))))
    _, d, alpha, beta = estate(extra=(fips,))
    assert provider_block(alpha).startswith('provider "azurerm" {\n  # FIPS endpoints: Azure has no separate FIPS '
                                            'endpoints')
    assert '  environment     = "usgovernment"\n' in provider_block(alpha)
    assert "FIPS" not in provider_block(beta) and "environment" not in provider_block(beta)


def _state(provider, *resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": f"r{i}", "provider": f'provider["registry.terraform.io/hashicorp/{provider}"]',
         "instances": [{"attributes": a}]} for i, (t, a) in enumerate(resources)]})


def _tags_by_kind(resources):
    return {r.kind: (dict(r.tags) if r.tags is not None else None) for r in resources}


def test_taggable_resources_are_read_with_their_tags_and_others_without():
    resources, _ = state_resources(_state("azurerm",
        ("azurerm_virtual_network", {"name": "vnet", "address_space": ["10.0.0.0/16"], "tags": {"Owner": "p"}}),
        ("azurerm_subnet", {"name": "snet", "virtual_network_name": "vnet", "address_prefixes": ["10.0.1.0/24"]}),
        ("azurerm_monitor_metric_alert", {"id": "/alerts/a", "name": "a", "tags": {"Realizes": "lag"}})))
    tags = _tags_by_kind(resources)
    assert tags["network"] == {"Owner": "p"} and tags["alarm"] == {"Realizes": "lag"}
    assert tags["subnet"] is None            # subnets take no tags: not judged


def test_a_dns_record_carries_its_tags():
    d, alpha, _ = model(alpha=(entry(ALPHA, "svc-ldaps", "ciamServiceName", ciamBindingRole="ds-ldaps-service",
                                     ciamFqdn="ldap.example.test", ciamDnsZone="example.test",
                                     ciamFrontendIp="10.0.1.10", ciamPort="636", ciamTargetRole="ds"),))
    out = "\n".join(service_record(d, alpha, of_class(alpha, "ciamServiceName")[0], "svc_ldaps"))
    assert 'resource "azurerm_private_dns_a_record"' in out and '"ldap.example.test"' in out and "tags" in out

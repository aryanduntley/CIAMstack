"""The resource providers an environment's roots need registered: each managed azurerm resource's namespace by its
type, each azapi resource's by its type; every azurerm type the adapter names has one; the note for an environment
without a landing zone."""
import pathlib
import re

from opsdir_adapter_azure.resource_providers import namespace_of, registration_notes, resource_providers
from opsdir_format_terraform.hcl import as_text
from opsdir_format_terraform.hcl_reader import read_hcl
from network_fixtures import model

SOURCE = pathlib.Path(__file__).parents[1] / "src" / "opsdir_adapter_azure"
MAIN = '''resource "azurerm_linux_virtual_machine" "ds_1" {
}

data "azurerm_key_vault" "kv" {
}

resource "azurerm_private_dns_a_record" "ldap" {
}

resource "azapi_resource" "rule" {
  type      = "Microsoft.Security/alertsSuppressionRules@2019-01-01-preview"
}
'''


def _items(*texts):
    """The Terraform items of rendered texts, as the renderers build them."""
    return tuple(x for t in texts for x in read_hcl(t))


def test_namespaces_of_managed_resources_and_azapi_types():
    assert resource_providers(_items(MAIN, 'resource "azurerm_user_assigned_identity" "x" {\n}\n')) == (
        ("Microsoft.Compute", "Microsoft.ManagedIdentity", "Microsoft.Network", "Microsoft.Security"), ())
    assert namespace_of("azurerm_subscription_policy_exemption") == "Microsoft.Authorization"
    assert namespace_of("azurerm_subscription") == "Microsoft.Resources"
    assert namespace_of("azurerm_virtual_network_peering") == "Microsoft.Network"
    assert namespace_of("azurerm_virtual_machine_extension") == "Microsoft.Compute"


def test_every_azurerm_type_the_adapter_names_has_a_namespace():
    types = {t for f in SOURCE.glob("*.py") for t in re.findall(r"\bazurerm_[a-z0-9_]+[a-z0-9]\b", f.read_text())}
    assert len(types) > 100 and sorted(t for t in types if namespace_of(t) is None) == []


def test_an_unknown_type_and_the_note_without_a_landing_zone():
    namespaces, unknown = resource_providers(_items('resource "azurerm_spring_cloud_app" "x" {\n}\n', MAIN))
    assert unknown == ("azurerm_spring_cloud_app",) and "Microsoft.Compute" in namespaces
    m = model()[1]
    notes = registration_notes(m, namespaces, unknown)
    assert [n.severity for n in notes] == ["action", "action"]
    assert notes[0].text.startswith("to register in the subscription before applying") and notes[0].scope == m.label
    assert notes[1].subject == "resource type `azurerm_spring_cloud_app`"
    assert registration_notes(m, (), ()) == ()
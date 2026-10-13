"""Where an Azure organization's settings are made (5.7b): the management group the record names (ciamManagementRef,
a name or its resource ID), as the management_group_id input a root assigns organization-wide policy on."""
from types import SimpleNamespace

from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.account import management_group, management_group_variable


def _m(ref=None):
    attrs = {"ciamManagementRef": [ref]} if ref else {}
    return SimpleNamespace(cloud=SimpleNamespace(dn="cloud=x", attrs=attrs))


def test_a_management_group_is_named_by_its_resource_id_and_defaults_its_input():
    mg = "/providers/Microsoft.Management/managementGroups/corp-security"
    assert management_group(_m("corp-security")) == mg == management_group(_m(mg))
    assert management_group(_m()) is None
    text = as_text(management_group_variable(_m("corp-security")))
    assert text.startswith('variable "management_group_id"') and f'default     = "{mg}"' in text
    assert "default" not in as_text(management_group_variable(_m()))

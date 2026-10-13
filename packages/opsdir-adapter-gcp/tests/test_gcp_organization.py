"""Where a Google Cloud organization's settings are made (5.7b): the organization the cloud's ciamOrganizationRef
names, as the organization_id input (shared by organization sinks and organization-wide services); a folder isn't
one."""
from types import SimpleNamespace

from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_gcp.account import organization_id, organization_variable


def _m(ref=None):
    attrs = {"ciamOrganizationRef": [ref]} if ref else {}
    return SimpleNamespace(cloud=SimpleNamespace(dn="cloud=x", attrs=attrs))


def test_the_organization_input_defaults_to_the_recorded_organization_not_a_folder():
    assert organization_id(_m("organizations/123456789012")) == "123456789012" == organization_id(_m("123456789012"))
    assert organization_id(_m("folders/42")) is None and organization_id(_m()) is None
    text = as_text(organization_variable(_m("organizations/123456789012"), "The organization"))
    assert 'description = "The organization"' in text and 'default     = "123456789012"' in text
    assert "default" not in as_text(organization_variable(_m("folders/42"), "The organization"))

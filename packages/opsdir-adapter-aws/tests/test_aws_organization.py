"""The accounts an AWS organization's settings are made from (5.7b): the management account and the security services'
delegated administrator, each an aliased provider pinned to its account, which a root keeps only when it uses it."""
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_aws.account import MANAGEMENT, SECURITY_ADMIN, organization_providers
from opsdir_adapter_aws.terraform import render_files
from network_fixtures import model

CLOUD = "cloud=alpha,ou=environments,dc=ciam-ops"


def _alpha(**attrs):
    change = LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                              ("replace", "ciamRegion", ("us-gov-west-1",)),
                                              ("replace", "ciamCloudProvider", ("aws",)),
                                              ("replace", "ciamAccountRef", ("111122223333",)),
                                              *(("replace", k, (v,)) for k, v in attrs.items())))
    d, alpha, _ = model(changes=(change,))
    return alpha


def test_each_organization_account_the_record_names_is_an_aliased_provider_pinned_to_it():
    m = _alpha(ciamManagementRef="999988887777", ciamSecurityAdminRef="555566667777")
    management, admin = (as_text(p) for p in organization_providers(m))
    assert f'alias               = "{MANAGEMENT}"' in management and '["999988887777"]' in management
    assert f'alias               = "{SECURITY_ADMIN}"' in admin and '["555566667777"]' in admin
    assert 'region              = "us-gov-west-1"' in management
    assert organization_providers(_alpha()) == ()


def test_a_root_that_uses_neither_leaves_them_out():
    files = as_text(render_files(_alpha(ciamManagementRef="999988887777", ciamSecurityAdminRef="555566667777"), None))
    assert not any(MANAGEMENT in text or SECURITY_ADMIN in text for text in files.values())

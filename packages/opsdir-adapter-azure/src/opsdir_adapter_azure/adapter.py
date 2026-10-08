"""Azure adapter: applies to environments in clouds whose ciamCloudProvider is azure."""
from opsdir.core.contract import Adapter
from opsdir.domains.infrastructure.firewall import priority_check
from .access import ACCESS
from .boundary import check_boundary
from .arm import ARM
from .cli import CLI_INVENTORY
from .inventory import TERRAFORM_STATE
from .quotas import PREREQUISITE as QUOTA_PREREQUISITE, QUOTAS
from .regions import PREREQUISITE, REGIONS
from .secrets import SECRET_PATTERNS, keyvault_command
from .terraform import PRIORITIES, render

PROVIDER = "azure"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="azure", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(priority_check(*PRIORITIES), check_boundary),
                  ref_schemes=("azkv", "azkv-key", "azkv-cert", "azblob"),
                  secret_schemes={"azkv": keyvault_command}, renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamCloudEnvironment": ("public", "usgovernment")}, schema=None,
                  formats=(("terraform/*.tf", "hcl"),),
                  products=(),
                  secret_patterns=SECRET_PATTERNS, importers=(TERRAFORM_STATE, CLI_INVENTORY, ARM, REGIONS, QUOTAS),
                  profile_terms=None, access=ACCESS, prerequisites=(PREREQUISITE, QUOTA_PREREQUISITE))

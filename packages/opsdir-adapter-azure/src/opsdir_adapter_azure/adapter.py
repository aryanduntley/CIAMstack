"""Azure adapter: applies to environments in clouds whose ciamCloudProvider is azure."""
from opsdir.core.contract import Adapter
from .arm import ARM
from .cli import CLI_INVENTORY
from .inventory import TERRAFORM_STATE
from .secrets import SECRET_PATTERNS, keyvault_command
from .terraform import render

PROVIDER = "azure"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="azure", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(), ref_schemes=("azkv", "azkv-key", "azkv-cert", "azblob"),
                  secret_schemes={"azkv": keyvault_command}, renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamCloudEnvironment": ("public", "usgovernment")}, schema=None,
                  formats=(("terraform/*.tf", "hcl"),),
                  products=(),
                  secret_patterns=SECRET_PATTERNS, importers=(TERRAFORM_STATE, CLI_INVENTORY, ARM))

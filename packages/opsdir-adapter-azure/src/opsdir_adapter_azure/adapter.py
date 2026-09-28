"""Azure adapter: applies to environments in clouds whose ciamCloudProvider is azure."""
from opsdir.core.contract import Adapter
from .secrets import keyvault_command
from .terraform import render

PROVIDER = "azure"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="azure", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(), ref_schemes=("azkv", "azkv-key", "azblob"),
                  secret_schemes={"azkv": keyvault_command}, renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamCloudEnvironment": ("public", "usgovernment")}, schema=None,
                  formats=(("terraform/*.tf", "hcl"),),
                  products=())

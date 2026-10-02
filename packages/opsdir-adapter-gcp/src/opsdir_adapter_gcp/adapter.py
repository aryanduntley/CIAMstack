"""Google Cloud adapter: applies to environments in clouds whose ciamCloudProvider is gcp."""
from opsdir.core.contract import Adapter
from .cli import CLI_INVENTORY
from .inventory import TERRAFORM_STATE
from .secrets import SECRET_PATTERNS, secret_manager_command
from .terraform import render

PROVIDER = "gcp"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="gcp", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(),
                  ref_schemes=("gcp-sm", "gcp-kms", "gcp-cert", "gs"),
                  secret_schemes={"gcp-sm": secret_manager_command}, renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamCloudEnvironment": ("public",)}, schema=None,
                  formats=(("terraform/*.tf", "hcl"),),
                  products=(),
                  secret_patterns=SECRET_PATTERNS, importers=(TERRAFORM_STATE, CLI_INVENTORY), profile_terms=None)

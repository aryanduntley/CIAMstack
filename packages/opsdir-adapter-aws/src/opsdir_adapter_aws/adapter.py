"""AWS adapter: applies to environments in clouds whose ciamCloudProvider is aws."""
from opsdir.core.contract import Adapter
from .cli import CLI_INVENTORY
from .cloudformation import CLOUDFORMATION
from .inventory import TERRAFORM_STATE
from .secrets import SECRET_PATTERNS, secretsmanager_command
from .terraform import render

PROVIDER = "aws"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="aws", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(), ref_schemes=("aws-sm", "aws-kms", "aws-acm", "s3"),
                  secret_schemes={"aws-sm": secretsmanager_command}, renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamCloudEnvironment": ("public",)}, schema=None,
                  formats=(("terraform/*.tf", "hcl"),),
                  products=(),
                  secret_patterns=SECRET_PATTERNS, importers=(TERRAFORM_STATE, CLI_INVENTORY, CLOUDFORMATION),
                  profile_terms=None)

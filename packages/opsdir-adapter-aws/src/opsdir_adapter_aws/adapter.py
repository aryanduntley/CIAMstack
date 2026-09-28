"""AWS adapter: applies to environments in clouds whose ciamCloudProvider is aws."""
from opsdir.core.contract import Adapter
from .secrets import secretsmanager_command
from .terraform import render

PROVIDER = "aws"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="aws", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(), ref_schemes=("aws-sm", "aws-kms", "s3"),
                  secret_schemes={"aws-sm": secretsmanager_command}, renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamCloudEnvironment": ("public",)}, schema=None,
                  formats=(("terraform/*.tf", "hcl"),),
                  products=())

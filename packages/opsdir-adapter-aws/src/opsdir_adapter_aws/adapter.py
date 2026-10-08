"""AWS adapter: applies to environments in clouds whose ciamCloudProvider is aws."""
from opsdir.core.contract import Adapter
from .boundary import check_boundary
from .discovery import check_discovery_availability
from .access import ACCESS
from .cli import CLI_INVENTORY
from .collect import COLLECTORS
from .cloudformation import CLOUDFORMATION
from .inventory import TERRAFORM_STATE
from .quotas import PREREQUISITE as QUOTA_PREREQUISITE, QUOTAS
from .regions import PREREQUISITE, REGIONS
from .secrets import SECRET_PATTERNS, secretsmanager_command
from .terraform import render

PROVIDER = "aws"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="aws", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_boundary, check_discovery_availability), ref_schemes=("aws-sm", "aws-kms", "aws-acm", "s3"),
                  secret_schemes={"aws-sm": secretsmanager_command}, renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamCloudEnvironment": ("public",)}, schema=None,
                  formats=(("terraform/*.tf", "hcl"), ("access/*.sh", "shell")),
                  products=(),
                  secret_patterns=SECRET_PATTERNS,
                  importers=(TERRAFORM_STATE, CLI_INVENTORY, CLOUDFORMATION, REGIONS, QUOTAS),
                  profile_terms=None, access=ACCESS, prerequisites=(PREREQUISITE, QUOTA_PREREQUISITE),
                  collectors=COLLECTORS)

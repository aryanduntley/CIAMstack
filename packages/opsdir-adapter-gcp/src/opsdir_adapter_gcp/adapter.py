"""Google Cloud adapter: applies to environments in clouds whose ciamCloudProvider is gcp."""
from opsdir.core.contract import Adapter
from opsdir.domains.infrastructure.checks import check_server_inputs
from opsdir.domains.infrastructure.firewall import priority_check
from .access import ACCESS
from .boundary import check_boundary
from .cli import CLI_INVENTORY
from .collect import COLLECTORS
from .inventory import TERRAFORM_STATE
from .ingress import gateway_plug
from .kubernetes import SECRET_DELIVERY, workload_identity
from .secrets import SECRET_PATTERNS, secret_manager_command
from .names import PRIORITIES
from .quotas import PREREQUISITE as QUOTA_PREREQUISITE, QUOTAS
from .regions import PREREQUISITE, REGIONS
from .terraform import render

PROVIDER = "gcp"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="gcp", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render,
                  checks=(priority_check(*PRIORITIES), check_boundary, check_server_inputs),
                  ref_schemes=("gcp-sm", "gcp-kms", "gcp-cert", "gs"),
                  secret_schemes={"gcp-sm": secret_manager_command}, renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamOnProvider": (PROVIDER,),
                              "ciamCloudEnvironment": ("public",)}, schema=None,
                  formats=(("terraform/*.tf", "hcl"), ("access/*.sh", "shell")),
                  products=(),
                  secret_patterns=SECRET_PATTERNS, importers=(TERRAFORM_STATE, CLI_INVENTORY, REGIONS, QUOTAS),
                  profile_terms=None, access=ACCESS, prerequisites=(PREREQUISITE, QUOTA_PREREQUISITE),
                  collectors=COLLECTORS,
                  workload_identity=workload_identity, secret_delivery=SECRET_DELIVERY,
                  gateway_plug=gateway_plug)

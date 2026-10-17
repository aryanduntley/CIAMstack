"""Google Cloud adapter: applies to environments in clouds whose ciamCloudProvider is gcp."""
from opsdir.core.contract import Adapter, ReadBack
from opsdir.domains.infrastructure.checks import check_server_inputs
from opsdir.domains.infrastructure.firewall import priority_check
from .access import ACCESS
from .boundary import check_boundary, check_regulated_placement
from .cli import CLI_INVENTORY
from .collect import COLLECTORS
from .discovery import check_discovery_cadence
from .frameworks import FRAMEWORKS, PREREQUISITE as FRAMEWORK_PREREQUISITE
from .inventory import TERRAFORM_STATE
from .ingress import gateway_plug
from .kubernetes import SECRET_DELIVERY, workload_identity
from .ops_agent import host_files
from .secrets import SECRET_PATTERNS, secret_manager_command
from .managed_ad import MANAGED as MANAGED_DIRECTORY, SERVICE as MANAGED_AD
from .names import PRIORITIES
from .quotas import PREREQUISITE as QUOTA_PREREQUISITE, QUOTAS
from .regions import PREREQUISITE, REGIONS
from .terraform import render, render_notes
from .rendered_state import rendered_states

PROVIDER = "gcp"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="gcp", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render,
                  checks=(priority_check(*PRIORITIES), check_boundary, check_regulated_placement, check_server_inputs,
                          check_discovery_cadence),
                  ref_schemes=("gcp-sm", "gcp-kms", "gcp-cert", "gs"),
                  secret_schemes={"gcp-sm": secret_manager_command}, renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamOnProvider": (PROVIDER,),
                              "ciamCloudEnvironment": ("public",), "ciamManagedService": (MANAGED_AD,)},
                  schema=None,
                  formats=(("terraform/*.tf", "hcl"), ("terraform/discovery/*.yaml", "yaml"),
                           ("terraform/*checks/*/index.js", "javascript"),
                           ("terraform/*checks/*/package.json", "json"), ("access/*.sh", "shell")),
                  products=(),
                  secret_patterns=SECRET_PATTERNS,
                  importers=(TERRAFORM_STATE, CLI_INVENTORY, REGIONS, QUOTAS, FRAMEWORKS),
                  profile_terms=None, access=ACCESS,
                  prerequisites=(PREREQUISITE, QUOTA_PREREQUISITE, FRAMEWORK_PREREQUISITE),
                  collectors=COLLECTORS,
                  workload_identity=workload_identity, secret_delivery=SECRET_DELIVERY,
                  gateway_plug=gateway_plug, host_files=host_files,
                  reads_back=(ReadBack("terraform-state", "terraform/*.tf", "terraform/", "{environment}/", False,
                                       rendered_states, intent=True),),
                  notes=render_notes, renders_synthetic_checks=True, managed_directory=MANAGED_DIRECTORY)

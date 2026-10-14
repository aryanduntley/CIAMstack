"""Azure adapter: applies to environments in clouds whose ciamCloudProvider is azure."""
from opsdir.core.contract import Adapter, ReadBack
from opsdir.domains.infrastructure.checks import check_server_inputs
from opsdir.domains.infrastructure.firewall import priority_check
from .access import ACCESS
from .boundary import check_boundary, check_regulated_placement
from .arm import ARM
from .cli import CLI_INVENTORY
from .collect import COLLECTORS
from .identity_protection import check_identity_protection
from .purview import check_discovery_cadence
from .inventory import TERRAFORM_STATE
from .ingress import gateway_plug
from .kubernetes import SECRET_DELIVERY, workload_identity
from .quotas import PREREQUISITE as QUOTA_PREREQUISITE, QUOTAS
from .regions import PREREQUISITE, REGIONS
from .secrets import SECRET_PATTERNS, keyvault_command, keyvault_lookup
from .terraform import PRIORITIES, TARGETS, render
from .rendered_state import rendered_deployments, rendered_states

PROVIDER = "azure"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="azure", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render,
                  checks=(priority_check(*PRIORITIES), check_boundary, check_regulated_placement, check_server_inputs,
                          check_identity_protection,
                          check_discovery_cadence),
                  ref_schemes=("azkv", "azkv-key", "azkv-cert", "azblob"),
                  secret_schemes={"azkv": keyvault_command}, renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamOnProvider": (PROVIDER,),
                              "ciamCloudEnvironment": ("public", "usgovernment")}, schema=None,
                  formats=(("terraform/*.tf", "hcl"), ("bicep/*.bicep", "bicep"), ("bicep/*.tf", "hcl"),
                           ("bicep/*placements.json", "json"), ("arm/*placements.json", "json"),
                           ("arm/*.json", "arm-json"), ("arm/*.tf", "hcl"), ("kubernetes/azure-monitor/*", "yaml")),
                  products=(),
                  secret_patterns=SECRET_PATTERNS, importers=(TERRAFORM_STATE, CLI_INVENTORY, ARM, REGIONS, QUOTAS),
                  profile_terms=None, access=ACCESS, prerequisites=(PREREQUISITE, QUOTA_PREREQUISITE),
                  collectors=COLLECTORS, render_targets=TARGETS,
                  workload_identity=workload_identity, secret_delivery=SECRET_DELIVERY,
                  gateway_plug=gateway_plug, ansible_lookup={"azkv": keyvault_lookup},
                  reads_back=(ReadBack("terraform-state", "terraform/*.tf", "terraform/", "{environment}/", False,
                                       rendered_states, intent=True),
                              ReadBack("arm", "arm/*", "arm/", "{environment}/", True, rendered_deployments,
                                       intent=True)))

"""Azure adapter: applies to environments in clouds whose ciamCloudProvider is azure."""
from opsdir.core.contract import Adapter, ReadBack
from opsdir.domains.infrastructure.checks import check_server_inputs
from opsdir.domains.infrastructure.firewall import priority_check
from .access import ACCESS
from .boundary import check_boundary, check_regulated_placement
from .arm import ARM
from .check_jobs import DELIVERY, IMAGE
from .dbauth import SCHEME as DB_TOKEN, entra_token_command
from .cli import CLI_INVENTORY
from .collect import COLLECTORS
from .external_id import GEOGRAPHIES, MANAGED, SERVICE as EXTERNAL_ID
from .domain_services import EDITIONS, MANAGED as MANAGED_DIRECTORY, SERVICE as DOMAIN_SERVICES
from .external_id_graph import GRAPH_COLLECTOR, GRAPH_IMPORTER
from .identity_protection import check_identity_protection
from .purview import check_discovery_cadence
from .inventory import TERRAFORM_STATE
from .keyvault_certificates import KEYVAULT_CERTIFICATES
from .keyvault_collect import KEYVAULT_COLLECTOR
from .ingress import gateway_plug
from .kubernetes import SECRET_DELIVERY, workload_identity
from .quotas import PREREQUISITE as QUOTA_PREREQUISITE, QUOTAS
from .regions import PREREQUISITE, REGIONS
from .secrets import SECRET_PATTERNS, keyvault_command, keyvault_lookup
from .schema import FRAGMENT
from .sentinel import SEARCH_LANGUAGE, check_nrt_quota, keeps as sentinel_keeps
from .terraform import PRIORITIES, TARGETS, cert_forwarding, render, render_notes
from .rendered_state import rendered_deployments, rendered_states

PROVIDER = "azure"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="azure", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render,
                  checks=(priority_check(*PRIORITIES), check_boundary, check_regulated_placement, check_server_inputs,
                          check_identity_protection,
                          check_discovery_cadence, check_nrt_quota),
                  ref_schemes=("azkv", "azkv-key", "azkv-cert", "azblob"),
                  secret_schemes={"azkv": keyvault_command}, db_tokens={DB_TOKEN: entra_token_command},
                  renders="Terraform for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamOnProvider": (PROVIDER,),
                              "ciamCloudEnvironment": ("public", "usgovernment"),
                              "ciamManagedService": (EXTERNAL_ID, DOMAIN_SERVICES),
                              "ciamDataGeography": tuple(GEOGRAPHIES), "ciamDirectoryEdition": EDITIONS,
                              "ciamSearchLanguage": (SEARCH_LANGUAGE,)},
                  schema=FRAGMENT,
                  formats=(("terraform/*.tf", "hcl"), ("terraform/checks/check.py", "python"),
                           ("bicep/*/checks/check.py", "python"), ("arm/*/checks/check.py", "python"),
                           ("images/*/Dockerfile", "dockerfile"), ("images/*/check.py", "python"),
                           ("bicep/*.bicep", "bicep"), ("bicep/*.tf", "hcl"),
                           ("bicep/*placements.json", "json"), ("arm/*placements.json", "json"),
                           ("arm/*.json", "arm-json"), ("arm/*.tf", "hcl"), ("kubernetes/azure-monitor/*", "yaml")),
                  products=(),
                  secret_patterns=SECRET_PATTERNS,
                  importers=(TERRAFORM_STATE, CLI_INVENTORY, ARM, REGIONS, QUOTAS, GRAPH_IMPORTER,
                             KEYVAULT_CERTIFICATES),
                  profile_terms=None, access=ACCESS, prerequisites=(PREREQUISITE, QUOTA_PREREQUISITE),
                  collectors=(*COLLECTORS, GRAPH_COLLECTOR, KEYVAULT_COLLECTOR), render_targets=TARGETS,
                  settings=(IMAGE, DELIVERY),
                  workload_identity=workload_identity, secret_delivery=SECRET_DELIVERY,
                  gateway_plug=gateway_plug, ansible_lookup={"azkv": keyvault_lookup},
                  reads_back=(ReadBack("terraform-state", "terraform/*.tf", "terraform/", "{environment}/", False,
                                       rendered_states, intent=True),
                              ReadBack("arm", "arm/*", "arm/", "{environment}/", True, rendered_deployments,
                                       intent=True)),
                  notes=render_notes, renders_synthetic_checks=True, siem_indexes=sentinel_keeps,
                  managed_identity=MANAGED, managed_directory=MANAGED_DIRECTORY,
                  cert_forwarding=cert_forwarding)

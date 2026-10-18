"""AWS adapter: applies to environments in clouds whose ciamCloudProvider is aws."""
from opsdir.core.contract import Adapter, ReadBack
from opsdir.domains.infrastructure.checks import check_server_inputs
from .boundary import check_boundary, check_regulated_placement
from .discovery import check_discovery_availability
from .access import ACCESS
from .cli import CLI_INVENTORY
from .collect import COLLECTORS
from .cloudformation import CLOUDFORMATION
from .inventory import TERRAFORM_STATE
from .private_ca import PRIVATE_CA_IMPORTER
from .ingress import gateway_plug
from .mtls import cert_forwarding
from .kubernetes import SECRET_DELIVERY, workload_identity
from .log_agent import host_files
from .quotas import PREREQUISITE as QUOTA_PREREQUISITE, QUOTAS
from .regions import PREREQUISITE, REGIONS
from .secrets import SECRET_PATTERNS, secretsmanager_command, secretsmanager_lookup
from .terraform import TARGETS, render, render_notes
from .canaries import RUNTIME
from .cognito import MANAGED, SERVICE as COGNITO
from .dbauth import SCHEME as DB_TOKEN, rds_token_command
from .directory import EDITIONS, MANAGED as MANAGED_DIRECTORY, SERVICE as MANAGED_AD
from .rendered_state import rendered_stacks, rendered_states

PROVIDER = "aws"


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="aws", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render,
                  checks=(check_boundary, check_regulated_placement, check_discovery_availability,
                          check_server_inputs),
                  ref_schemes=("aws-sm", "aws-kms", "aws-acm", "s3"),
                  secret_schemes={"aws-sm": secretsmanager_command}, db_tokens={DB_TOKEN: rds_token_command},
                  renders="Terraform (or AWS CloudFormation) for the target cloud",
                  neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamOnProvider": (PROVIDER,),
                              "ciamCloudEnvironment": ("public",), "ciamManagedService": (COGNITO, MANAGED_AD),
                              "ciamDirectoryEdition": EDITIONS}, schema=None,
                  formats=(("terraform/*.tf", "hcl"), ("terraform/canaries/*/python/*.py", "python"),
                           ("terraform/discovery/*/*.py", "python"),
                           ("cloudformation/*.yaml", "cloudformation-yaml"),
                           ("cloudformation/*.resources-to-import.json", "json"),
                           ("cloudformation/*placements.json", "json"), ("cloudformation/*.tf", "hcl"),
                           ("cloudformation/canaries/*/python/*.py", "python"),
                           ("cloudformation/discovery/*/*.py", "python"),
                           ("access/*.sh", "shell"), ("kubernetes/fluent-bit/*", "yaml")),
                  products=(),
                  secret_patterns=SECRET_PATTERNS,
                  importers=(TERRAFORM_STATE, CLI_INVENTORY, CLOUDFORMATION, REGIONS, QUOTAS, PRIVATE_CA_IMPORTER),
                  profile_terms=None, access=ACCESS, prerequisites=(PREREQUISITE, QUOTA_PREREQUISITE),
                  collectors=COLLECTORS, render_targets=TARGETS,
                  workload_identity=workload_identity, secret_delivery=SECRET_DELIVERY,
                  gateway_plug=gateway_plug, ansible_lookup={"aws-sm": secretsmanager_lookup},
                  settings=(RUNTIME,), host_files=host_files,
                  reads_back=(ReadBack("terraform-state", "terraform/*.tf", "terraform/", "{environment}/", False,
                                       rendered_states, intent=True),
                              ReadBack("cloudformation", "cloudformation/*", "cloudformation/", "{environment}/", True,
                                       rendered_stacks, intent=True)),
                  notes=render_notes, renders_synthetic_checks=True, managed_identity=MANAGED,
                  managed_directory=MANAGED_DIRECTORY, cert_forwarding=cert_forwarding)

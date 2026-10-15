"""Azure DevOps YAML pipelines read as pipeline jobs: schedules, triggers (CI unless none, PR, pipeline completion),
pools at every level, deployment jobs' environments, secrets by name (variable groups, Key Vault task filters);
templates counted, not read as pipelines; each named by its file; a re-import changes nothing; a pipeline a re-read
repository no longer defines (gone, or a template now) removed, not one that isn't YAML this time, nor another
repository's."""
import json

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.automation.naming import job_dn
from opsdir_adapter_azure_devops.adapter import ADAPTER
import mini_estate
from support import REGISTRY, build_directory

PIPELINE = """trigger: none
pr: none
schedules:
  - cron: "0 3 * * 1-5"
    displayName: weekdays
    branches: {include: [main]}
resources:
  pipelines:
    - pipeline: build
      source: ciam-build
      trigger: true
variables:
  - group: ciam-prod-secrets
  - name: region
    value: westeurope
pool: {vmImage: ubuntu-22.04}
stages:
  - stage: deploy
    pool: ciam-agents
    jobs:
      - deployment: apply
        environment: {name: prod}
        strategy:
          runOnce:
            deploy:
              steps:
                - task: AzureKeyVault@2
                  inputs: {KeyVaultName: kv-ciam-prod, SecretsFilter: "ds-root-password, pf-admin-password"}
                - script: ./deploy.sh
"""
CI = """trigger: [main]
pr: [main]
steps:
  - script: make test
"""
TEMPLATE = """parameters:
  - name: env
steps:
  - script: echo ${{ parameters.env }}
"""
FILES = {"ciam/infra/azure-pipelines.yml": CI, "ciam/infra/pipelines/deploy.yml": PIPELINE,
         "ciam/infra/templates/steps.yml": TEMPLATE,
         "ciam/infra/repository.json": json.dumps({"webUrl": "https://dev.azure.com/example/ciam/_git/infra"}),
         "ciam/docs/README.md": "# docs\n"}


def imported(files=None):
    base = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)))
    changes, notices = preview_import(base, "azure-devops/pipelines", files or FILES, (ADAPTER,))
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)), changes), changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def test_a_scheduled_deployment_pipeline(after):
    d, _ = after
    job = get(d, job_dn("azure-devops-infra-deploy"))
    assert (values(job, "ciamSchedule"), values(job, "ciamTrigger"), one(job, "ciamRuntime"),
            values(job, "ciamDeploysTo"), values(job, "ciamSecretName"), one(job, "ciamRepoUrl"),
            one(job, "ciamRepoPath"), one(job, "ciamJobName"), one(job, "ciamCiSystem")) == \
        (("0 3 * * 1-5",), ("event",), "ubuntu-22.04, pool ciam-agents", ("prod",),
         ("keyvault kv-ciam-prod/ds-root-password", "keyvault kv-ciam-prod/pf-admin-password",
          "variable group ciam-prod-secrets"),
         "https://dev.azure.com/example/ciam/_git/infra", "pipelines/deploy.yml", "deploy.yml", "azure-devops")


def test_a_ci_pipeline_with_only_steps(after):
    d, _ = after
    job = get(d, job_dn("azure-devops-infra-azure-pipelines"))
    assert (values(job, "ciamTrigger"), values(job, "ciamSchedule"), one(job, "ciamRuntime")) == \
        (("push", "pull-request"), (), None)


def test_templates_and_repositories_without_pipelines_are_named(after):
    _, notices = after
    assert {"1 YAML file(s) without pipeline-level keys (templates) not read as pipelines",
            "ciam/docs: no YAML pipeline in it; not read"} <= set(notices)


def test_a_reimport_changes_nothing():
    d, _, _ = imported()
    assert preview_import(d, "azure-devops/pipelines", FILES, (ADAPTER,))[0] == ()


def test_a_pipeline_a_reread_repository_no_longer_defines_is_removed():
    other = {"ciam/web/azure-pipelines.yml": CI, "ciam/infra/pipelines/nightly.yml": CI}
    d, _, _ = imported({**FILES, **other})
    reread = {"ciam/infra/repository.json": FILES["ciam/infra/repository.json"],     # azure-pipelines.yml gone
              "ciam/infra/pipelines/nightly.yml": TEMPLATE,                         # a template now
              "ciam/infra/pipelines/deploy.yml": "trigger: [\n"}                   # not YAML this time: kept
    changes, notices = preview_import(d, "azure-devops/pipelines", reread, (ADAPTER,))
    assert sorted((r.changetype, r.dn) for r in changes) == [                      # ciam/web not read: kept
        ("delete", job_dn("azure-devops-infra-azure-pipelines")), ("delete", job_dn("azure-devops-infra-nightly"))]
    assert "pipeline azure-devops-infra-azure-pipelines (azure-devops, https://dev.azure.com/example/ciam/_git/infra" \
        ", azure-pipelines.yml): no longer defined in its repository; removed" in notices

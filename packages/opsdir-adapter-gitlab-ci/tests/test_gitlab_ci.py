"""GitLab CI/CD read as pipeline jobs: active schedules with their timezone (inactive ones counted), triggers from
workflow rules (push by default), runner tags and images, environments, secrets by name from jobs' secrets: and
masked variables (no value ever kept); one job per project, named as the project, matched on a re-import; a project
re-read without its definition loses its pipeline (not one whose definition can't be read this time, nor a project
not read); what isn't a definition named."""
import json

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.automation.naming import job_dn
from opsdir_adapter_gitlab_ci.adapter import ADAPTER
import mini_estate
from support import REGISTRY, build_directory

CI = """stages: [plan, apply]
image: hashicorp/terraform:1.9
default:
  tags: [ciam, docker]
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_PIPELINE_SOURCE == "push"
      when: never
.template:
  script: [echo hidden]
plan:
  stage: plan
  script: [terraform plan]
apply:
  stage: apply
  image: {name: "registry.example.test/ciam/deployer:2"}
  environment: {name: prod, url: "https://sso.example.test"}
  secrets:
    DS_BIND_PASSWORD:
      vault: ciam/ds/bind@secret
  script: [terraform apply]
"""
SCHEDULES = [{"description": "nightly", "ref": "main", "cron": "0 2 * * *", "cron_timezone": "Europe/Berlin",
              "active": True},
             {"description": "old", "ref": "main", "cron": "0 3 * * 0", "active": False}]
VARIABLES = [{"key": "TF_TOKEN", "masked": True, "value": "not-a-real-token-value"},
             {"key": "REGION", "masked": False, "value": "eu-central-1"}]
FILES = {"ciam/infra/.gitlab-ci.yml": CI, "ciam/infra/pipeline_schedules.json": json.dumps(SCHEDULES),
         "ciam/infra/variables.json": json.dumps(VARIABLES),
         "ciam/infra/project.json": json.dumps({"web_url": "https://gitlab.example.test/ciam/infra"}),
         "ciam/docs/.gitlab-ci.yml": "- not\n- a\n- definition\n",
         "ciam/web/pipeline_schedules.json": "[]"}
INFRA_DN = job_dn("gitlab-ci-infra-gitlab-ci")


def imported(files=None):
    base = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)))
    changes, notices = preview_import(base, "gitlab-ci/pipelines", files or FILES, (ADAPTER,))
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)), changes), changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def test_a_project_pipeline(after):
    d, _ = after
    job = get(d, INFRA_DN)
    assert (one(job, "ciamJobKind"), values(job, "ciamSchedule"), values(job, "ciamTrigger"), one(job, "ciamRuntime"),
            values(job, "ciamDeploysTo"), values(job, "ciamSecretName"), one(job, "ciamRepoUrl"),
            one(job, "ciamRepoPath"), one(job, "ciamJobName"), one(job, "ciamCiSystem")) == \
        ("pipeline", ("0 2 * * * (Europe/Berlin)",), ("manual", "pull-request"),
         "ciam, docker, hashicorp/terraform:1.9, registry.example.test/ciam/deployer:2", ("prod",),
         ("DS_BIND_PASSWORD", "TF_TOKEN"), "https://gitlab.example.test/ciam/infra", ".gitlab-ci.yml", "infra",
         "gitlab-ci")


def test_no_variable_value_is_kept(after):
    d, _ = after
    assert "not-a-real-token-value" not in repr([dict(e.attrs) for e in d.entries.values()])


def test_notices(after):
    _, notices = after
    assert {"ciam/infra/pipeline_schedules.json: 1 inactive schedule(s) not read",
            "ciam/docs/.gitlab-ci.yml: not a GitLab CI definition; not read",
            "ciam/web: no .gitlab-ci.yml; not read"} <= set(notices)


def test_a_reimport_changes_nothing():
    d, _, _ = imported()
    assert preview_import(d, "gitlab-ci/pipelines", FILES, (ADAPTER,))[0] == ()


def test_without_a_url_the_path_names_the_project():
    files = {"a/x/.gitlab-ci.yml": "build: {script: [make]}\n", "b/x/.gitlab-ci.yml": "build: {script: [make]}\n"}
    d, _, _ = imported(files)
    paths = sorted(one(j, "ciamRepoPath") for j in d.entries.values() if "ciamJob" in j.classes)
    assert paths == ["a/x/.gitlab-ci.yml", "b/x/.gitlab-ci.yml"]
    assert preview_import(d, "gitlab-ci/pipelines", files, (ADAPTER,))[0] == ()


def test_a_project_reread_without_its_definition_loses_its_pipeline():
    files = {"a/x/.gitlab-ci.yml": "build: {script: [make]}\n", "a/y/.gitlab-ci.yml": "build: {script: [make]}\n",
             "b/z/.gitlab-ci.yml": "build: {script: [make]}\n"}
    d, _, _ = imported(files)
    changes, notices = preview_import(d, "gitlab-ci/pipelines", {        # x without its definition, y unreadable
        "a/x/pipeline_schedules.json": "[]", "a/y/.gitlab-ci.yml": "- a list\n"}, (ADAPTER,))
    assert [(r.changetype, r.dn) for r in changes] == [("delete", job_dn("gitlab-ci-x-gitlab-ci"))]   # z not read
    assert "pipeline gitlab-ci-x-gitlab-ci (gitlab-ci, no repository URL, a/x/.gitlab-ci.yml): no longer defined " \
        "in its repository; removed" in notices

"""GitHub Actions workflows read as pipeline jobs: schedules, triggers, runners, environments and the secrets they name
(never a value; GITHUB_TOKEN skipped); one job per workflow, matched by repository and path on a re-import (which
changes nothing and keeps an owner); files that aren't workflows and repositories without workflows named."""
import pytest

from opsdir.connectors.importing import preview_import
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.automation.naming import job_dn
from opsdir_adapter_github_actions.adapter import ADAPTER
import mini_estate
from support import REGISTRY, build_directory

NIGHTLY = """name: Nightly directory export
on:
  schedule:
    - cron: "30 2 * * *"
  workflow_dispatch:
jobs:
  export:
    runs-on: [self-hosted, linux, ciam]
    environment: prod
    steps:
      - run: ./scripts/export.sh --bind-password "${{ secrets.DS_BIND_PASSWORD }}"
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
          S3: ${{ vars.EXPORT_BUCKET }}
"""
DEPLOY = """on: [push, pull_request]
jobs:
  plan:
    runs-on: ubuntu-24.04
    steps: [{run: "terraform plan"}]
  apply:
    runs-on: {group: deployers}
    environment: {name: stage, url: "https://stage.example.test"}
    steps: [{run: "terraform apply -var token=${{ secrets.TF_TOKEN }}"}]
"""
FILES = {"example-aero/ciam-ops/.github/workflows/nightly.yml": NIGHTLY,
         "example-aero/ciam-ops/.github/workflows/deploy.yaml": DEPLOY,
         "example-aero/ciam-ops/.github/workflows/notes.yml": "just: [a, list]\n",
         "example-aero/docs/README.md": "# docs\n"}
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n\n"
          "dn: cn=ops,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n")
NIGHTLY_DN = job_dn("github-actions-ciam-ops-nightly")
OWNER = tuple(parse(f"dn: {NIGHTLY_DN}\nchangetype: modify\nadd: ciamOwner\nciamOwner: cn=ops,ou=owners,dc=ciam-ops\n-\n"))


def records():
    return tuple(parse(mini_estate.LDIF + "\n" + OWNERS))


def imported(changes=(), files=None):
    base = build_directory(REGISTRY, records())
    import_changes, notices = preview_import(base, "github-actions/workflows", files or FILES, (ADAPTER,))
    return build_directory(REGISTRY, records(), (*import_changes, *changes)), import_changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def test_a_scheduled_workflow(after):
    d, _ = after
    job = get(d, NIGHTLY_DN)
    assert (one(job, "ciamJobKind"), values(job, "ciamSchedule"), values(job, "ciamTrigger"), one(job, "ciamRuntime"),
            values(job, "ciamDeploysTo"), values(job, "ciamSecretName"), one(job, "ciamRepoUrl"),
            one(job, "ciamRepoPath")) == \
        ("pipeline", ("30 2 * * *",), ("manual",), "self-hosted, linux, ciam", ("prod",), ("DS_BIND_PASSWORD",),
         "https://github.com/example-aero/ciam-ops", ".github/workflows/nightly.yml")


def test_a_workflow_on_push_with_several_jobs(after):
    d, _ = after
    job = get(d, job_dn("github-actions-ciam-ops-deploy"))
    assert (values(job, "ciamSchedule"), values(job, "ciamTrigger"), one(job, "ciamRuntime"),
            values(job, "ciamDeploysTo"), values(job, "ciamSecretName")) == \
        ((), ("push", "pull-request"), "ubuntu-24.04, group deployers", ("stage",), ("TF_TOKEN",))


def test_what_isnt_a_workflow_is_named(after):
    _, notices = after
    assert {"example-aero/ciam-ops/.github/workflows/notes.yml: not a GitHub Actions workflow; not read",
            "example-aero/docs: no .github/workflows/ in it; not read"} <= set(notices)


def test_a_reimport_changes_nothing_and_keeps_the_owner():
    d, _, _ = imported(OWNER)
    assert preview_import(d, "github-actions/workflows", FILES, (ADAPTER,))[0] == ()
    assert one(get(d, NIGHTLY_DN), "ciamOwner") == "cn=ops,ou=owners,dc=ciam-ops"

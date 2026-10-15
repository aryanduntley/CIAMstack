# opsdir-adapter-azure-devops

opsdir delivery adapter for Azure DevOps Pipelines: the platform's pipelines as Azure Pipelines defines them, read from repositories' YAML pipelines as jobs of the core `automation` domain (`ciamJob`, kind `pipeline`). (Azure the cloud is `opsdir-adapter-azure`; this is the CI/CD service.)

**Applies to** any estate whose pipelines run on Azure DevOps (YAML pipelines). Declaration-only (adapter kind `delivery`, no render): an environment may name it in its stack as the CI system that delivers it, and its importer works either way.

**Depends on** `opsdir` (the automation domain's shared pipeline placement, `opsdir.domains.automation.pipelines`) and `pyyaml`.

## What it renders

Nothing: pipelines live in their repositories. The record holds what they run, when, where and with which secrets, so the planner and the `jobs` report see them.

## What it reads back

The importer `azure-devops/pipelines` takes one folder per repository, `project/repo` (two levels deep; a single folder when the export has only one level), holding its YAML pipelines anywhere below it and, optionally, `repository.json` (the repository as `az repos show` or `GET _apis/git/repositories/{repo}` gives it):

```bash
git clone --depth 1 https://dev.azure.com/example/ciam/_git/infra repos/ciam/infra     # one folder per repository, project/repo
az repos show --repository infra --project ciam -o json > repos/ciam/infra/repository.json   # optional: its URL
opsdir import --dry-run azure-devops/pipelines repos/
opsdir import --change CHG-… azure-devops/pipelines repos/
```

A `.yml`/`.yaml` file is a pipeline when it is a mapping named `azure-pipelines.yml` (`.yaml`) or declaring pipeline-level keys (`trigger`, `pr`, `schedules`, `pool`, `resources`, `extends`), and has `steps`, `jobs`, `stages` or `extends`; other YAML mappings are counted as templates.

| In a pipeline | Recorded on the job |
|---|---|
| `schedules[].cron` | `ciamSchedule` (UTC, as written) |
| `trigger` (absent counts: CI on every branch; not when `none`), `pr` (only when present and not `none`), `resources.pipelines[].trigger` | `ciamTrigger`: `push`, `pull-request`, `event` (another pipeline completing) |
| `pool` at the top, in stages and jobs (`vmImage`; a pool name, as a string or `{name}`) | `ciamRuntime`, in one value (`ubuntu-22.04, pool ciam-agents`) |
| Deployment jobs' (`deployment:`) `environment` (a name or `{name}`) | `ciamDeploysTo` |
| `variables: - group: NAME` (pipeline, stages, jobs); `AzureKeyVault@N` tasks' `KeyVaultName` and `SecretsFilter` (in a job's steps or a deployment strategy's hooks; no filter is `*`) | `ciamSecretName`: `variable group NAME`, `keyvault VAULT/NAME` (names only) |
| The file name | `ciamJobName` |
| The CI system | `ciamCiSystem`: `azure-devops` |
| `repository.json` (`webUrl`, else `remoteUrl`) | `ciamRepoUrl`, `ciamRepoPath` the file's path in the repository; without it, the path is qualified by the repository (`project/repo/<path>`) so two repositories stay apart |

The jobs a pipeline has are its top-level `jobs`, its stages' jobs, or, for a pipeline with only `steps`, the pipeline itself.

One job per pipeline file (`ciamJobKind: pipeline`, under `ou=jobs`), named `azure-devops-<repo>-<file name without extension>` (made unique with `-2`, `-3`, …), matched on a re-import by repository URL and path. What the record adds (owner, criticality, the binding role that realizes it, the roles it uses) is kept; importing the same repositories again changes nothing.

**Removed upstream.** An Azure DevOps pipeline the record has from a repository folder this import read (same repository URL, or the same folder when there is none) that the folder no longer defines (the file is gone, or is a template now) is removed: its deletion is in the import's change records, named in a notice (`pipeline <name> (azure-devops, <URL>, <path>): no longer defined in its repository; removed`), and like every deletion an import makes it is the operator's conflict to take or keep. A file that doesn't parse this time keeps its pipeline; repositories the import didn't read, other CI systems' pipelines and jobs that aren't pipelines are never touched.

Named in the notices, not read: YAML files that don't parse, repository folders without a pipeline, the number of templates, and an import with no repository folders.

**Secrets.** Only names: secret variables can't be written in YAML, and variable groups and Key Vault secrets are named, never read.

## References, vocabulary and schema

None of its own: jobs are the core `automation` domain's (`ciamJob` under `ou=jobs`, placed by `opsdir.domains.automation.pipelines`, shared with `opsdir-adapter-github-actions` and `opsdir-adapter-gitlab-ci`). No required roles or planner checks.

## Known limits

- `template:` references (stages, jobs, steps, variables) and `extends:` templates are not followed: what only a template declares (pools, groups, Key Vault tasks) isn't recorded.
- Classic (designer) build and release pipelines are not read; neither are pipeline settings kept outside YAML (UI triggers, scheduled triggers set in the UI, pipeline variables).
- `trigger` defaults are taken from the YAML (CI on every branch when absent); branch and path filters are not recorded. An absent `pr` is read as no PR trigger: on Azure Repos, PR validation is a branch policy, outside YAML.
- A repository deleted (or left out of the import) keeps its pipelines in the record: an import can't tell a partial export from a deletion, so only the repositories it reads lose pipelines. A pipeline imported before opsdir recorded `ciamCiSystem` (an older record) isn't removed this way until a re-import has found it again and recorded its system.

## Tests

`tests/test_azure_devops.py`: a scheduled deployment pipeline (no CI or PR trigger, a pipeline-completion trigger, pools at two levels, an environment, variable group and Key Vault secrets by name, the repository's URL), a steps-only CI pipeline, templates and repositories without pipelines named, a re-import changing nothing, the file name and CI system recorded, a pipeline gone or turned template in a re-read repository removed (not one that doesn't parse, nor another repository's).

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-azure-devops/tests`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `azure-devops`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

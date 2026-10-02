# opsdir-adapter-azure-devops

opsdir delivery adapter for Azure DevOps Pipelines: the platform's pipelines as Azure Pipelines defines them, read from repositories' YAML pipelines as jobs of the core `automation` domain (kind `pipeline`). (Azure the cloud is `opsdir-adapter-azure`; this is the CI/CD service.)

**Applies to** environments that declare it in their stack (`kind: delivery`); declaration-only, its importer works either way.

**Depends on** `opsdir` (the automation domain's shared pipeline placement) and `pyyaml`.

## What it renders

Nothing: pipelines live in their repositories.

## Reading the pipelines

```bash
git clone --depth 1 https://dev.azure.com/example/ciam/_git/infra repos/ciam/infra     # one folder per repository, project/repo
az repos show --repository infra --project ciam -o json > repos/ciam/infra/repository.json   # optional: its URL
opsdir import --dry-run azure-devops/pipelines repos/
```

A YAML file is a pipeline when it is named `azure-pipelines.yml` (`.yaml`) or declares pipeline-level keys (`trigger`, `pr`, `schedules`, `pool`, `resources`, `extends`) and has `steps`, `jobs`, `stages` or `extends`; other YAML files are counted as templates.

| In a pipeline | Recorded on the job |
|---|---|
| `schedules[].cron` | `ciamSchedule` (UTC, as written) |
| `trigger` (unless `none`), `pr` (unless absent or `none`), `resources.pipelines[].trigger` | `ciamTrigger`: `push`, `pull-request`, `event` (another pipeline completing) |
| `pool` at the top, in stages and jobs (`vmImage`, a pool name) | `ciamRuntime` (`ubuntu-22.04, pool ciam-agents`) |
| Deployment jobs' `environment` (a name or `{name}`) | `ciamDeploysTo` |
| `variables: - group: NAME` (pipeline, stages, jobs); `AzureKeyVault@N` tasks' `KeyVaultName` and `SecretsFilter` | `ciamSecretName`: `variable group NAME`, `keyvault VAULT/NAME` (names only) |
| `repository.json` (`webUrl` or `remoteUrl`) | `ciamRepoUrl`; without it, `ciamRepoPath` is qualified by the repository |

One job per pipeline file, named `azure-devops-REPO-FILE` (made unique), matched on a re-import by repository and path; what the record adds is kept. Named in the notices: files that aren't YAML, repository folders without a pipeline, the number of templates.

**Secrets.** Only names: secret variables can't be written in YAML, and variable groups and Key Vault secrets are named, never read.

## References, vocabulary and schema

None of its own: jobs are the core `automation` domain's (`opsdir.domains.automation.pipelines`). Adapter kind `delivery`.

## Known limits

- `template:` references (stages, jobs, steps, variables) and `extends:` templates are not followed: what only a template declares (pools, groups, Key Vault tasks) isn't recorded.
- Classic (designer) build and release pipelines are not read; neither are pipeline settings kept outside YAML (UI triggers, scheduled triggers set in the UI, pipeline variables).
- `trigger` defaults are taken from the YAML (CI on every branch when absent); branch filters are not recorded.

## Tests

`tests/test_azure_devops.py`: a scheduled deployment pipeline (no CI or PR trigger, a pipeline-completion trigger, pools at two levels, an environment, variable group and Key Vault secrets by name, the repository's URL), a steps-only CI pipeline, templates and repositories without pipelines named, a re-import changing nothing.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `azure-devops`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

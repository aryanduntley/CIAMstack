# opsdir-adapter-github-actions

opsdir delivery adapter for GitHub Actions: the platform's pipelines as GitHub Actions defines them, read from repositories' workflows as jobs of the core `automation` domain (kind `pipeline`).

**Applies to** environments that declare it in their stack (`kind: delivery`); declaration-only, its importer works either way.

**Depends on** `opsdir` (the automation domain's shared pipeline placement) and `pyyaml`.

## What it renders

Nothing: workflows live in their repositories. The record holds what they run, when, where and with which secrets, so the planner and the `jobs` report see them.

## Reading the workflows

```bash
# one folder per repository, owner/repo, with its .github/workflows/ (a checkout works)
git clone --depth 1 https://github.com/example-aero/ciam-ops repos/example-aero/ciam-ops
opsdir import --dry-run github-actions/workflows repos/
opsdir import --change CHG-… github-actions/workflows repos/
```

| In a workflow | Recorded on the job |
|---|---|
| `on.schedule[].cron` | `ciamSchedule` (UTC cron, as GitHub writes it) |
| `on.workflow_dispatch`, `push`, `pull_request`(`_target`), `release`, `workflow_call`, `repository_dispatch` / `workflow_run`, any other event | `ciamTrigger`: `manual`, `push`, `pull-request`, `release`, `called`, `event`, the event's name |
| `jobs.*.runs-on` (labels, a list, `{group, labels}`) | `ciamRuntime`: the runners it asks for (`self-hosted, linux, ciam`; `group deployers`) |
| `jobs.*.environment` (a name or `{name, url}`) | `ciamDeploysTo` |
| `${{ secrets.NAME }}` anywhere in the file | `ciamSecretName` (the name only; `GITHUB_TOKEN`, GitHub's own, skipped; `vars.*` aren't secrets) |
| The repository and file | `ciamRepoUrl` (`https://github.com/owner/repo` for an owner/repo folder), `ciamRepoPath` (`.github/workflows/<file>`) |

One job per workflow, named `github-actions-REPO-FILE` (made unique), matched on a re-import by repository and path; what the record adds (owner, criticality, the roles it uses, its realization) is kept. Named in the notices: files under `.github/workflows/` that aren't workflows (no `jobs`), repository folders without workflows.

**Secrets.** Only the names a workflow references are recorded; GitHub never exports secret values and nothing here asks for them.

## References, vocabulary and schema

None of its own: jobs are the core `automation` domain's (`ciamJob` under `ou=jobs`, built by `opsdir.domains.automation.pipelines`, shared with the other CI packages). Adapter kind `delivery`.

## Known limits

- Reusable workflows called by a workflow (`uses: owner/repo/.github/workflows/x.yml@ref`) and composite actions are not followed; their secrets passed with `secrets: inherit` are not listed.
- Organization- and environment-level secrets and variables are not read (names only appear where a workflow references them).
- `on.schedule` crons are in UTC; the record keeps them as written.

## Tests

`tests/test_github_actions.py`: a scheduled, manually dispatchable workflow (self-hosted runners, an environment, a secret by name, GitHub's token skipped), a push/PR workflow with several jobs (runner group, environment object), what isn't a workflow named, a re-import changing nothing and keeping an owner.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `github-actions`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

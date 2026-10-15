# opsdir-adapter-github-actions

opsdir delivery adapter for GitHub Actions: the platform's pipelines as GitHub Actions defines them, read from repositories' workflows as jobs of the core `automation` domain (`ciamJob`, kind `pipeline`).

**Applies to** any estate whose pipelines run on GitHub Actions. Declaration-only (adapter kind `delivery`, no render): an environment may name it in its stack as the CI system that delivers it, and its importer works either way.

**Depends on** `opsdir` (the automation domain's shared pipeline placement, `opsdir.domains.automation.pipelines`) and `pyyaml`.

## What it renders

Nothing: workflows live in their repositories. The record holds what they run, when, where and with which secrets, so the planner and the `jobs` report see them.

## What it reads back

The importer `github-actions/workflows` takes one folder per repository, `owner/repo` (or just `repo`), holding the repository's `.github/workflows/*.yml` / `*.yaml` (a checkout works):

```bash
git clone --depth 1 https://github.com/example-aero/ciam-ops repos/example-aero/ciam-ops
opsdir import --dry-run github-actions/workflows repos/
opsdir import --change CHG-… github-actions/workflows repos/
```

| In a workflow | Recorded on the job |
|---|---|
| `on.schedule[].cron` | `ciamSchedule` (UTC cron, as GitHub writes it) |
| `on.workflow_dispatch`, `push`, `pull_request` / `pull_request_target`, `release`, `workflow_call`, `repository_dispatch` / `workflow_run`, any other event | `ciamTrigger`: `manual`, `push`, `pull-request`, `release`, `called`, `event`, the event's own name. `on` may be a string, a list or a mapping |
| `jobs.*.runs-on` (a label, a list, `{group, labels}`) | `ciamRuntime`: the runners every job asks for, in one value (`self-hosted, linux, ciam`; `group deployers`) |
| `jobs.*.environment` (a name or `{name, url}`) | `ciamDeploysTo` |
| `${{ secrets.NAME }}` anywhere in the file | `ciamSecretName` (the name only; `GITHUB_TOKEN`, GitHub's own, skipped; `vars.*` aren't secrets) |
| `name:` (else the file name) | `ciamJobName` |
| The CI system | `ciamCiSystem`: `github-actions` |
| The repository and file | `ciamRepoUrl` (`https://github.com/owner/repo` for an `owner/repo` folder; none for a bare `repo` folder), `ciamRepoPath` (`.github/workflows/<file>`, qualified as `<repo>/.github/workflows/<file>` when the URL isn't known) |

One job per workflow file (`ciamJobKind: pipeline`, under `ou=jobs`), named `github-actions-<repo>-<file name without extension>` (characters other than letters, digits, `.`, `_`, `-` as `-`; made unique with `-2`, `-3`, …), matched on a re-import by repository URL and path. What the record adds (owner, criticality, the binding role that realizes it, the roles it uses) is kept; importing the same workflows again changes nothing.

**Removed upstream.** A GitHub Actions pipeline the record has from a repository folder this import read (same repository URL, or the same folder when there is none) that the folder no longer defines is removed: its deletion is in the import's change records, named in a notice (`pipeline <name> (github-actions, <URL>, <path>): no longer defined in its repository; removed`), and like every deletion an import makes it is the operator's conflict to take or keep. A file that isn't a workflow this time keeps its pipeline; repositories the import didn't read, other CI systems' pipelines and jobs that aren't pipelines are never touched.

Named in the notices, not read: files under `.github/workflows/` that aren't workflows (not YAML, or no `jobs` mapping), folders without `.github/workflows/`, and an empty import. Files under `.github/workflows/` that aren't `.yml`/`.yaml` are passed over.

**Secrets.** Only the names a workflow references are recorded; GitHub never exports secret values and nothing here asks for them.

## References, vocabulary and schema

None of its own: jobs are the core `automation` domain's (`ciamJob` under `ou=jobs`, placed by `opsdir.domains.automation.pipelines`, shared with `opsdir-adapter-gitlab-ci` and `opsdir-adapter-azure-devops`). No required roles or planner checks.

## Known limits

- Reusable workflows called by a workflow (`uses: owner/repo/.github/workflows/x.yml@ref`) and composite actions are not followed; their secrets passed with `secrets: inherit` are not listed.
- Organization- and environment-level secrets and variables are not read (names only appear where a workflow references them).
- `on.schedule` crons are in UTC; the record keeps them as written.
- The runners of all a workflow's jobs are one `ciamRuntime` value; per-job runners and matrices aren't told apart.
- The entry is named after the file; the workflow's `name:` is `ciamJobName`.
- A repository deleted (or left out of the import) keeps its pipelines in the record: an import can't tell a partial export from a deletion, so only the repositories it reads lose pipelines. A pipeline imported before opsdir recorded `ciamCiSystem` (an older record) isn't removed this way until a re-import has found it again and recorded its system.

## Tests

`tests/test_github_actions.py`: a scheduled, manually dispatchable workflow (self-hosted runners, an environment, a secret by name, GitHub's token skipped), a push/PR workflow with several jobs (runner group, environment object), what isn't a workflow named, a re-import changing nothing and keeping an owner, the workflow's name and CI system recorded, a workflow gone from a re-read repository removed (not a broken one, nor another repository's).

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-github-actions/tests`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `github-actions`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

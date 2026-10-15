# opsdir-adapter-gitlab-ci

opsdir delivery adapter for GitLab CI/CD: the platform's pipelines as GitLab defines them, read from projects' `.gitlab-ci.yml` and schedules as jobs of the core `automation` domain (`ciamJob`, kind `pipeline`).

**Applies to** any estate whose pipelines run on GitLab CI/CD. Declaration-only (adapter kind `delivery`, no render): an environment may name it in its stack as the CI system that delivers it, and its importer works either way.

**Depends on** `opsdir` (the automation domain's shared pipeline placement, `opsdir.domains.automation.pipelines`) and `pyyaml`.

## What it renders

Nothing: pipelines live in their projects. The record holds what they run, when, where and with which secrets, so the planner and the `jobs` report see them.

## What it reads back

The importer `gitlab-ci/pipelines` takes one folder per project (`group/.../project`), holding `.gitlab-ci.yml` and, optionally, three files saved from GitLab's API:

```bash
p=projects/ciam/infra; mkdir -p $p                       # one folder per project, group/.../project
git -C $p init -q && git -C $p pull -q --depth 1 https://gitlab.example.test/ciam/infra   # or copy .gitlab-ci.yml
api=https://gitlab.example.test/api/v4/projects/ciam%2Finfra; auth="PRIVATE-TOKEN: $GITLAB_TOKEN"
curl -s -H "$auth" $api                                  > $p/project.json              # optional: its web_url
curl -s -H "$auth" $api/pipeline_schedules              > $p/pipeline_schedules.json   # optional: schedules
curl -s -H "$auth" $api/variables | jq '[.[] | {key, masked, hidden}]' > $p/variables.json   # optional: names only
opsdir import --dry-run gitlab-ci/pipelines projects/
opsdir import --change CHG-… gitlab-ci/pipelines projects/
```

| Source | Recorded on the job |
|---|---|
| `pipeline_schedules.json` (`GET /projects/:id/pipeline_schedules`) | `ciamSchedule`: each active schedule's cron, with its timezone when given (`0 2 * * * (Europe/Berlin)`); inactive ones counted in a notice |
| `workflow:rules` (`$CI_PIPELINE_SOURCE == "…"` in a rule's `if`, rules not `when: never`) | `ciamTrigger`: `push`, `manual` (`web`, `chat`), `pull-request` (`merge_request_event`, `external_pull_request_event`), `api`, `event` (`trigger`), `called` (`pipeline`, `parent_pipeline`), any other source by its name; `schedule` is the schedules above. Without workflow rules: `push` |
| Runner `tags` (`default:`, jobs) and `image` (top level, `default:`, jobs; a string or `{name}`) | `ciamRuntime`: tags then images, in one value |
| Jobs' `environment` (a name or `{name, url}`) | `ciamDeploysTo` |
| The keys of jobs' `secrets:` and the masked or hidden keys of `variables.json` (`GET /projects/:id/variables`) | `ciamSecretName` (names only) |
| `project.json` (`GET /projects/:id`) | `ciamRepoUrl` (its `web_url`), `ciamRepoPath` `.gitlab-ci.yml`; without it, the path is qualified by the project (`group/project/.gitlab-ci.yml`) so two projects stay apart |

A job is any top-level mapping that isn't a reserved key (`stages`, `variables`, `image`, `services`, `before_script`, `after_script`, `cache`, `include`, `workflow`, `default`) or hidden (`.name`) and has `script`, `trigger` or `extends`.

One job per project (`ciamJobKind: pipeline`, under `ou=jobs`), named `gitlab-ci-<project>-gitlab-ci` (the project's last path segment; made unique with `-2`, `-3`, …), matched on a re-import by repository URL and path. What the record adds (owner, criticality, the binding role that realizes it, the roles it uses) is kept; importing the same projects again changes nothing.

Named in the notices, not read: a project folder (one holding any of the four files) without `.gitlab-ci.yml`, a `.gitlab-ci.yml` that isn't a YAML mapping, inactive schedules, and an import with no project folders.

**Secrets.** Only names are recorded. `variables.json` is best exported with keys only (the `jq` above); should it hold values, they are dropped as the file is parsed and never reach the record.

## References, vocabulary and schema

None of its own: jobs are the core `automation` domain's (`ciamJob` under `ou=jobs`, placed by `opsdir.domains.automation.pipelines`, shared with `opsdir-adapter-github-actions` and `opsdir-adapter-azure-devops`). No required roles or planner checks.

## Known limits

- `include:` (local, project, remote, template) and `extends:` are not followed; jobs defined only in included files don't contribute runners, environments or secrets.
- Group- and instance-level CI/CD variables are not read; `rules:` on jobs (as opposed to `workflow:`) don't change the triggers. Workflow rules that never test `$CI_PIPELINE_SOURCE` give no trigger.
- Child pipelines (`trigger: include:`) are part of their parent's job.
- A project removed from the import isn't removed from the record by a re-import: each import touches only the jobs it finds.

## Tests

`tests/test_gitlab_ci.py`: a project pipeline (schedules with timezone, workflow-rule triggers with `push` ruled out, tags and images, an environment, secrets from `secrets:` and masked variables, the project's URL), no variable value kept, notices (inactive schedule, not a definition, no definition), a re-import changing nothing, two projects' same-named files kept apart without URLs.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-gitlab-ci/tests`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `gitlab-ci`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

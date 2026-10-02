# opsdir-adapter-gitlab-ci

opsdir delivery adapter for GitLab CI/CD: the platform's pipelines as GitLab defines them, read from projects' `.gitlab-ci.yml` and schedules as jobs of the core `automation` domain (kind `pipeline`).

**Applies to** environments that declare it in their stack (`kind: delivery`); declaration-only, its importer works either way.

**Depends on** `opsdir` (the automation domain's shared pipeline placement) and `pyyaml`.

## What it renders

Nothing: pipelines live in their projects.

## Reading the projects

```bash
p=projects/ciam/infra; mkdir -p $p                       # one folder per project, group/.../project
git -C $p init -q && git -C $p pull -q --depth 1 https://gitlab.example.test/ciam/infra   # or copy .gitlab-ci.yml
api=https://gitlab.example.test/api/v4/projects/ciam%2Finfra; auth="PRIVATE-TOKEN: $GITLAB_TOKEN"
curl -s -H "$auth" $api                                  > $p/project.json              # optional: its web_url
curl -s -H "$auth" $api/pipeline_schedules              > $p/pipeline_schedules.json   # optional: schedules
curl -s -H "$auth" $api/variables | jq '[.[] | {key, masked, hidden}]' > $p/variables.json   # optional: names only
opsdir import --dry-run gitlab-ci/pipelines projects/
```

| Source | Recorded on the job |
|---|---|
| `pipeline_schedules.json` (`GET /projects/:id/pipeline_schedules`) | `ciamSchedule`: each active schedule's cron, with its timezone (`0 2 * * * (Europe/Berlin)`); inactive ones counted |
| `workflow:rules` (`$CI_PIPELINE_SOURCE == "…"`, rules not `when: never`) | `ciamTrigger`: `push`, `manual` (web, chat), `pull-request` (merge requests), `api`, `event` (trigger), `called` (pipeline, parent pipeline); a schedule source is the schedules above. Without workflow rules: `push` |
| Runner `tags` (`default:`, jobs) and `image` (top level, `default:`, jobs) | `ciamRuntime` |
| Jobs' `environment` (a name or `{name, url}`) | `ciamDeploysTo` |
| Jobs' `secrets:` and the masked or hidden keys of `variables.json` (`GET /projects/:id/variables`) | `ciamSecretName` (names only) |
| `project.json` (`GET /projects/:id`) | `ciamRepoUrl` (its `web_url`); without it, `ciamRepoPath` is qualified by the project (`group/project/.gitlab-ci.yml`) |

One job per project, named `gitlab-ci-PROJECT-gitlab-ci` (made unique), matched on a re-import by repository and path; what the record adds is kept. Named in the notices: a project folder without `.gitlab-ci.yml`, a `.gitlab-ci.yml` that isn't a mapping, inactive schedules.

**Secrets.** Only names are recorded. `variables.json` is best exported with keys only (the `jq` above); should it hold values, they are dropped as the file is parsed and never reach the record.

## References, vocabulary and schema

None of its own: jobs are the core `automation` domain's (`opsdir.domains.automation.pipelines`). Adapter kind `delivery`.

## Known limits

- `include:` (local, project, remote, template) and `extends:` are not followed; jobs defined only in included files don't contribute runners, environments or secrets.
- Group- and instance-level CI/CD variables are not read; `rules:` on jobs (as opposed to `workflow:`) don't change the triggers.
- Child pipelines (`trigger: include:`) are part of their parent's job.

## Tests

`tests/test_gitlab_ci.py`: a project pipeline (schedules with timezone, workflow-rule triggers with `push` ruled out, tags and images, an environment, secrets from `secrets:` and masked variables, the project's URL), no variable value kept, notices (inactive schedule, not a definition, no definition), a re-import changing nothing, two projects' same-named files kept apart without URLs.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `gitlab-ci`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

"""GitHub Actions workflows read as pipeline jobs (opsdir.domains.automation.pipelines). Pure.

The importer `github-actions/workflows` takes one folder per repository, owner/repo (or just repo), holding the
repository's .github/workflows/*.yml (or the whole checkout). For each workflow:

  on.schedule[].cron                    -> schedules (UTC cron, as GitHub writes them)
  on.workflow_dispatch / push /         -> triggers: manual, push, pull-request, release, called (workflow_call),
    pull_request(_target) / release /      event (repository_dispatch, workflow_run), and any other event by name
    workflow_call / repository_dispatch
  jobs.*.runs-on                        -> runners (labels, a runner group)
  jobs.*.environment                    -> environments it deploys to
  ${{ secrets.NAME }}                   -> the secrets it names (never a value; GITHUB_TOKEN, GitHub's own, skipped)

Files that aren't YAML workflows are named; a repository folder without workflows is named.
"""
import re
from types import MappingProxyType

import yaml

from opsdir.core.contract import Imported, Importer
from opsdir.core.sources import parsed
from opsdir.domains.automation.pipelines import FoundPipeline, environment_name, jobs_container, pipeline_groups

SYSTEM = "github-actions"
WORKFLOWS = ".github/workflows/"
TRIGGERS = MappingProxyType({"workflow_dispatch": "manual", "push": "push", "pull_request": "pull-request",
                             "pull_request_target": "pull-request", "release": "release", "workflow_call": "called",
                             "repository_dispatch": "event", "workflow_run": "event"})
_SECRET = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
OWN_SECRETS = ("GITHUB_TOKEN",)


def _on(doc):
    """A workflow's `on:` as {event: settings} (YAML 1.1 reads a bare `on` key as true)."""
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {e: None for e in on if isinstance(e, str)}
    return on if isinstance(on, dict) else {}


def _runners(job):
    runs_on = job.get("runs-on")
    if isinstance(runs_on, str):
        return (runs_on,)
    if isinstance(runs_on, list):
        return tuple(str(r) for r in runs_on)
    if isinstance(runs_on, dict):
        return (*((f"group {runs_on['group']}",) if runs_on.get("group") else ()),
                *(str(x) for x in ([runs_on.get("labels")] if isinstance(runs_on.get("labels"), str)
                                   else runs_on.get("labels") or ())))
    return ()


def workflow(repo, repo_url, path, text):
    """The FoundPipeline of one workflow file, or None when it isn't a workflow."""
    doc = parsed(yaml.safe_load, text, (yaml.YAMLError,), dict)
    if doc is None or not isinstance(doc.get("jobs"), dict):
        return None
    on = _on(doc)
    jobs = [j for j in doc["jobs"].values() if isinstance(j, dict)]
    schedules = tuple(s.get("cron") for s in (on.get("schedule") or ()) if isinstance(s, dict) and s.get("cron"))
    triggers = tuple(dict.fromkeys(TRIGGERS.get(e, e) for e in on if e != "schedule"))
    return FoundPipeline(SYSTEM, repo, repo_url, path, str(doc.get("name") or path.rsplit("/", 1)[-1]), schedules,
                         triggers, tuple(dict.fromkeys(r for j in jobs for r in _runners(j))),
                         tuple(sorted({s for s in _SECRET.findall(text) if s not in OWN_SECRETS})),
                         tuple(dict.fromkeys(e for j in jobs for e in (environment_name(j.get("environment")),) if e)))


def _repos(files):
    """{repository: {path within it: text}} from the folders the workflows are in (owner/repo/.github/workflows/...)."""
    placed = [(p.split(f"/{WORKFLOWS}", 1)[0], WORKFLOWS + p.split(f"/{WORKFLOWS}", 1)[1], t)
              for p, t in files.items() if f"/{WORKFLOWS}" in p]
    return {r: {p: t for rr, p, t in placed if rr == r} for r in dict.fromkeys(r for r, _, _ in placed)}


def read_workflows(files, d, patterns, at=None):
    """Imported: the pipelines GitHub Actions workflows define, as jobs."""
    repos = _repos(files)
    found = [(r, p, workflow(r, f"https://github.com/{r}" if r.count("/") == 1 else None, p, t))
             for r, ws in repos.items() for p, t in sorted(ws.items()) if p.endswith((".yml", ".yaml"))]
    pipelines = [f for _, _, f in found if f]
    others = sorted({"/".join(p.split("/")[:2]) if p.count("/") >= 2 else p.split("/")[0]
                     for p in files if f"/{WORKFLOWS}" not in p and "/" in p})
    return Imported(containers=(jobs_container(),), groups=pipeline_groups(d, pipelines),
                    notices=(*(f"{r}/{p}: not a GitHub Actions workflow; not read" for r, p, f in found if not f),
                             *(f"{o}: no .github/workflows/ in it; not read" for o in others
                               if o not in repos and not any(r.startswith(o + "/") for r in repos)),
                             *(("no repository folders (one folder per repository, owner/repo, holding "
                                ".github/workflows/)",) if not files else ())))


WORKFLOWS_IMPORTER = Importer("workflows", "GitHub Actions workflows (one folder per repository, owner/repo, holding "
                                           ".github/workflows/*.yml)", read_workflows)

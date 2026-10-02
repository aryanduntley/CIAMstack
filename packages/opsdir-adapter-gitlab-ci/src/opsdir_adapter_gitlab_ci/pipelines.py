"""GitLab CI/CD read as pipeline jobs (opsdir.domains.automation.pipelines). Pure.

The importer `gitlab-ci/pipelines` takes one folder per project (group/.../project) holding:

  .gitlab-ci.yml                the pipeline: triggers from workflow:rules ($CI_PIPELINE_SOURCE: push, web -> manual,
                                merge_request_event -> pull-request, api, trigger -> event, pipeline / parent_pipeline
                                -> called, schedule; without workflow rules a pipeline runs on push), runner tags and
                                images (a job's, `default:`'s, the top level's), environments, the secrets jobs name
                                (`secrets:`)
  pipeline_schedules.json       optional, the project's schedules as the API lists them
                                (GET /projects/:id/pipeline_schedules): cron and timezone of the active ones
  project.json                  optional, the project as the API gives it (GET /projects/:id): its web_url
  variables.json                optional, the project's CI/CD variables as the API lists them
                                (GET /projects/:id/variables): the keys of masked or hidden ones are secret names;
                                every value is dropped as the file is parsed, never kept

One job per project pipeline. A project folder without .gitlab-ci.yml, and files that aren't what they should be,
are named. include: and extends: are not followed.
"""
import re
from types import MappingProxyType

import yaml

from opsdir.core.contract import Imported, Importer
from opsdir.core.sources import folders, json_document, parsed
from opsdir.domains.automation.pipelines import FoundPipeline, environment_name, jobs_container, pipeline_groups

SYSTEM = "gitlab-ci"
DEFINITION, SCHEDULES, VARIABLES, PROJECT = (".gitlab-ci.yml", "pipeline_schedules.json", "variables.json",
                                             "project.json")
RESERVED = ("stages", "variables", "image", "services", "before_script", "after_script", "cache", "include",
            "workflow", "default")
SOURCES = MappingProxyType({"push": "push", "web": "manual", "merge_request_event": "pull-request", "api": "api",
                            "trigger": "event", "pipeline": "called", "parent_pipeline": "called",
                            "external_pull_request_event": "pull-request", "chat": "manual", "schedule": None})
_SOURCE = re.compile(r"\$CI_PIPELINE_SOURCE\s*==\s*[\"']([a-z_]+)[\"']")


def _jobs(doc):
    return [j for k, j in doc.items() if k not in RESERVED and not str(k).startswith(".") and isinstance(j, dict)
            and ("script" in j or "trigger" in j or "extends" in j)]


def _image(holder):
    image = holder.get("image") if isinstance(holder, dict) else None
    return image.get("name") if isinstance(image, dict) else image if isinstance(image, str) else None


def _runners(doc, jobs):
    default = doc.get("default") if isinstance(doc.get("default"), dict) else {}
    tags = [str(t) for h in (default, *jobs) for t in (h.get("tags") or ()) if isinstance(h.get("tags"), list)]
    images = [i for h in (doc, default, *jobs) for i in (_image(h),) if i]
    return tuple(dict.fromkeys((*tags, *images)))


def _triggers(doc):
    rules = ((doc.get("workflow") or {}).get("rules") or ()) if isinstance(doc.get("workflow"), dict) else ()
    named = [s for r in rules if isinstance(r, dict) and r.get("when") != "never"
             for s in _SOURCE.findall(str(r.get("if") or ""))]
    return tuple(dict.fromkeys(SOURCES.get(s, s) for s in named if SOURCES.get(s, s))) if rules else ("push",)


def schedules(text):
    """(cron (timezone) of each active schedule, how many are inactive) from the API's pipeline_schedules list."""
    doc = json_document(text)
    listed = [s for s in doc if isinstance(s, dict) and s.get("cron")] if isinstance(doc, list) else []
    return (tuple(f"{s['cron']} ({s['cron_timezone']})" if s.get("cron_timezone") else s["cron"]
                  for s in listed if s.get("active", True)),
            sum(1 for s in listed if not s.get("active", True)))


def secret_variables(text):
    """The keys of masked or hidden CI/CD variables in the API's variables list (values are never kept)."""
    doc = json_document(text)
    keys = [(v.get("key"), v.get("masked") or v.get("hidden")) for v in doc if isinstance(v, dict)] \
        if isinstance(doc, list) else []
    return tuple(k for k, secret in keys if k and secret)


def project_pipeline(project, files):
    """(FoundPipeline or None, notices) of one project folder."""
    doc = parsed(yaml.safe_load, files[DEFINITION], (yaml.YAMLError,)) if DEFINITION in files else None
    if not isinstance(doc, dict):
        return None, ((f"{project}: no {DEFINITION}; not read",) if DEFINITION not in files
                      else (f"{project}/{DEFINITION}: not a GitLab CI definition; not read",))
    jobs = _jobs(doc)
    crons, inactive = schedules(files[SCHEDULES]) if SCHEDULES in files else ((), 0)
    secrets = sorted({*(str(k) for j in jobs if isinstance(j.get("secrets"), dict) for k in j["secrets"]),
                      *(secret_variables(files[VARIABLES]) if VARIABLES in files else ())})
    triggers = _triggers(doc)
    url = (json_document(files[PROJECT], dict) or {}).get("web_url") if PROJECT in files else None
    return FoundPipeline(SYSTEM, project, url if isinstance(url, str) else None, DEFINITION,
                         project.rsplit("/", 1)[-1], crons,
                         tuple(t for t in triggers if t), _runners(doc, jobs), tuple(secrets),
                         tuple(dict.fromkeys(e for j in jobs for e in (environment_name(j.get("environment")),) if e))), \
        ((f"{project}/{SCHEDULES}: {inactive} inactive schedule(s) not read",) if inactive else ())


def _projects(files):
    """{project: {path within it: text}}: the folders holding a definition, schedules or variables."""
    known = (DEFINITION, SCHEDULES, VARIABLES, PROJECT)
    roots = dict.fromkeys(p.rsplit("/", 1)[0] for p in files if "/" in p and p.rsplit("/", 1)[1] in known)
    return folders(files, roots)


def read_pipelines(files, d, patterns, at=None):
    """Imported: the pipelines GitLab CI/CD projects define, as jobs."""
    read = [project_pipeline(p, fs) for p, fs in _projects(files).items()]
    return Imported(containers=(jobs_container(),), groups=pipeline_groups(d, [p for p, _ in read if p]),
                    notices=(*(n for _, ns in read for n in ns),
                             *(("no project folders (one folder per project, group/project, holding .gitlab-ci.yml)",)
                               if not read else ())))


PIPELINES_IMPORTER = Importer("pipelines", "GitLab CI/CD projects (one folder per project, group/project, holding "
                                           ".gitlab-ci.yml, optionally pipeline_schedules.json and variables.json)",
                              read_pipelines)

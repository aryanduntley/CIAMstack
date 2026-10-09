"""Azure DevOps YAML pipelines read as pipeline jobs (opsdir.domains.automation.pipelines). Pure.

The importer `azure-devops/pipelines` takes one folder per repository (project/repo) holding its YAML pipelines and,
optionally, repository.json (GET _apis/git/repositories/{repo}: remoteUrl or webUrl). A YAML file is a pipeline when it
is named azure-pipelines.yml (.yaml) or declares pipeline-level keys (trigger, pr, schedules, pool, resources,
extends); other YAML files are counted as templates. For each pipeline:

  schedules[].cron                       -> schedules (UTC cron, as Azure DevOps writes them)
  trigger (unless none), pr (unless      -> triggers: push, pull-request, event (another pipeline completing)
    none), resources.pipelines[].trigger
  pool (vmImage, a pool name) at the     -> runners
    top, stages and jobs
  deployment jobs' environment           -> environments it deploys to
  variables: - group: NAME, AzureKeyVault -> the secrets it names: variable group NAME, keyvault VAULT/NAME (never a
    tasks' KeyVaultName + SecretsFilter      value)
"""

import yaml

from opsdir.core.contract import Imported, Importer
from opsdir.core.sources import folders, json_document, parsed
from opsdir.domains.automation.pipelines import FoundPipeline, environment_name, jobs_container, pipeline_groups

SYSTEM = "azure-devops"
NAMES = ("azure-pipelines.yml", "azure-pipelines.yaml")
PIPELINE_KEYS = ("trigger", "pr", "schedules", "pool", "resources", "extends")
REPOSITORY = "repository.json"


def _list(v):
    return v if isinstance(v, list) else []


def _jobs(doc):
    """Every job of a pipeline: its top-level jobs, its stages' jobs, or the pipeline itself when it only has steps."""
    stages = [s for s in _list(doc.get("stages")) if isinstance(s, dict)]
    jobs = [j for j in (*_list(doc.get("jobs")), *(j for s in stages for j in _list(s.get("jobs"))))
            if isinstance(j, dict)]
    return stages, jobs or ([doc] if doc.get("steps") else [])


def _pool(p):
    if isinstance(p, str):
        return (f"pool {p}",)
    if isinstance(p, dict):
        return (*((p["vmImage"],) if p.get("vmImage") else ()), *((f"pool {p['name']}",) if p.get("name") else ()))
    return ()


def _groups(holder):
    return tuple(f"variable group {v['group']}" for v in _list(holder.get("variables"))
                 if isinstance(v, dict) and v.get("group"))


def _steps(job):
    strategy = job.get("strategy") if isinstance(job.get("strategy"), dict) else {}
    deploy = [s for phase in strategy.values() if isinstance(phase, dict)
              for hook in phase.values() if isinstance(hook, dict) for s in _list(hook.get("steps"))]
    return [s for s in (*_list(job.get("steps")), *deploy) if isinstance(s, dict)]


def _vault_secrets(step):
    if not str(step.get("task") or "").startswith("AzureKeyVault@"):
        return ()
    inputs = step.get("inputs") or {}
    vault = inputs.get("KeyVaultName") or "?"
    names = [n.strip() for n in str(inputs.get("SecretsFilter") or "*").split(",") if n.strip()]
    return tuple(f"keyvault {vault}/{n}" for n in names)


def _environment(job):
    return environment_name(job.get("environment")) if "deployment" in job else None


def is_pipeline(path, doc):
    return isinstance(doc, dict) and (path.rsplit("/", 1)[-1] in NAMES or any(k in doc for k in PIPELINE_KEYS)) \
        and any(k in doc for k in ("steps", "jobs", "stages", "extends"))


def pipeline(repo, repo_url, path, doc):
    """The FoundPipeline of one YAML pipeline."""
    stages, jobs = _jobs(doc)
    on_pipelines = any(isinstance(p, dict) and p.get("trigger") not in (None, "none", False)
                       for p in _list((doc.get("resources") or {}).get("pipelines")))
    triggers = (*(("push",) if doc.get("trigger") not in ("none", False) else ()),
                *(("pull-request",) if doc.get("pr") not in (None, "none", False) else ()),
                *(("event",) if on_pipelines else ()))
    secrets = {*_groups(doc), *(g for h in (*stages, *jobs) for g in _groups(h)),
               *(s for j in jobs for step in _steps(j) for s in _vault_secrets(step))}
    return FoundPipeline(SYSTEM, repo, repo_url, path, path.rsplit("/", 1)[-1],
                         tuple(s.get("cron") for s in _list(doc.get("schedules"))
                               if isinstance(s, dict) and s.get("cron")),
                         triggers, tuple(dict.fromkeys(r for h in (doc, *stages, *jobs) for r in _pool(h.get("pool")))),
                         tuple(sorted(secrets)),
                         tuple(dict.fromkeys(e for j in jobs for e in (_environment(j),) if e)))


def _repos(files):
    """{repository: {path within it: text}}: a repository is the folder (project/repo) its YAML or repository.json is
    in, two levels deep (a single folder when the export has only one level)."""
    def repo(p):
        parts = p.split("/")
        return "/".join(parts[:2]) if len(parts) > 2 else parts[0]
    return folders(files, dict.fromkeys(repo(p) for p in files if "/" in p))


def _url(text):
    meta = json_document(text, dict)
    return (meta.get("webUrl") or meta.get("remoteUrl")) if meta is not None else None


def repository_pipelines(repo, texts):
    """(pipelines, templates counted, notices) of one repository folder."""
    url = _url(texts[REPOSITORY]) if REPOSITORY in texts else None
    docs = [(p, parsed(yaml.safe_load, t, (yaml.YAMLError,))) for p, t in sorted(texts.items())
            if p.endswith((".yml", ".yaml"))]
    found = tuple(pipeline(repo, url, p, doc) for p, doc in docs if is_pipeline(p, doc))
    return (found, sum(1 for p, doc in docs if isinstance(doc, dict) and not is_pipeline(p, doc)),
            (*(f"{repo}/{p}: not YAML; not read" for p, doc in docs if doc is None),
             *((f"{repo}: no YAML pipeline in it; not read",) if not found else ())))


def read_pipelines(files, d, patterns, at=None):
    """Imported: the pipelines Azure DevOps repositories define, as jobs."""
    read = [repository_pipelines(r, texts) for r, texts in _repos(files).items()]
    templates = sum(t for _, t, _ in read)
    return Imported(containers=(jobs_container(),),
                    groups=pipeline_groups(d, [p for found, _, _ in read for p in found]),
                    notices=(*(n for _, _, ns in read for n in ns),
                             *((f"{templates} YAML file(s) without pipeline-level keys (templates) not read as "
                                "pipelines",) if templates else ()),
                             *(("no repository folders (one folder per repository, project/repo, holding its YAML "
                                "pipelines)",) if not files else ())))


PIPELINES_IMPORTER = Importer("pipelines", "Azure DevOps YAML pipelines (one folder per repository, project/repo, "
                                           "optionally with repository.json)", read_pipelines)

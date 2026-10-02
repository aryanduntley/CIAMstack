"""Pipelines read from a CI system's definitions, placed as jobs: shared by every CI system's package. Pure.

A CI package parses its own files into FoundPipelines; pipeline_groups places them as ciamJob entries of kind pipeline
under ou=jobs, so every CI system's pipelines are the same kind of record:

  matched by       a pipeline the record has with the same repository and definition path
  named            SYSTEM-REPO-NAME (the definition's file name), made unique
  recorded         schedules (as the system writes them), other triggers, the runners it asks for (ciamRuntime), the
                   secrets it names (ciamSecretName: names only, the package never reads a value), the environments it
                   deploys to (ciamDeploysTo), the repository (ciamRepoUrl) and definition path (ciamRepoPath; qualified
                   by the repository when its URL isn't known)
  kept             what the record adds (owner, criticality, the binding role that realizes it, the roles it uses)
"""
import re
from functools import reduce
from typing import NamedTuple, Optional

from ...core.directory import children, get, make_entry, merged_attrs, ou_entry, rdn_of, rdn_value, values
from .naming import JOBS, job_dn

FoundPipeline = NamedTuple("FoundPipeline", [("system", str), ("repo", str), ("repo_url", Optional[str]),
                                             ("path", str), ("name", str), ("schedules", tuple), ("triggers", tuple),
                                             ("runners", tuple), ("secrets", tuple), ("environments", tuple)])
OWNED = ("cn", "ciamJobKind", "ciamSchedule", "ciamTrigger", "ciamRuntime", "ciamSecretName", "ciamDeploysTo",
         "ciamRepoUrl", "ciamRepoPath")
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def slug(text):
    """Text as part of an entry name: anything but letters, digits, '.', '_' and '-' becomes '-'."""
    return _UNSAFE.sub("-", text or "").strip("-")


def environment_name(env):
    """The environment a CI job deploys to, as CI systems write it: a name, or a mapping with a name (None: none)."""
    return env.get("name") if isinstance(env, dict) else env if isinstance(env, str) else None


def stored_path(p):
    """Where a pipeline's definition is, as the record keeps it: its path in the repository when the repository's URL
    is known, else qualified by the repository (repo/path), so two repositories' same-named files stay apart."""
    return p.path if p.repo_url else f"{p.repo}/{p.path}"


def _held(d, p):
    return next((j for j in children(d, JOBS, "ciamJob") if stored_path(p) in values(j, "ciamRepoPath")
                 and (values(j, "ciamRepoUrl") == ((p.repo_url,) if p.repo_url else ()))), None)


def pipeline_entry(d, p, taken):
    """The ciamJob entry for one found pipeline: the record's (same repository and path) or a new one, named
    SYSTEM-REPO-NAME, made unique against taken (lower-cased names)."""
    held = _held(d, p)
    stem = p.path.rsplit("/", 1)[-1].rsplit(".", 1)[0].lstrip(".")
    base = slug(f"{p.system}-{p.repo.rsplit('/', 1)[-1]}-{stem}") or "pipeline"
    dn = held.dn if held is not None else \
        job_dn(next(n for n in (base, *(f"{base}-{i}" for i in range(2, 1000))) if n.lower() not in taken))
    owned = {"cn": (rdn_of(dn),), "ciamJobKind": ("pipeline",), "ciamSchedule": p.schedules,
             "ciamTrigger": p.triggers, "ciamRuntime": (", ".join(p.runners) if p.runners else None,),
             "ciamSecretName": p.secrets, "ciamDeploysTo": p.environments, "ciamRepoUrl": (p.repo_url,),
             "ciamRepoPath": (stored_path(p),)}
    return make_entry(dn, ("top", "ciamObject", "ciamJob"), merged_attrs(get(d, dn), owned, OWNED))


def pipeline_groups(d, pipelines):
    """((DN, (entry,)), ...) for the found pipelines, each once."""
    taken = {rdn_value(j).lower() for j in children(d, JOBS, "ciamJob")}

    def place(acc, p):
        entries, names = acc
        e = pipeline_entry(d, p, names)
        return (*entries, e), names | {rdn_value(e).lower()}
    entries, _ = reduce(place, pipelines, ((), taken))
    return tuple((e.dn, (e,)) for e in entries)


def jobs_container():
    return ou_entry(JOBS)

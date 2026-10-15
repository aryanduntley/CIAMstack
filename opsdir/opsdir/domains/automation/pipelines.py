"""Pipelines read from a CI system's definitions, placed as jobs: shared by every CI system's package. Pure.

A CI package parses its own files into FoundPipelines; pipeline_groups places them as ciamJob entries of kind pipeline
under ou=jobs, so every CI system's pipelines are the same kind of record:

  matched by       a pipeline the record has with the same repository and definition path
  named            SYSTEM-REPO-NAME (the definition's file name), made unique
  recorded         its name as the system shows it (ciamJobName), the CI system (ciamCiSystem), schedules (as the
                   system writes them), other triggers, the runners it asks for (ciamRuntime), the secrets it names
                   (ciamSecretName: names only, the package never reads a value), the environments it deploys to
                   (ciamDeploysTo), the repository (ciamRepoUrl) and definition path (ciamRepoPath; qualified by the
                   repository when its URL isn't known)
  kept             what the record adds (owner, criticality, the binding role that realizes it, the roles it uses)
  removed          a pipeline the record has from the same CI system and a repository the import read (ReadRepository),
                   not found again and not at a definition path that couldn't be read this time: an empty group and a
                   notice naming it, so the import's deletion is the operator's to take or keep. Repositories the
                   import didn't read are never touched (a partial export isn't a deletion); a pipeline recorded
                   before its CI system was (no ciamCiSystem) is removed only after an import has found it again.
"""
import re
from functools import reduce
from typing import NamedTuple, Optional

from ...core.directory import children, get, make_entry, merged_attrs, one, ou_entry, rdn_of, rdn_value, values
from .naming import JOBS, job_dn

FoundPipeline = NamedTuple("FoundPipeline", [("system", str), ("repo", str), ("repo_url", Optional[str]),
                                             ("path", str), ("name", str), ("schedules", tuple), ("triggers", tuple),
                                             ("runners", tuple), ("secrets", tuple), ("environments", tuple)])
# A repository a CI package's import read: its system, folder and URL (None: unknown), and the definition paths in it
# that couldn't be read this time (a pipeline held at one of them is kept)
ReadRepository = NamedTuple("ReadRepository", [("system", str), ("repo", str), ("repo_url", Optional[str]),
                                               ("unread", tuple)])
OWNED = ("cn", "ciamJobKind", "ciamJobName", "ciamCiSystem", "ciamSchedule", "ciamTrigger", "ciamRuntime",
         "ciamSecretName", "ciamDeploysTo", "ciamRepoUrl", "ciamRepoPath")
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
    return _stored(p.repo, p.repo_url, p.path)


def _stored(repo, repo_url, path):
    return path if repo_url else f"{repo}/{path}"


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
    owned = {"cn": (rdn_of(dn),), "ciamJobKind": ("pipeline",), "ciamJobName": (p.name or None,),
             "ciamCiSystem": (p.system,), "ciamSchedule": p.schedules,
             "ciamTrigger": p.triggers, "ciamRuntime": (", ".join(p.runners) if p.runners else None,),
             "ciamSecretName": p.secrets, "ciamDeploysTo": p.environments, "ciamRepoUrl": (p.repo_url,),
             "ciamRepoPath": (stored_path(p),)}
    return make_entry(dn, ("top", "ciamObject", "ciamJob"), merged_attrs(get(d, dn), owned, OWNED))


def _in_repository(j, r):
    """Whether held pipeline j is defined in read repository r: the same URL, else (no URL either side) a path
    qualified by r's folder."""
    url = values(j, "ciamRepoUrl")
    return url == (r.repo_url,) if r.repo_url else \
        not url and any(v.startswith(f"{r.repo}/") for v in values(j, "ciamRepoPath"))


def gone_pipelines(d, found_dns, read):
    """The pipelines the record has that the read repositories no longer define: of the repository's CI system
    (ciamCiSystem), in a read repository, not among found_dns (normalized DNs of the pipelines found again) and not at
    one of its unread definition paths."""
    held = tuple(j for j in children(d, JOBS, "ciamJob") if values(j, "ciamJobKind") == ("pipeline",)
                 and j.norm not in found_dns)
    return tuple(j for j in held if any(
        values(j, "ciamCiSystem") == (r.system,) and _in_repository(j, r)
        and not set(values(j, "ciamRepoPath")) & {_stored(r.repo, r.repo_url, u) for u in r.unread} for r in read))


def pipeline_groups(d, pipelines, read=()):
    """(((DN, (entry,)), ...) for the found pipelines, each once, then (DN, ()) for each gone_pipelines entry of the
    read repositories; notices naming the ones removed)."""
    taken = {rdn_value(j).lower() for j in children(d, JOBS, "ciamJob")}

    def place(acc, p):
        entries, names = acc
        e = pipeline_entry(d, p, names)
        return (*entries, e), names | {rdn_value(e).lower()}
    entries, _ = reduce(place, pipelines, ((), taken))
    gone = gone_pipelines(d, {e.norm for e in entries}, read)
    return (*((e.dn, (e,)) for e in entries), *((j.dn, ()) for j in gone)), tuple(
        f"pipeline {rdn_value(j)} ({one(j, 'ciamCiSystem')}, {one(j, 'ciamRepoUrl') or 'no repository URL'}, "
        f"{one(j, 'ciamRepoPath')}): no longer defined in its repository; removed" for j in gone)


def jobs_container():
    return ou_entry(JOBS)

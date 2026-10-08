"""Configuration sources `opsdir collect` may read for any importer: a Git repository, a Kubernetes ConfigMap, files
over SSH. Each is a collection source (ciamCollectionSource) whose ciamSourceRef names it, and each kind is read only
once its estate setting allows it (collect-from-git, -kubernetes, -ssh: off until an approved change turns it on); what
is read is the operator's own access (Git credentials, kubectl context, SSH agent and known hosts), never held. Pure:
the calls are built here, run by the core. A kubectl context that doesn't exist fails its call (kubectl says so).

  git+https://host/org/repo.git?ref=main&dir=gateway&prefix=     a shallow clone (git clone --depth 1) into a private
  git+ssh://git@host/org/repo.git?...                            work directory; the files under dir (else all), placed
                                                                 under prefix; .git is never read
  k8s://<context>/<namespace>/configmap/<name>?prefix=routes/    kubectl get configmap -o json: each data key a file
                                                                 under prefix (never Secrets)
  ssh://<user>@<host>[:port]/<base>?dir=config&match=*.json      find the files under base/dir (named like match),
  ssh://<user>@<host>/<base>?files=bin/run.properties,...        then cat each (zcat a .gz, saved without .gz); or
                                                                 the files listed; placed under prefix (default
                                                                 <host>/), dir kept in the path

SSH runs with BatchMode and StrictHostKeyChecking=yes (an unknown or changed host key fails), and only fixed commands
(find, cat, zcat) on paths that must match a safe pattern and are quoted, since ssh hands its command to the remote
shell: nothing in the record becomes shell code."""
import json
import posixpath
import re
import shlex
from urllib.parse import parse_qs, urlparse

from ...core.contract import Command
from ...core.directory import one
from ...core.environment import of_class
from ...core.settings import setting_value
from .collection import SOURCE
from .settings import COLLECT_GIT, COLLECT_KUBERNETES, COLLECT_SSH

KINDS = {"git": COLLECT_GIT, "kubernetes": COLLECT_KUBERNETES, "ssh": COLLECT_SSH}
SAFE = re.compile(r"^[A-Za-z0-9_./@+=,:-]+$")          # a path or name usable on a remote command line (then quoted)
GLOB = re.compile(r"^[A-Za-z0-9_.*?+-]+$")
NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")    # a host, user or object name: never taken for an option
WORK = "_work/"


def source_kind(ref):
    """The kind of configuration source a ciamSourceRef names (git, kubernetes, ssh), or None."""
    scheme = urlparse(ref or "").scheme
    return {"git+https": "git", "git+ssh": "git", "k8s": "kubernetes", "ssh": "ssh"}.get(scheme)


def _query(parsed):
    return {k: v[0] for k, v in parse_qs(parsed.query).items() if v}


def _safe(*paths):
    return all(p and SAFE.match(p) and ".." not in p.split("/") for p in paths)


def _named(*names):
    return all(n is None or NAME.match(n) for n in names)


def git_files(dir_, prefix):
    """keep of a clone: the files under dir (all when none) placed under prefix, .git left out."""
    root = f"repo/{dir_.strip('/')}/" if dir_ else "repo/"
    return lambda files: {f"{prefix}{rel[len(root):]}": text for rel, text in files.items()
                          if rel.startswith(root) and "/.git/" not in f"/{rel}"}


def configmap_files(prefix):
    """keep of kubectl get configmap -o json: each data key a file under prefix."""
    def files(text):
        try:
            data = (json.loads(text) or {}).get("data") or {}
        except (ValueError, AttributeError):
            data = {}
        return {f"{prefix}{k}": v for k, v in data.items() if isinstance(v, str)}
    return files


def _git(parsed, q):
    url = f"{parsed.scheme[4:]}://{parsed.netloc}{parsed.path}"
    ref = q.get("ref")
    return (("", Command(("git", "clone", "--depth", "1", "--single-branch", *(("--branch", ref) if ref else ()),
                          url, "{dir}/export/repo"), workdir=True,
                         keep=git_files(q.get("dir", ""), q.get("prefix", "")))),)


def _kubernetes(parsed, q):
    context, (ns, kind, name) = parsed.netloc, (parsed.path.strip("/").split("/") + ["", "", ""])[:3]
    if kind != "configmap" or not (context and ns and name) or not _named(context, ns, name):
        return None
    return (("", Command(("kubectl", "--context", context, "-n", ns, "get", "configmap", name, "-o", "json"),
                         keep=configmap_files(q.get("prefix", "")))),)


def _ssh_target(parsed):
    host, user = parsed.hostname, parsed.username
    return (("-p", str(parsed.port)) if parsed.port else ()), (f"{user}@{host}" if user else host)


def _ssh(parsed, q, done, n):
    port, target = _ssh_target(parsed)
    ssh = ("ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", *port, target)
    base, prefix = parsed.path.rstrip("/") or "/", q.get("prefix", f"{parsed.hostname}/")

    def read(path, rel):
        gz = path.endswith(".gz")
        return (f"{prefix}{rel[:-3] if gz else rel}",
                Command((*ssh, "zcat" if gz else "cat", "--", shlex.quote(path))))
    if q.get("files"):
        rels = tuple(r.strip("/") for r in q["files"].split(",") if r.strip("/"))
        return tuple(read(posixpath.join(base, r), r) for r in rels) if _safe(base, *rels) else None
    dir_, match = q.get("dir", "").strip("/"), q.get("match")
    target_dir = posixpath.join(base, dir_) if dir_ else base
    if not _safe(target_dir) or (match and not GLOB.match(match)):
        return None
    listing = f"{WORK}ssh-{n}.txt"
    found = tuple(line.strip() for line in (done.get(listing) or "").splitlines()
                  if line.strip().startswith(target_dir + "/") and _safe(line.strip()))
    return ((listing, Command((*ssh, "find", shlex.quote(target_dir), "-type", "f",
                               *(("-name", shlex.quote(match)) if match else ())))),
            *(read(f, posixpath.join(dir_, f[len(target_dir) + 1:]) if dir_ else f[len(target_dir) + 1:])
              for f in found))


def _calls(ref, done, n):
    """The calls a configuration source's ref makes (given what was collected so far), or None when it doesn't parse."""
    parsed, kind = urlparse(ref), source_kind(ref)
    q = _query(parsed)
    if kind == "git":
        return _git(parsed, q) if parsed.hostname and _named(parsed.hostname, parsed.username) and parsed.path \
            else None
    if kind == "kubernetes":
        return _kubernetes(parsed, q)
    return _ssh(parsed, q, done, n) if kind == "ssh" and parsed.hostname and \
        _named(parsed.hostname, parsed.username) else None


def _sources(m, importer):
    return tuple((s, one(s, "ciamSourceRef")) for s in of_class(m, SOURCE)
                 if one(s, "ciamImporter") == importer and source_kind(one(s, "ciamSourceRef")))


def source_steps(importer):
    """Collector.steps reading importer's ('adapter/importer') configuration sources the settings allow."""
    def steps(d, m, done, options):
        allowed = [(i, ref) for i, (_, ref) in enumerate(_sources(m, importer))
                   if setting_value(d, KINDS[source_kind(ref)])]
        return tuple(c for i, ref in allowed for c in (_calls(ref, done, i) or ()))
    return steps


def source_problems(importer):
    """Collector.problems: a configuration source whose kind its setting doesn't allow, or whose ref doesn't parse."""
    def problems(d, m, options):
        found = _sources(m, importer)
        return (*(f"collection source `{one(s, 'cn')}` ({source_kind(ref)}): not allowed: `opsdir setting "
                  f"{KINDS[source_kind(ref)].name} TRUE --change CHG-…` allows reading {source_kind(ref)} sources"
                  for s, ref in found if not setting_value(d, KINDS[source_kind(ref)])),
                *(f"collection source `{one(s, 'cn')}`: {ref} isn't a source opsdir can read (see the README)"
                  for i, (s, ref) in enumerate(found)
                  if setting_value(d, KINDS[source_kind(ref)]) and _calls(ref, {}, i) is None))
    return problems


def has_sources(m, importer):
    """Whether environment m declares configuration sources for importer."""
    return bool(_sources(m, importer))

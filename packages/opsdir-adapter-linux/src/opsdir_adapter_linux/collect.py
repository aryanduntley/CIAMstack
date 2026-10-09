"""Linux collectors (`opsdir collect`, core.contract Collector): the servers' own files and a few commands' output that
linux/baseline and linux/jobs read, collected over SSH from every server of the roles collection sources name. Pure:
the core runs the calls.

A collection source for linux/baseline or linux/jobs names a server role (ciamTargetRole), the account to sign in as
(ciamLoginName: a read-only login) and, when it isn't 22, the port (ciamPort); each server of the role is read by its
host name (ciamHostname), one folder per server, the layout the importers read. Reading over SSH is allowed only by
the estate setting collect-from-ssh. Every call is the core's SSH (domains.governance.config_sources.ssh_command:
batch mode, strict host keys, so an unknown or changed host key fails) running a fixed command line: `cat` of a file,
`find` of a directory's files then `cat` of each (only paths that look like paths, quoted), and, for the baseline,
`command -v` of the tools first, then only those present: `java -version`, the default truststore's listing and the
installed packages (rpm, or dpkg-query on Debian-like systems). A file, directory or tool a server doesn't have is
absent, not a failure. Nothing is escalated: users' crontabs (/var/spool/cron, readable by root only) aren't read.

  baseline   etc/os-release, etc/security/limits.conf and limits.d/*.conf, etc/sysctl.conf and sysctl.d/*.conf,
             sys/kernel/mm/transparent_hugepage/enabled, proc/sys/crypto/fips_enabled, etc/selinux/config,
             etc/systemd/system/* (services, and the timers that make some of them jobs), etc/hosts, etc/resolv.conf;
             java/version.txt, java/cacerts.txt, packages.txt
  jobs       etc/crontab, etc/cron.d/*, etc/systemd/system/* (timers and the services they start)
"""
import shlex

from opsdir.core.contract import Collector
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import of_class, servers_with_role
from opsdir.core.settings import setting_value
from opsdir.domains.governance.collection import SOURCE
from opsdir.domains.governance.config_sources import safe_name, safe_path, ssh_command
from opsdir.domains.governance.settings import COLLECT_SSH

WORK = "_work/"
GONE = ("No such file or directory",)
BASELINE_FILES = ("etc/os-release", "etc/security/limits.conf", "etc/sysctl.conf",
                  "sys/kernel/mm/transparent_hugepage/enabled", "proc/sys/crypto/fips_enabled", "etc/selinux/config",
                  "etc/hosts", "etc/resolv.conf")
BASELINE_DIRS = (("etc/security/limits.d", "*.conf"), ("etc/sysctl.d", "*.conf"), ("etc/systemd/system", None))
JOB_FILES = ("etc/crontab",)
JOB_DIRS = (("etc/cron.d", None), ("etc/systemd/system", None))
TOOLS = "command -v java keytool rpm dpkg-query || true"
COMMANDS = (("java/version.txt", "java", "java -version 2>&1"),
            ("java/cacerts.txt", "keytool", "keytool -list -cacerts -storepass changeit"))
PACKAGES = {"rpm": "rpm -qa --qf '%{NAME} %{VERSION}\\n'", "dpkg-query": "dpkg-query -W"}
DEBIAN_LIKE = ("debian", "ubuntu")


def _role_sources(m, importer):
    """The environment's collection sources for importer that name a server role (no ciamSourceRef: those are
    configuration sources, read by the core)."""
    return tuple(s for s in of_class(m, SOURCE) if one(s, "ciamImporter") == importer
                 and one(s, "ciamTargetRole") and not one(s, "ciamSourceRef"))


def ssh_hosts(m, importer):
    """((host name, SSH target, port), ...) of each server of the roles importer's collection sources name, once each,
    when its host name, the login name and the port are safe to pass."""
    rows = ((one(x, "ciamHostname"), one(s, "ciamLoginName"), one(s, "ciamPort"))
            for s in _role_sources(m, importer) for x in servers_with_role(m, one(s, "ciamTargetRole")))
    return tuple(dict.fromkeys((h, f"{u}@{h}" if u else h, p) for h, u, p in rows
                               if h and safe_name(h, u) and (p is None or p.isdigit())))


def ssh_problems(importer):
    """Collector.problems of importer: its role sources while collect-from-ssh is off, or naming a role with no servers
    with host names, a login name or port that can't be passed safely."""
    def problems(d, m, options):
        found = _role_sources(m, importer)
        if found and not setting_value(d, COLLECT_SSH):
            return (f"{importer}: reading servers over SSH is not allowed: `opsdir setting {COLLECT_SSH.name} TRUE "
                    f"--change CHG-…` allows it",)
        return tuple(f"collection source `{rdn_value(s)}`: {why}" for s in found for why in (
            *((f"role `{one(s, 'ciamTargetRole')}` has no servers with host names in {m.label}",)
              if not [x for x in servers_with_role(m, one(s, "ciamTargetRole")) if one(x, "ciamHostname")] else ()),
            *(("its login name can't be passed to ssh safely",) if not safe_name(one(s, "ciamLoginName")) else ()),
            *(("its port isn't a number",) if one(s, "ciamPort") and not one(s, "ciamPort").isdigit() else ())))
    return problems


def _found(done, host, n, top):
    """The files a directory listing collected so far names (paths that look like paths, under the directory)."""
    return tuple(line.strip() for line in (done.get(f"{WORK}{host}/find-{n}.txt") or "").splitlines()
                 if line.strip().startswith(f"/{top}/") and safe_path(line.strip()))


def _packages(done, host, present):
    """The package listing to run: dpkg-query on a Debian-like system, else rpm, of the tools present; None while
    os-release hasn't been read."""
    if f"{host}/etc/os-release" not in done:
        return None
    fields = dict(line.split("=", 1) for line in (done.get(f"{host}/etc/os-release") or "").lower().splitlines()
                  if "=" in line)
    ids = {*fields.get("id", "").strip().strip('"').split(), *fields.get("id_like", "").strip().strip('"').split()}
    debian = bool(ids & set(DEBIAN_LIKE))
    order = ("dpkg-query", "rpm") if debian else ("rpm", "dpkg-query")
    return next((PACKAGES[t] for t in order if t in present), None)


def _host_steps(done, host, target, port, files, dirs, commands):
    """(path, call) of one server's files (cat), directories' files (find, then cat of each) and, with commands, the
    tools present first, then their commands."""
    ssh = lambda *remote: ssh_command(target, port, *remote, absent=GONE)
    tools = f"{WORK}{host}/tools.txt"
    present = {line.strip().rsplit("/", 1)[-1] for line in (done.get(tools) or "").splitlines() if line.strip()}
    tools_known = commands and done.get(tools) is not None
    packages = _packages(done, host, present) if tools_known else None
    return (*((f"{host}/{f}", ssh("cat", "--", shlex.quote(f"/{f}"))) for f in files),
            *((f"{WORK}{host}/find-{n}.txt", ssh("find", shlex.quote(f"/{top}"), "-type", "f",
                                                  *(("-name", shlex.quote(match)) if match else ())))
              for n, (top, match) in enumerate(dirs)),
            *((f"{host}{path}", ssh("cat", "--", shlex.quote(path)))
              for n, (top, _) in enumerate(dirs) for path in _found(done, host, n, top)),
            *(((tools, ssh(TOOLS)),) if commands else ()),
            *((f"{host}/{path}", ssh(command)) for path, tool, command in (COMMANDS if tools_known else ())
              if tool in present),
            *(((f"{host}/packages.txt", ssh(packages)),) if packages else ()))


def _steps(importer, m, done, files, dirs, commands):
    return tuple(c for host, target, port in ssh_hosts(m, importer)
                 for c in _host_steps(done, host, target, port, files, dirs, commands))


def baseline_steps(d, m, done, options):
    """The linux/baseline calls still to make: each server's files, directories' files, tools, then their commands."""
    return _steps("linux/baseline", m, done, BASELINE_FILES, BASELINE_DIRS, True)


def jobs_steps(d, m, done, options):
    """The linux/jobs calls still to make: each server's crontab, cron.d and systemd unit files."""
    return _steps("linux/jobs", m, done, JOB_FILES, JOB_DIRS, False)
COLLECTORS = (Collector("baseline", "environment", baseline_steps, None, ssh_problems("linux/baseline")),
              Collector("jobs", "environment", jobs_steps, None, ssh_problems("linux/jobs")))

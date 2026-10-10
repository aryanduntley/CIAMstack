"""Linux schedulers' files read as jobs: crontabs and systemd timers. Pure.

  etc/crontab, etc/cron.d/<file>           system crontabs: minute hour day month weekday USER command
  var/spool/cron/crontabs/<user>,          a user's crontab: minute hour day month weekday command (runs as <user>)
    var/spool/cron/<user>
  etc/systemd/system/<name>.timer          a timer: OnCalendar / OnBootSec / OnStartupSec / OnUnitActiveSec /
    + <unit>.service                       OnActiveSec, and the service it starts (Unit=, else <name>.service):
                                           its ExecStart and User

Each found job is a Found: its kind, schedules, triggers, command (the shell command line: crontab's \\% and
systemd's %% and $$ escapes undone), the account it runs as, and where it was found (path and line). Lines that set an
environment variable are kept apart (an assignment may hold a secret).
"""
import re
from functools import reduce
from typing import NamedTuple, Optional

Found = NamedTuple("Found", [("kind", str), ("name", str), ("schedules", tuple), ("triggers", tuple),
                             ("command", str), ("runs_as", Optional[str]), ("where", str)])

SYSTEM_CRONTABS = ("etc/crontab",)
CRON_D, USER_SPOOLS = "etc/cron.d/", ("var/spool/cron/crontabs/", "var/spool/cron/")
TIMERS = "etc/systemd/system/"
_ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
TIMER_KEYS = ("OnCalendar", "OnBootSec", "OnStartupSec", "OnUnitActiveSec", "OnUnitInactiveSec", "OnActiveSec")
BOOT_KEYS = ("OnBootSec", "OnStartupSec")


def job_name(command):
    """A name for a job from what it runs: the script or program its command starts (its first path, else its first
    word), without directory or extension."""
    words = command.split()
    path = next((w for w in words if "/" in w), words[0] if words else "job")
    stem = path.rstrip("/").rsplit("/", 1)[-1].rsplit(".", 1)[0]
    return _UNSAFE.sub("-", stem).strip("-") or "job"


def _cron_line(line, system):
    """(schedule, trigger, user, command) of a crontab line, or None for a line that isn't one."""
    parts = line.split()
    when_n = 1 if parts and parts[0].startswith("@") else 5
    need = when_n + (1 if system else 0)
    if len(parts) <= need:
        return None
    when, user, command = " ".join(parts[:when_n]), (parts[when_n] if system else None), " ".join(parts[need:])
    command = command.replace("\\%", "%")          # the record holds the shell command; crontab escapes % as \%
    return (None, "boot", user, command) if when == "@reboot" else (when, None, user, command)


def crontab(path, text):
    """(jobs, environment assignments as (path, line number, name, value)) of one crontab."""
    system = path in SYSTEM_CRONTABS or path.startswith(CRON_D)
    user = None if system else path.rsplit("/", 1)[-1]
    lines = [(n, line.strip()) for n, line in enumerate(text.splitlines(), 1)]
    meaningful = [(n, line) for n, line in lines if line and not line.startswith("#")]
    assigns = tuple((path, n, m.group(1), line[m.end():].strip()) for n, line in meaningful
                    for m in (_ASSIGN.match(line),) if m and not line.startswith("@"))
    parsed = [(n, _cron_line(line, system)) for n, line in meaningful if not _ASSIGN.match(line)]
    jobs = tuple(Found("cron", job_name(cmd), tuple(filter(None, (when,))), tuple(filter(None, (trigger,))), cmd,
                       runs_as or user, f"{path}:{n}")
                 for n, p in parsed if p for when, trigger, runs_as, cmd in (p,))
    return jobs, assigns


def unit_settings(text):
    """{section: {key: (values, ...)}} of a systemd unit file."""
    def add(acc, line):
        section, found = acc
        if line.startswith("[") and line.endswith("]"):
            return line[1:-1], found
        key, sep, value = line.partition("=")
        if not sep or section is None:
            return acc
        entries = found.get(section, {})
        return section, {**found, section: {**entries, key.strip(): (*entries.get(key.strip(), ()), value.strip())}}
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith(("#", ";"))]
    return reduce(add, lines, (None, {}))[1]


def _exec(value):
    """An ExecStart= command as the shell would run it: its prefixes off, systemd's %% and $$ escapes undone."""
    return value.lstrip("-@+!:").replace("%%", "%").replace("$$", "$")


def _started(path, settings):
    """The service a timer starts: its Unit=, else the timer's own name."""
    return (settings.get("Unit") or (f"{path.rsplit('/', 1)[-1][:-len('.timer')]}.service",))[0]


def timer(path, text, files):
    """The job a timer runs, or None when it schedules nothing."""
    settings = unit_settings(text).get("Timer", {})
    if not any(k in settings for k in TIMER_KEYS):
        return None
    stem = path.rsplit("/", 1)[-1][:-len(".timer")]
    service = unit_settings(files.get(f"{TIMERS}{_started(path, settings)}", "")).get("Service", {})
    schedules = tuple(f"{k}={v}" for k in TIMER_KEYS if k not in BOOT_KEYS for v in settings.get(k, ()))
    triggers = ("boot",) if any(k in settings for k in BOOT_KEYS) else ()
    command = " ".join(_exec(v) for v in service.get("ExecStart", ()))
    return Found("timer", _UNSAFE.sub("-", stem).strip("-") or "timer", schedules, triggers, command,
                 (service.get("User") or (None,))[0], path)


def timer_services(files):
    """The service units the server's timers start (Unit=, else the timer's own name): they are jobs, not services."""
    return frozenset(_started(p, unit_settings(t).get("Timer", {})) for p, t in files.items()
                     if p.startswith(TIMERS) and p.endswith(".timer"))


def found_jobs(files):
    """(jobs, environment assignments) of one server's files ({path under /: text})."""
    tabs = [crontab(p, t) for p, t in sorted(files.items())
            if p in SYSTEM_CRONTABS or p.startswith(CRON_D) or p.startswith(USER_SPOOLS)]
    timers = [timer(p, t, files) for p, t in sorted(files.items()) if p.startswith(TIMERS) and p.endswith(".timer")]
    return (*(j for js, _ in tabs for j in js), *(t for t in timers if t)), tuple(a for _, a_s in tabs for a in a_s)

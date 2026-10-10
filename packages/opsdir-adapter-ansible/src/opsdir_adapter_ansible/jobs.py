"""A server role's jobs in an environment (the core automation domain's ciamJob: cron entries and systemd
timers whose ciamTargetRole is the role, and that apply in the environment: core environment.applies_in) as the
variables the host-config playbook reads. A cron job's schedule is its five fields or an @-word; a timer's schedule
lines go into its [Timer] section as the record writes them (OnCalendar=..., OnBootSec=...). The command runs as cron
runs it, through /bin/sh: a cron entry escapes %, which cron reads as a line break; a timer's service runs /bin/sh -c
with the command quoted as systemd reads ExecStart (\\, ", % and $ escaped). A job whose command the record withholds
(it held a secret) isn't deployed, and is named. Pure."""
import re

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.environment import applies_in
from opsdir.domains.automation.naming import JOBS

CRON_FIELDS = ("minute", "hour", "day", "month", "weekday")
SPECIAL = ("annually", "daily", "hourly", "monthly", "reboot", "weekly", "yearly")


def _cron(schedule):
    """A cron schedule as ansible.builtin.cron's fields: {special_time} for an @-word, else the five fields; None
    when it is neither."""
    if schedule.startswith("@") and schedule[1:] in SPECIAL:
        return {"special_time": schedule[1:]}
    fields = schedule.split()
    return dict(zip(CRON_FIELDS, fields)) if len(fields) == 5 else None


def cron_command(command):
    """A command as a crontab line keeps it: % escaped (cron reads a bare % as a line break)."""
    return command.replace("%", "\\%")


def exec_start(command):
    """A systemd ExecStart= value running a command through /bin/sh, as cron would: the command one double-quoted
    argument, with \\, ", % (a specifier) and $ (a variable) escaped as systemd reads them."""
    quoted = command.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return f'/bin/sh -c "{quoted}"'


def unit_name(job):
    """The systemd unit name of a timer job: opsdir-<job>, characters systemd doesn't take as -."""
    return "opsdir-" + re.sub(r"[^A-Za-z0-9_.-]", "-", rdn_value(job))


def role_jobs(m, role):
    """The cron and timer jobs of a server role that apply in environment m, in DN order."""
    return tuple(j for j in children(m.d, JOBS, "ciamJob") if one(j, "ciamTargetRole") == role
                 and one(j, "ciamJobKind") in ("cron", "timer") and applies_in(j, m))


def job_vars(m, role):
    """{ciam_cron_jobs, ciam_timer_jobs, ciam_jobs_not_deployed} of a role in environment m (those it has)."""
    jobs = role_jobs(m, role)
    cron = [{"name": f"{rdn_value(j)}" + (f" ({i + 1})" if len(values(j, "ciamSchedule")) > 1 else ""),
             "job": cron_command(one(j, "ciamCommand")), "user": one(j, "ciamRunsAs", "root"), **fields}
            for j in jobs if one(j, "ciamJobKind") == "cron" and one(j, "ciamCommand")
            for i, s in enumerate(values(j, "ciamSchedule")) for fields in (_cron(s),) if fields]
    timers = [{"unit": unit_name(j), "description": f"{rdn_value(j)} (opsdir)",
               "exec_start": exec_start(one(j, "ciamCommand")), "user": one(j, "ciamRunsAs", "root"),
               "schedule": list(values(j, "ciamSchedule"))}
              for j in jobs if one(j, "ciamJobKind") == "timer" and one(j, "ciamCommand")]
    skipped = [rdn_value(j) for j in jobs if not one(j, "ciamCommand")]
    found = {"ciam_cron_jobs": cron, "ciam_timer_jobs": timers, "ciam_jobs_not_deployed": skipped}
    return {k: v for k, v in found.items() if v}

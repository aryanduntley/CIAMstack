"""The importer `linux/jobs`: Linux servers' crontabs and systemd timers read into the record as jobs. Pure.

Takes one folder per server, named by its hostname (or its record name), holding copies of the server's files at their
paths under / (etc/crontab, etc/cron.d/, var/spool/cron/, etc/systemd/system/). A job is intent: the same job on every
server of a role is one job for that role (ciamTargetRole), with the servers it was found on (ciamFoundOn).

  matched by       a job the record has of the same kind, role and command, else of the same name
  named            ROLE-NAME, NAME from the script or program the command runs (or the timer), made unique
  command          not recorded when it holds secret material, a secret assignment or a random-looking token (named)
  code             linked to the recorded bundle whose deploy path the command runs from (ciamCodeBundle)
  notices          a job found on some of a role's servers in an environment and not others; schedules that differ
                   between servers; environment lines that give a secret a value (never recorded); folders that name
                   no server

What the record adds to a job (its owner, criticality, the roles it uses) is kept on import.
"""
from functools import reduce

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import children, get, make_entry, merged_attrs, one, rdn_of, rdn_value
from opsdir.core.environment import server_location, server_named
from opsdir.core.secrets import text_concerns, withheld
from opsdir.core.sources import by_folder
from opsdir.domains.automation.naming import JOBS, job_dn
from opsdir.domains.automation.pipelines import jobs_container
from opsdir.domains.configuration.naming import BUNDLES
from .cron import found_jobs

OWNED = ("cn", "ciamJobKind", "ciamSchedule", "ciamTrigger", "ciamCommand", "ciamRunsAs", "ciamTargetRole",
         "ciamFoundOn")


def _roles(d):
    return tuple(dict.fromkeys(one(e, "ciamServerRole") for e in d.entries.values() if "ciamServer" in e.classes))


def grouped(placed):
    """{(kind, role, name, command): [(server, Found), ...]}: each job once per role, with every server it was found
    on."""
    keys = [((f.kind, one(s, "ciamServerRole"), f.name, f.command), (s, f)) for s, found in placed for f in found]
    return {k: [sf for kk, sf in keys if kk == k] for k in dict.fromkeys(k for k, _ in keys)}


def _held_dn(d, kind, role, name, command, taken):
    """The DN of the job the record has for this one, else a new unique name's."""
    jobs = children(d, JOBS, "ciamJob")
    same = next((j for j in jobs if (one(j, "ciamJobKind"), one(j, "ciamTargetRole")) == (kind, role)
                 and (one(j, "ciamCommand") == command or rdn_value(j) == f"{role}-{name}")), None)
    if same is not None:
        return same.dn
    base = f"{role}-{name}"
    return job_dn(next(n for n in (base, *(f"{base}-{i}" for i in range(2, 1000))) if n.lower() not in taken))


def _bundle_of(d, command):
    """The recorded bundle whose deploy path the command runs from, or None."""
    words = command.split()
    return next((b for b in children(d, BUNDLES, "ciamBundle") if one(b, "ciamDeployPath")
                 and any(w.startswith(one(b, "ciamDeployPath").rstrip("/") + "/") or w == one(b, "ciamDeployPath")
                         for w in words)), None)


def job_entry(d, key, found_on, patterns, taken):
    """(entry, notices) for one job found on these servers."""
    kind, role, name, command = key
    first = found_on[0][1]
    dn = _held_dn(d, kind, role, name, command, taken)
    secret = bool(text_concerns(command, patterns))
    bundle = _bundle_of(d, command)
    owned = {"cn": (rdn_of(dn),), "ciamJobKind": (kind,), "ciamSchedule": first.schedules,
             "ciamTrigger": first.triggers, "ciamCommand": (None if secret else command,),
             "ciamRunsAs": (first.runs_as,), "ciamTargetRole": (role,),
             "ciamFoundOn": tuple(sorted({s.dn for s, _ in found_on})),
             **({"ciamCodeBundle": (bundle.dn,)} if bundle is not None else {})}
    names = (*OWNED, *(("ciamCodeBundle",) if bundle is not None else ()))
    entry = make_entry(dn, ("top", "ciamObject", "ciamJob"), merged_attrs(get(d, dn), owned, names))
    label = f"job {owned['cn'][0]} ({first.where} on {rdn_value(found_on[0][0])})"
    schedules = {(f.schedules, f.triggers) for _, f in found_on}
    return entry, (*((f"{label}: its command holds secret material; not recorded, record what it runs by hand",)
                     if secret else ()),
                   *((f"{label}: its schedule differs between servers "
                      f"({', '.join(f'{rdn_value(s)}: ' + ' '.join((*f.schedules, *f.triggers)) for s, f in found_on)}"
                      f"); recorded the first",) if len(schedules) > 1 else ()))


def _partial(d, key, found_on):
    """Notices for a job found on some of its role's servers in an environment and not on the others."""
    role, where = key[1], {server_location(s) for s, _ in found_on}
    servers = [e for e in d.entries.values() if "ciamServer" in e.classes and one(e, "ciamServerRole") == role]
    on = {s.dn for s, _ in found_on}
    missing = {w: sorted(rdn_value(s) for s in servers if server_location(s) == w and s.dn not in on) for w in where}
    return tuple(f"job {key[2]} of role {role} is on {', '.join(sorted(rdn_value(s) for s, _ in found_on))} but not "
                 f"{', '.join(names)} in {w}: one server runs it, or the others drifted"
                 for w, names in sorted(missing.items()) if names)


def read_jobs(files, d, patterns, at=None):
    """Imported: the jobs Linux servers' crontabs and systemd timers run."""
    folders = by_folder(files)
    placed = [(f, *server_named(d, f, _roles(d), "server")) for f in folders]
    found = [(s, *found_jobs(folders[f])) for f, s, _ in placed if s is not None]
    groups = grouped([(s, jobs) for s, jobs, _ in found])
    taken = {rdn_value(j).lower() for j in children(d, JOBS, "ciamJob")}

    def build(acc, item):
        entries, notices, names = acc
        key, found_on = item
        entry, ns = job_entry(d, key, found_on, patterns, names)
        return (*entries, entry), (*notices, *ns, *_partial(d, key, found_on)), names | {rdn_value(entry).lower()}
    entries, notices, _ = reduce(build, groups.items(), ((), (), taken))
    secrets = tuple(f"{rdn_value(s)} {path}:{n}: {name} is given a secret value in the crontab; not recorded: move it "
                    f"to a secret store" for s, _, assigns in found for path, n, name, value in assigns
                    if withheld(name, value, patterns))
    return Imported(
        containers=(jobs_container(),),
        groups=tuple((e.dn, (e,)) for e in entries),
        notices=(*(why for _, s, why in placed if s is None), *notices, *secrets,
                 *(("no server folders (one folder per server, named by its hostname, holding etc/crontab, "
                    "etc/cron.d/, var/spool/cron/, etc/systemd/system/)",) if not folders else ())))


JOBS_IMPORTER = Importer("jobs", "Linux servers' crontabs and systemd timers (one folder per server, named by its "
                                 "hostname, holding its files at their paths under /)", read_jobs)

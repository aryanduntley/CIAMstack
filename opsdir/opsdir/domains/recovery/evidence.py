"""What an environment shows against a recovery objective: the best point it can recover a role's data to after a
disaster that takes its region (how many minutes of changes are lost at worst, and what copied them out of the region;
a copy kept in the region is named, but lost with it) and the time a recovery took when someone last did
one (a restore test, a failover drill). The data domain says what copies a role and how restores went; the
infrastructure domain which environments join whose replication and where each runs. Pure."""
from collections import namedtuple

from ...core.directory import children, date_of, is_kind, norm_dn, one, rdn_value, values
from ...core.environment import env_model, one_role
from ...core.naming import env_label
from ..data.backups import protected_roles
from ..data.protection import schedule_of, words
from ..data.restores import tests_of
from ..data.volumes import VOLUME, runs_role
from .intent import joining, minutes, region_of
from .naming import DRILLS

DRILL = "ciamFailoverDrill"
# How far behind the failure a managed database's point-in-time restore reaches at worst: its transaction logs are
# shipped every few minutes (RDS's latest restorable time lags by up to five)
PITR_MINUTES = 5

# What an environment shows against an objective: minutes (of changes lost at worst, or until recovered) and what
# gives them, in words.
Evidence = namedtuple("Evidence", ("minutes", "how"))


def server_role(m, role):
    """The role of the servers holding a role's data in environment m: a volume's ciamTargetRole, else the role."""
    b = one_role(m, role)
    return one(b, "ciamTargetRole") if b is not None and VOLUME in b.classes else role


def _replicas(d, m, role, here):
    """Copies kept current in another region: environments joining m's replication deployment that run the servers
    holding the role's data. (Evidence, copied out of m's region) pairs."""
    servers = server_role(m, role)
    found = []
    for e in joining(d, m.dn):
        there = region_of(d, e.dn)
        other = env_model(d, e.dn)
        if here and there and there != here and runs_role(other, servers):
            found.append((Evidence(0, f"replicated to {other.label} in {there}"), True))
    return found


def _away(regions, here):
    """The copy regions other than here (an environment's own region)."""
    return tuple(r for r in regions if r != here)


def _every(hours):
    return "every hour" if hours == 1 else f"every {hours} hours"


def _copied(away, what="copied"):
    return f", {what} to {', '.join(away)}" if away else ""


def _copies(d, m, role, here):
    """What the role's own binding keeps: an object store's replica (in another region by its description), a
    database's point-in-time restore (out of the region only when its backups are copied to another region)."""
    b = one_role(m, role)
    if b is None:
        return []
    if one(b, "ciamStorageReplicaRef"):
        return [(Evidence(0, f"replicated to {one(b, 'ciamStorageReplicaRef')}"), True)]
    if is_kind(d, b, "ciamDatabase") and one(b, "ciamDbPointInTime") == "TRUE":
        away = _away(values(b, "ciamCopyRegion"), here)
        return [(Evidence(PITR_MINUTES, f"point-in-time restore{_copied(away, 'backups copied')}"), bool(away))]
    return []


def _schedules(m, role, here):
    """Each snapshot policy or backup plan copying the role: its interval, out of the region when it copies to
    another region."""
    def pair(p):
        s, away = schedule_of(p), _away(schedule_of(p).copies, here)
        return (Evidence(s.every * 60, f"{words(p).label.lower()} `{one(p, 'ciamBindingRole')}` {_every(s.every)}"
                                       f"{_copied(away)}"), bool(away))
    return [pair(p) for p in protected_roles(m).get(role, ())]


def _points(d, m, role):
    here = region_of(d, m.dn)
    return [*_replicas(d, m, role, here), *_copies(d, m, role, here), *_schedules(m, role, here)]


def recovery_point(d, m, role):
    """The best Evidence of how little of a role's data environment m loses in a disaster that takes its region:
    replication into an environment in another region (nothing at worst beyond what was in flight), an object-store
    replica, a database's point-in-time restore whose backups are copied to another region, or the interval of a
    snapshot policy or backup plan copying it to another region; None when nothing copies it out of its region."""
    found = [e for e, away in _points(d, m, role) if away]
    return min(found, key=lambda e: e.minutes) if found else None


def regional_points(d, m, role):
    """What copies a role's data in environment m without leaving its region (a point-in-time restore or a schedule
    copying nowhere else): a regional disaster loses them with the data."""
    return tuple(e for e, away in _points(d, m, role) if not away)


def failover_drills(d):
    """Every failover-drill record, newest first."""
    return tuple(sorted(children(d, DRILLS, DRILL),
                        key=lambda e: (str(date_of(e, "ciamDrilledOn") or ""), rdn_value(e)), reverse=True))


def drills_from(d, env_dn, role):
    """The failover drills from an environment (its DN) that verified a role (every role, when a drill names none),
    newest first."""
    n = norm_dn(env_dn)
    return tuple(e for e in failover_drills(d) if norm_dn(one(e, "ciamDrillFrom") or "") == n
                 and (not values(e, "ciamRecoversRole") or role in values(e, "ciamRecoversRole")))


def _latest_passed(entries, result):
    return next((e for e in entries if one(e, result) == "passed"), None)


def recovery_time(d, m, role):
    """The best Evidence of how fast environment m recovered a role: its latest passed restore test's minutes, or its
    latest passed failover drill's minutes until service was back; None when neither recorded any."""
    test = _latest_passed(tests_of(d, m.dn, role), "ciamTestResult")
    drill = _latest_passed(drills_from(d, m.dn, role), "ciamDrillResult")
    found = [*([Evidence(minutes(test, "ciamRestoreMinutes"), f"restore test {date_of(test, 'ciamTestedOn')}")]
               if minutes(test, "ciamRestoreMinutes") is not None else []),
             *([Evidence(minutes(drill, "ciamServiceMinutes"), f"failover drill {date_of(drill, 'ciamDrilledOn')} to "
                                                               f"{env_label(one(drill, 'ciamDrillTo'))}")]
               if minutes(drill, "ciamServiceMinutes") is not None else [])]
    return min(found, key=lambda e: e.minutes) if found else None

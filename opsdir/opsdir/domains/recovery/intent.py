"""Disaster-recovery intent: the recovery objectives (how long each protected role may be down, how much of what it
holds may be lost) and the standby environments (which environment each takes over from, how ready it is kept, where
it runs, the runbook that fails over to it). Pure."""
from ...core.directory import children, follow, get, norm_dn, one, rdn_value, subtree, values
from ...core.naming import branch
from .naming import OBJECTIVES

OBJECTIVE, STANDBY = "ciamRecoveryObjective", "ciamStandby"


def objectives(d):
    """Every recovery objective, by name."""
    return tuple(sorted(children(d, OBJECTIVES, OBJECTIVE), key=rdn_value))


def minutes(e, attr):
    """An entry's minutes (ciamRtoMinutes, ciamServiceMinutes, ...) as a number, or None when it holds none."""
    v = one(e, attr) if e is not None else None
    return int(v) if v else None


def environments(d):
    """Every environment of the estate, by DN."""
    return tuple(subtree(d, branch("environments"), "ciamEnvironment"))


def _naming(d, attr, env_dn):
    n = norm_dn(env_dn)
    return tuple(e for e in environments(d) if norm_dn(one(e, attr) or "") == n)


def standbys_of(d, env_dn):
    """The environments standing by for an environment (its DN)."""
    return tuple(e for e in _naming(d, "ciamStandbyOf", env_dn) if STANDBY in e.classes)


def primary_of(d, env):
    """The environment a standby environment takes over from, or None when it stands by for none."""
    return follow(d, env, "ciamStandbyOf") if STANDBY in env.classes else None


def joining(d, env_dn):
    """The environments whose replicas join an environment's replication deployment (ciamJoinsDeploymentOf)."""
    return _naming(d, "ciamJoinsDeploymentOf", env_dn)


def region_of(d, env_dn):
    """The region an environment runs in (its cloud's ciamRegion), or None."""
    cloud = get(d, env_dn.split(",", 1)[1])
    return one(cloud, "ciamRegion") if cloud is not None else None


def runbooks(d, e):
    """The runbooks an entry names (ciamRunbookRef) that the record holds."""
    return tuple(r for r in (get(d, v) for v in values(e, "ciamRunbookRef")) if r is not None)

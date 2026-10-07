"""The recovery reports: each objective against every environment running its roles (the recovery time shown against
its RTO, the best recovery point against its RPO, who stands by), the standby environments (whose, how ready, where,
which deployment they join, the runbook failing over to them), and the failover drills. Pure."""
from ...core.directory import date_of, one, rdn_of, rdn_value, values
from ...core.environment import env_model
from ...core.findings import owner_label
from ...core.naming import env_label
from ..data.backups import holds_role
from .evidence import failover_drills, recovery_point, recovery_time, regional_points
from .intent import STANDBY, environments, objectives, primary_of, region_of, standbys_of

RECOVERY_HEADERS = ("objective", "role", "environment", "RTO minutes", "recovered in", "RPO minutes", "recovery point",
                    "standby", "runbook")
STANDBY_HEADERS = ("environment", "stands by for", "mode", "region", "primary's region", "joins", "runbook")
DRILL_HEADERS = ("drilled on", "from", "to", "roles", "result", "service minutes", "data loss minutes", "runbook",
                 "owner")


def _runbook(e):
    return ", ".join(rdn_of(r) for r in values(e, "ciamRunbookRef"))


def _shown(evidence, local=()):
    if evidence is not None:
        return f"{evidence.minutes} ({evidence.how})"
    return f"none out of its region ({'; '.join(e.how for e in local)})" if local else "none recorded"


def recovery_rows(d, dn=None):
    """One row per recovery objective, role it names and environment running that role."""
    models = [env_model(d, e.dn) for e in environments(d)]
    return [(rdn_value(o), role, m.label, one(o, "ciamRtoMinutes") or "", _shown(recovery_time(d, m, role)),
             one(o, "ciamRpoMinutes") or "", _shown(recovery_point(d, m, role), regional_points(d, m, role)),
             ", ".join(env_label(s.dn) for s in standbys_of(d, m.dn)), _runbook(o))
            for o in objectives(d) for role in values(o, "ciamRecoversRole") for m in models if holds_role(m, role)]


def standby_rows(d, dn=None):
    """One row per standby environment."""
    def row(e):
        primary = primary_of(d, e)
        return (env_label(e.dn), env_label(primary.dn) if primary is not None else one(e, "ciamStandbyOf"),
                one(e, "ciamStandbyMode") or "", region_of(d, e.dn) or "",
                region_of(d, primary.dn) or "" if primary is not None else "",
                env_label(one(e, "ciamJoinsDeploymentOf")) if one(e, "ciamJoinsDeploymentOf") else "", _runbook(e))
    return [row(e) for e in environments(d) if STANDBY in e.classes]


def drill_rows(d, dn=None):
    """One row per failover drill, newest first."""
    return [(str(date_of(e, "ciamDrilledOn") or ""), env_label(one(e, "ciamDrillFrom")),
             env_label(one(e, "ciamDrillTo")), ", ".join(values(e, "ciamRecoversRole")) or "all",
             one(e, "ciamDrillResult"), one(e, "ciamServiceMinutes") or "", one(e, "ciamDataLossMinutes") or "",
             _runbook(e), owner_label(d, e) if values(e, "ciamOwner") else "")
            for e in failover_drills(d)]

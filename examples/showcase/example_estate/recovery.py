"""Disaster-recovery fixture data (data file 87-recovery; STANDBY_INTENT is used by infrastructure for the standby's
own entry): what the estate promises for the directory's data and what shows it holds.

  objective   directory-data: the directory's data volume back within 120 minutes of a disaster, at most 60 minutes
              of changes lost; recovered by restoring a volume (WI-CIAM-015) or failing over to the standby
              (WI-CIAM-016)
  source      meets it: its directory replicas replicate into the standby in us-central1 (and the target in eastus2),
              its restore test took 95 minutes and its failover drill 45 with nothing lost
  standby     a warm standby of production (ciamStandby on its environment), failed over to by WI-CIAM-016
  target      planted: nothing stands by for it (the standby still stands by for production: re-pointing it is the
              plan's fix) and nothing copies its directory data out of its region (its disk backup, CHG-2019, stays
              in eastus2: a copy in the region is lost with it)
"""
from .common import AWS, GCP, R, RB, owner, spec, t

RECOVERY, DRILLS = f"ou=recovery,{R}", f"ou=failover-drills,{R}"
# what the standby's environment entry says of itself (infrastructure adds it to the entry)
STANDBY_INTENT = {"ciamStandbyOf": AWS, "ciamStandbyMode": "warm", "ciamRunbookRef": f"cn=WI-CIAM-016,{RB}"}
# failover drills done: (cn, date, from, to, result, minutes until service, minutes of changes lost, what was done)
DRILLS_DONE = (
    ("FD-2026-09-10-standby", "2026-09-10", AWS, GCP, "passed", 45, 0,
     "production's directory traffic moved to the standby's replicas and PingFederate there by WI-CIAM-016 in the "
     "Sunday maintenance window; sign-ins verified, then moved back"),
)


def entries():
    return (spec("87-recovery", f"cn=directory-data,{RECOVERY}", ["top", "ciamRecoveryObjective"], cn="directory-data",
                 ciamRecoversRole="volume-ds-data", ciamRtoMinutes=120, ciamRpoMinutes=60,
                 ciamRunbookRef=[f"cn=WI-CIAM-015,{RB}", f"cn=WI-CIAM-016,{RB}"], ciamOwner=owner("ciam-platform"),
                 description="The directory's data: back within two hours of a disaster, at most an hour of changes "
                             "lost"),
            *(spec("87-recovery", f"cn={cn},{DRILLS}", ["top", "ciamFailoverDrill"], cn=cn,
                   ciamDrilledOn=t(on, "060000"), ciamDrillFrom=frm, ciamDrillTo=to, ciamDrillResult=result,
                   ciamServiceMinutes=service, ciamDataLossMinutes=lost, ciamRecoversRole="volume-ds-data",
                   ciamRunbookRef=f"cn=WI-CIAM-016,{RB}", description=what, ciamOwner=owner("ciam-platform"))
              for cn, on, frm, to, result, service, lost, what in DRILLS_DONE))

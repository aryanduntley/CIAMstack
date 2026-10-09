"""Recovery domain vocabulary: how ready a standby environment is kept, how a failover drill went, and where the
recovery records live."""

from ...core.naming import branch

# how ready a standby is to take over, most ready first: serving already (hot), running with less capacity (warm), its
# data kept current but its servers mostly stopped (pilot-light), built only when needed (cold)
STANDBY_MODES = ("hot", "warm", "pilot-light", "cold")
DRILL_RESULTS = ("passed", "partial", "failed")
OBJECTIVES = branch("recovery")              # the recovery objectives (ciamRecoveryObjective), one per protected
                                             # service
DRILLS = branch("failover-drills")           # the failover-drill records (ciamFailoverDrill), one entry per drill

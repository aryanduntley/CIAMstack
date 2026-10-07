"""Recovery domain schema: what disaster recovery promises and what shows it holds. A recovery objective (under
ou=recovery) is the estate's promise for the roles it names: how long what they serve may be down after a disaster
(RTO) and how much of what they hold may be lost (RPO), and the runbook that recovers them; every environment running
those roles is held to it. A standby environment says so on its own entry (the auxiliary class ciamStandby): the
environment it takes over from, how ready it is kept and the runbook that fails over to it; its region is its cloud's.
A failover drill (under ou=failover-drills) is the record of one failover someone did: from where to where, how it
went, how long until service was back and how much was lost."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import DRILL_RESULTS, STANDBY_MODES

ATTRIBUTES = (
    AttributeDef(471, 'ciamRecoversRole', 'string', 'meta', False,
                 'A role a recovery objective or failover drill is about: a volume, a database, an object store, the '
                 'servers of a role'),
    AttributeDef(472, 'ciamRtoMinutes', 'int', 'meta', True,
                 'Recovery time objective: how long what a role serves may be unavailable after a disaster, in '
                 'minutes', (("X-MIN", "1"),)),
    AttributeDef(473, 'ciamRpoMinutes', 'int', 'meta', True,
                 'Recovery point objective: how much of what a role holds may be lost in a disaster, in minutes of '
                 'changes (0: nothing)', (("X-MIN", "0"),)),
    AttributeDef(474, 'ciamStandbyOf', 'dn', 'intent', True,
                 'The environment a standby environment takes over from in a disaster (its primary)'),
    AttributeDef(475, 'ciamStandbyMode', enum_type(STANDBY_MODES), 'intent', True,
                 'How ready a standby is kept: serving already (hot), running with less capacity (warm), its data '
                 'kept current but its servers mostly stopped (pilot-light), built only when needed (cold)'),
    AttributeDef(476, 'ciamDrilledOn', 'time', 'meta', True,
                 'When a failover drill was done'),
    AttributeDef(477, 'ciamDrillFrom', 'dn', 'meta', True,
                 'The environment a failover drill failed over from'),
    AttributeDef(478, 'ciamDrillTo', 'dn', 'meta', True,
                 'The environment a failover drill failed over to'),
    AttributeDef(479, 'ciamDrillResult', enum_type(DRILL_RESULTS), 'meta', True,
                 'How a failover drill went: passed (service back and verified), partial (back, but something was '
                 'missing or wrong), failed'),
    AttributeDef(480, 'ciamServiceMinutes', 'int', 'meta', True,
                 'How long a failover drill took, in minutes, until service was back from the environment failed '
                 'over to (the recovery time it measured)', (("X-MIN", "0"),)),
    AttributeDef(481, 'ciamDataLossMinutes', 'int', 'meta', True,
                 'How many minutes of changes a failover drill lost (the recovery point it measured; 0: none)',
                 (("X-MIN", "0"),)),
)
CLASSES = (
    ClassDef(100, 'ciamRecoveryObjective', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamRecoversRole'),
             ('ciamRtoMinutes', 'ciamRpoMinutes', 'ciamRunbookRef'),
             "A recovery objective (under ou=recovery): for the roles it names, how long what they serve may be down "
             "after a disaster (RTO), how much of what they hold may be lost (RPO) and the runbook that recovers "
             "them; every environment running them is held to it"),
    ClassDef(101, 'ciamStandby', 'top', 'AUXILIARY', ('ciamStandbyOf',), ('ciamStandbyMode', 'ciamRunbookRef'),
             "Added to an environment that stands by for another: the environment it takes over from, how ready it "
             "is kept and the runbook that fails over to it"),
    ClassDef(102, 'ciamFailoverDrill', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamDrilledOn', 'ciamDrillFrom',
                                                                     'ciamDrillTo', 'ciamDrillResult'),
             ('ciamServiceMinutes', 'ciamDataLossMinutes', 'ciamRecoversRole', 'ciamRunbookRef'),
             "One failover drill (under ou=failover-drills): when, from which environment to which, the roles it "
             "verified (all when none is named), how it went, how long until service was back and how much was "
             "lost"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)

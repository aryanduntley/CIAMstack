"""Recovery domain: disaster recovery as intent and evidence. Recovery objectives promise, for the roles they name, how
long what they serve may be down after a disaster (RTO) and how much of what they hold may be lost (RPO); standby
environments say whose they are, how ready they are kept and which runbook fails over to them; failover drills record
how failovers went. The planner holds both environments of a move to the objectives (the data domain's backups,
replicas and restore tests, the infrastructure domain's replication and regions are the evidence) and moves the
standbys and failover routing with it. Nothing is rendered: what realizes recovery (backups, replication, failover
records) belongs to the domains that own it. Vendor-neutral."""
from ...core.contract import Domain, directory_report
from .checks import check_recovery
from .reports import DRILL_HEADERS, RECOVERY_HEADERS, STANDBY_HEADERS, drill_rows, recovery_rows, standby_rows
from .schema import FRAGMENT

DOMAIN = Domain(name="recovery", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"recovery": directory_report(RECOVERY_HEADERS, recovery_rows),
                         "standbys": directory_report(STANDBY_HEADERS, standby_rows),
                         "failover-drills": directory_report(DRILL_HEADERS, drill_rows)},
                checks=(check_recovery,), order=70, vocabulary={})

"""Directory domain: a vendor-neutral LDAP user directory. Its declared and observed server configuration
(backends, indexes, password policies, connection handlers, log publishers, replication), the records
describing user attributes, the consumers that bind to it, and the ACIs that grant them access.
Product adapters render and import it."""
from pathlib import Path

from ...core.contract import Domain, directory_report, sql_report
from ...core.directory import children, rdn_value
from .checks import check_consumers, check_hygiene
from .drift import DRIFT_HEADERS, drift
from .naming import CONSUMERS, DIRECTORY_SERVER_ROLE
from .schema import FRAGMENT

PII_SQL = ("select attribute, pii_class, export_controlled, consumer, owner, aci, justification"
           " from v_pii_exposure order by pii_class, attribute, consumer")
PII_HEADERS = ("attribute", "pii", "export", "consumer", "owner", "aci", "justification")


def consumers_of_role(d, target_role):
    """Names of the consumers that use a service with this target role, or None if that is not the directory."""
    if target_role != DIRECTORY_SERVER_ROLE:
        return None
    return [rdn_value(c) for c in children(d, CONSUMERS, "ciamConsumer")]


def _drift_rows(d, dn):
    return drift(d)


DOMAIN = Domain(name="directory", schema=FRAGMENT, required_roles=(),
                sql=(Path(__file__).parent / "sql" / "directory.sql",),
                reports={"pii": sql_report(PII_HEADERS, PII_SQL), "drift": directory_report(DRIFT_HEADERS, _drift_rows)},
                checks=(check_consumers, check_hygiene), order=20,
                vocabulary={"ciamServerRole": (DIRECTORY_SERVER_ROLE,), "ciamTargetRole": (DIRECTORY_SERVER_ROLE,)})

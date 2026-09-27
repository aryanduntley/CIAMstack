"""Directory domain: a vendor-neutral LDAP user directory. Its declared and observed server configuration
(backends, indexes, password policies, connection handlers, log publishers, replication), the records
describing user attributes, the consumers that bind to it, and the ACIs that grant them access.
Product adapters (e.g. PingDS) render and import it."""
from pathlib import Path

from ...core.contract import Domain, Report
from ...core.directory import children, rdn_value
from ...store.postgres import load_directory
from ...store.queries import fetch_rows
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


def _pii_rows(conn, dn):
    return fetch_rows(conn, PII_SQL)


def _drift_rows(conn, dn):
    return drift(load_directory(conn))


DOMAIN = Domain(name="directory", schema=FRAGMENT, required_roles=(),
                sql=(Path(__file__).parent / "sql" / "directory.sql",),
                reports={"pii": Report(PII_HEADERS, _pii_rows), "drift": Report(DRIFT_HEADERS, _drift_rows)})

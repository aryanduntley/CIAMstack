"""PKI domain: certificates as public facts (fingerprint, validity, SANs, purpose, key role, who uses them)."""
from pathlib import Path

from ...core.contract import Domain, Report
from ...core.naming import branch
from ...store.queries import fetch_rows
from .schema import FRAGMENT

CERTIFICATES = branch("certificates")

EXPIRING_SQL = ("select cert, purpose, not_after, days_left, array_to_string(names, ','),"
                " (select string_agg(split_part(split_part(u, ',', 1), '=', 2), ',') from unnest(used_by) u)"
                " from v_certificates order by not_after")
EXPIRING_HEADERS = ("certificate", "purpose", "not_after", "days_left", "names", "used_by")


def _expiring_rows(conn, dn):
    return fetch_rows(conn, EXPIRING_SQL)


DOMAIN = Domain(name="pki", schema=FRAGMENT, required_roles=(), sql=(Path(__file__).parent / "sql" / "pki.sql",),
                reports={"expiring": Report(EXPIRING_HEADERS, _expiring_rows)})

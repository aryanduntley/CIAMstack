"""PKI domain: certificates as public facts (fingerprint, validity, SANs, purpose, key role, who uses them)."""
from pathlib import Path

from ...core.contract import Domain, sql_report
from .checks import check_certificates
from .schema import FRAGMENT

EXPIRING_SQL = ("select cert, purpose, not_after, days_left, array_to_string(names, ','),"
                " (select string_agg(split_part(split_part(u, ',', 1), '=', 2), ',') from unnest(used_by) u)"
                " from v_certificates order by not_after")
EXPIRING_HEADERS = ("certificate", "purpose", "not_after", "days_left", "names", "used_by")

DOMAIN = Domain(name="pki", schema=FRAGMENT, required_roles=(), sql=(Path(__file__).parent / "sql" / "pki.sql",),
                reports={"expiring": sql_report(EXPIRING_HEADERS, EXPIRING_SQL)}, checks=(check_certificates,), order=40,
                vocabulary={})

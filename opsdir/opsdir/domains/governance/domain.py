"""Governance domain: owners (parties), change records, incidents and work instructions."""
from pathlib import Path

from ...core.contract import Domain, directory_report, sql_report
from ...core.directory import children, one, rdn_value
from .imports import IMPORT_HEADERS, import_rows
from .naming import OWNERS
from .schema import FRAGMENT

STALE_SQL = "select runbook, title, last_validated, changed_on, changed_dependency from v_stale_runbooks"
STALE_HEADERS = ("runbook", "title", "validated", "dep_changed", "dependency")


def display_name(e):
    """How a party is named in correspondence: its display name, else its RDN."""
    return one(e, "ciamDisplayName") or rdn_value(e)


def operator(d):
    """The party that operates the platform (ciamOwnerKind operator), if the directory records one."""
    return next((p for p in children(d, OWNERS, "ciamParty") if one(p, "ciamOwnerKind") == "operator"), None)


DOMAIN = Domain(name="governance", schema=FRAGMENT, required_roles=(), sql=(Path(__file__).parent / "sql" / "governance.sql",),
                reports={"stale": sql_report(STALE_HEADERS, STALE_SQL),
                         "imports": directory_report(IMPORT_HEADERS, import_rows)}, checks=(), order=50,
                vocabulary={})

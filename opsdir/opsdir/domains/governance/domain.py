"""Governance domain: owners (parties), change records, incidents, work instructions and the unknowns register (the
questions the record can't answer yet, which the planner counts: unknowns.py)."""
from pathlib import Path

from ...core.contract import Domain, directory_report, sql_report
from ...core.directory import children, one, rdn_value
from .attempts import ATTEMPT_HEADERS, attempt_rows
from .collection import collection_roles
from .imports import IMPORT_HEADERS, import_rows
from .naming import OWNERS
from .schema import FRAGMENT
from .settings import SETTINGS
from .unknowns import UNKNOWN_HEADERS, check_unknowns, unknown_rows

STALE_SQL = "select runbook, title, last_validated, changed_on, changed_dependency from v_stale_runbooks"
STALE_HEADERS = ("runbook", "title", "validated", "dep_changed", "dependency")


def display_name(e):
    """How a party is named in correspondence: its display name, else its RDN."""
    return one(e, "ciamDisplayName") or rdn_value(e)


def operator(d):
    """The party that operates the platform (ciamOwnerKind operator), if the directory records one."""
    return next((p for p in children(d, OWNERS, "ciamParty") if one(p, "ciamOwnerKind") == "operator"), None)


DOMAIN = Domain(name="governance", schema=FRAGMENT, required_roles=(),
                sql=(Path(__file__).parent / "sql" / "governance.sql",),
                reports={"stale": sql_report(STALE_HEADERS, STALE_SQL),
                         "imports": directory_report(IMPORT_HEADERS, import_rows),
                         "collections": directory_report(ATTEMPT_HEADERS, attempt_rows),
                         "unknowns": directory_report(UNKNOWN_HEADERS, unknown_rows, dated=True)},
                checks=(check_unknowns,), order=50,
                vocabulary={}, settings=SETTINGS, roles_used=collection_roles)

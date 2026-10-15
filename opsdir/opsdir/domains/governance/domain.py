"""Governance domain: owners (parties), change records, incidents, work instructions, the unknowns register (the
questions the record can't answer yet, which the planner counts: unknowns.py) and the ITSM tickets change records are
tracked by, read as evidence (tickets.py)."""
from pathlib import Path

from ...core.contract import Domain, directory_report, sql_report
from .attempts import ATTEMPT_HEADERS, attempt_rows
from .collection import collection_roles
from .imports import IMPORT_HEADERS, import_rows
from .parties import display_name, operator  # noqa: F401  (re-exported: the planner and estate name parties by them)
from .schema import FRAGMENT
from .settings import SETTINGS
from .tickets import TICKET_HEADERS, check_tickets, ticket_rows
from .unknowns import UNKNOWN_HEADERS, check_unknowns, unknown_rows

STALE_SQL = "select runbook, title, last_validated, changed_on, changed_dependency from v_stale_runbooks"
STALE_HEADERS = ("runbook", "title", "validated", "dep_changed", "dependency")


DOMAIN = Domain(name="governance", schema=FRAGMENT, required_roles=(),
                sql=(Path(__file__).parent / "sql" / "governance.sql",),
                reports={"stale": sql_report(STALE_HEADERS, STALE_SQL),
                         "imports": directory_report(IMPORT_HEADERS, import_rows),
                         "collections": directory_report(ATTEMPT_HEADERS, attempt_rows),
                         "unknowns": directory_report(UNKNOWN_HEADERS, unknown_rows, dated=True),
                         "tickets": directory_report(TICKET_HEADERS, ticket_rows)},
                checks=(check_unknowns, check_tickets), order=50,
                vocabulary={}, settings=SETTINGS, roles_used=collection_roles)

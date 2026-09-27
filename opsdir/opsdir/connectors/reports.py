"""The report catalogue: every question the directory answers, gathered from the store, the domains and the
cross-domain views, and run against the store. A connector: each report's query lives with the part that owns it;
here it is only composed and executed."""
import sys

from ..core.contract import fetch_report, sql_report
from ..store.postgres import load_directory
from ..store.queries import fetch_blast_radius, fetch_rows
from .registry import DOMAINS

PORTABILITY = sql_report(("portability", "values"), "select * from v_portability")
UNOWNED = sql_report(("dn", "kind", "problem"), "select dn, kind, problem from v_unowned order by 1")
BLAST_RADIUS = fetch_report(("depth", "dependent", "via", "owner"), fetch_blast_radius, needs_dn=True)
HISTORY_HEADERS = ("at", "change", "op", "dn")


def catalogue(domains=DOMAINS):
    """report name → Report: store reports, every domain's reports, cross-domain reports."""
    return {"portability": PORTABILITY, "blast-radius": BLAST_RADIUS,
            **{name: r for domain in domains for name, r in domain.reports.items()}, "unowned": UNOWNED}


def run_report(conn, report, dn=None):
    """Effect: a report's rows, from whichever source it declares."""
    if report.sql:
        return fetch_rows(conn, report.sql, (dn,) if report.needs_dn else ())
    if report.from_directory:
        return report.from_directory(load_directory(conn), dn)
    return report.fetch(conn, dn)


def report_rows(conn, name, dn=None):
    """Effect: (rows, headers) of a named report; exits on an unknown name or a missing DN."""
    reports = catalogue()
    if name not in reports:
        sys.exit(f"unknown report {name}")
    if reports[name].needs_dn and not dn:
        sys.exit(f"usage: opsdir report {name} DN")
    return run_report(conn, reports[name], dn), reports[name].headers

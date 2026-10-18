"""The report catalogue: every question the directory answers, gathered from the store, the domains and the
cross-domain views, and run against the store. A connector: each report's query lives with the part that owns it;
here it is only composed and executed."""
import datetime as dt
import sys

from ..core.contract import fetch_report, sql_report
from ..domains.governance.naming import CHANGES
from ..store.postgres import load_directory
from ..store.queries import fetch_blast_radius, fetch_change_writes, fetch_rows
from .keys import keys_report
from .network import ports_report
from .observability import coverage_report, log_collection_report
from .secret_inventory import secret_inventory_report
from .registry import DOMAINS
from .settings import SETTINGS_REPORT

PORTABILITY = sql_report(("portability", "values"), "select * from v_portability")
UNOWNED = sql_report(("dn", "kind", "problem"), "select dn, kind, problem from v_unowned order by 1")
BLAST_RADIUS = fetch_report(("depth", "dependent", "via", "owner"), fetch_blast_radius, needs_dn=True)
HISTORY_HEADERS = ("at", "change", "op", "by", "dn")


def catalogue(domains=DOMAINS):
    """report name → Report: store reports, every domain's reports, cross-domain reports (the ports matrix, from the
    installed adapters' listeners; where an environment keeps its keys, against the roles its installed adapters
    require; where its log routes' logs come from, with the log sources its adapters declare; which synthetic checks
    each environment renders, with its adapters; every secret reference against its store's inventory, with the
    adapters' locators; the estate settings every installed domain declares)."""
    return {"portability": PORTABILITY, "blast-radius": BLAST_RADIUS,
            **{name: r for domain in domains for name, r in domain.reports.items()}, "unowned": UNOWNED,
            "ports": ports_report(), "keys": keys_report(), "log-collection": log_collection_report(),
            "canary-coverage": coverage_report(), "secret-inventory": secret_inventory_report(),
            "settings": SETTINGS_REPORT}


def change_writes(conn, as_of):
    """Effect (reads history): {change id: (first, last, count)} of when each change record's writes landed, counted
    up to the end of the as_of day (UTC): a plan or report as of a day sees the writes landed by then."""
    until = dt.datetime.combine(as_of + dt.timedelta(days=1), dt.time.min, dt.timezone.utc)
    return fetch_change_writes(conn, until, CHANGES)


def run_report(conn, report, dn=None, as_of=None):
    """Effect: a report's rows, from whichever source it declares; a dated directory report evaluates dates as of
    as_of (a date; today when not given), as the SQL reports do, and one with the record's writes is given them as
    the history holds them up to that day's end."""
    if report.sql:
        return fetch_rows(conn, report.sql, (dn,) if report.needs_dn else ())
    if report.from_directory and report.writes:
        return report.from_directory(load_directory(conn), dn, change_writes(conn, as_of or dt.date.today()))
    if report.from_directory and report.dated:
        return report.from_directory(load_directory(conn), dn, as_of or dt.date.today())
    if report.from_directory:
        return report.from_directory(load_directory(conn), dn)
    return report.fetch(conn, dn)


def report_rows(conn, name, dn=None, as_of=None):
    """Effect: (rows, headers) of a named report; exits on an unknown name or a missing DN."""
    reports = catalogue()
    if name not in reports:
        sys.exit(f"unknown report {name}")
    if reports[name].needs_dn and not dn:
        sys.exit(f"usage: opsdir report {name} DN")
    return run_report(conn, reports[name], dn, as_of), reports[name].headers

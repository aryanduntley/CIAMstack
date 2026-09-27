"""The report catalogue: every question the directory answers, gathered from the store, the domains and the
cross-domain views. A connector: it only composes; each report's query lives with the part that owns it."""
import sys

from ..core.contract import Report
from ..store.queries import fetch_blast_radius, fetch_rows
from .registry import DOMAINS



def _portability_rows(conn, dn):
    return fetch_rows(conn, "select * from v_portability")


def _unowned_rows(conn, dn):
    return fetch_rows(conn, "select dn, kind, problem from v_unowned order by 1")


def _blast_radius_rows(conn, dn):
    return fetch_blast_radius(conn, dn)


PORTABILITY = Report(("portability", "values"), _portability_rows)
UNOWNED = Report(("dn", "kind", "problem"), _unowned_rows)
BLAST_RADIUS = Report(("depth", "dependent", "via", "owner"), _blast_radius_rows)
HISTORY_HEADERS = ("at", "change", "op", "dn")
NEEDS_DN = {"blast-radius"}


def catalogue():
    """report name → Report: store reports, every domain's reports, cross-domain reports."""
    return {"portability": PORTABILITY, "blast-radius": BLAST_RADIUS,
            **{name: r for domain in DOMAINS for name, r in domain.reports.items()}, "unowned": UNOWNED}


def report_rows(conn, name, dn=None):
    """Effect: (rows, headers) of a named report; exits on an unknown name or a missing DN."""
    reports = catalogue()
    if name not in reports:
        sys.exit(f"unknown report {name}")
    if name in NEEDS_DN and not dn:
        sys.exit(f"usage: opsdir report {name} DN")
    return reports[name].fetch(conn, dn), reports[name].headers

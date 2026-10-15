"""The estate in counts (milestone 6.4): what the record holds and what needs attention, each count with the evidence
it is made of: the entries it counts, by DN, or the command whose output it is (a plan's blockers). Counts only: no
health score or readiness percentage, which nothing the record holds measures. Pure.

  applications                       ciamApplication entries
  integrations, directory consumers  ciamIntegration, ciamConsumer entries
  certificates expiring              certificates whose ciamNotAfter is within the estate's certificate-expiry-margin-
                                     days of the date (expired ones included)
  pending changes                    change records proposed or approved, not yet applied
  incidents                          incident records
  awaiting import                    entries set ahead of the live system (ciamVerifyPending) until an import confirms
  blockers, actions, ok              a plan's findings, when a plan is given (its evidence: the plan command)
"""
import datetime as dt
from typing import NamedTuple

from ..core.directory import gtime_date, is_kind, one, values
from ..core.settings import setting_value
from ..domains.pki.settings import EXPIRY_MARGIN_DAYS

# what is counted, how many, and the evidence: the DNs counted, or the command that shows them
Count = NamedTuple("Count", [("what", str), ("count", int), ("evidence", tuple)])
PENDING = ("proposed", "approved")


def _of_class(d, oc):
    return tuple(sorted((e for e in d.entries.values() if is_kind(d, e, oc)), key=lambda e: e.dn))


def _counted(what, entries):
    return Count(what, len(entries), tuple(e.dn for e in entries))


def expiring_certificates(d, as_of):
    """The certificates whose ciamNotAfter is no later than as_of plus the estate's certificate-expiry-margin-days."""
    horizon = as_of + dt.timedelta(days=setting_value(d, EXPIRY_MARGIN_DAYS))
    return tuple(c for c in _of_class(d, "ciamCertificate")
                 if one(c, "ciamNotAfter") and gtime_date(one(c, "ciamNotAfter")) <= horizon)


def estate_counts(d, as_of):
    """(Count, ...) of record d on date as_of: applications, integrations, directory consumers, expiring
    certificates, pending changes, incidents, entries awaiting an import's confirmation."""
    return (_counted("applications", _of_class(d, "ciamApplication")),
            _counted("integrations", _of_class(d, "ciamIntegration")),
            _counted("directory consumers", _of_class(d, "ciamConsumer")),
            _counted(f"certificates expiring within {setting_value(d, EXPIRY_MARGIN_DAYS)} days",
                     expiring_certificates(d, as_of)),
            _counted("pending changes", tuple(c for c in _of_class(d, "ciamChange")
                                              if one(c, "ciamChangeStatus") in PENDING)),
            _counted("incidents", _of_class(d, "ciamIncident")),
            _counted("awaiting import", tuple(sorted((e for e in d.entries.values() if values(e, "ciamVerifyPending")),
                                                     key=lambda e: e.dn))))


def plan_counts(p):
    """(Count, ...) of a plan (connectors.plan.Plan): its blockers, actions and ok lines, evidenced by the plan command
    that lists them."""
    command = (f"opsdir plan {p.src.label} {p.dst.label}",)
    return (Count("blockers", len(p.blockers), command), Count("actions", len(p.actions), command),
            Count("ok", len(p.ok), command))

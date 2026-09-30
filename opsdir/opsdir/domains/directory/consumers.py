"""The consumers review list: every client of the user directory with what the access logs observed and what its
operators recorded, and what to check about it. A pure function of a snapshot, dated (ages are as of a day)."""
import datetime as dt

from ...core.directory import children, follow_all, get, gtime_date, one, rdn_value, referrers, values
from .naming import CONSUMERS

CONSUMERS_HEADERS = ("consumer", "bind DN", "owner", "criticality", "status", "TLS only", "sources", "unindexed/day",
                     "peak/s", "last seen", "reviewed", "to check")
UNSEEN_DAYS = 30         # not seen in the logs for longer than this: still in use?
REVIEW_DAYS = 365        # a review older than this is due again


def _date(v):
    return gtime_date(v) if v else None


def _owners(d, c):
    return ", ".join(rdn_value(get(d, o)) for o in values(c, "ciamOwner") if get(d, o))


def to_check(d, c, as_of):
    """What an operator should look at for one consumer, as short phrases."""
    seen, reviewed = _date(one(c, "ciamLastSeen")), _date(one(c, "ciamReviewedOn"))
    sensitive = [one(a, "ciamLdapName") for a in follow_all(d, c, "ciamAttrRead")
                 if a is not None and one(a, "ciamPiiClass") == "high"]
    unindexed = int(one(c, "ciamUnindexedSearchesPerDay", "0") or 0)
    checks = (("no owner", not values(c, "ciamOwner")),
              ("no criticality", not one(c, "ciamCriticality")),
              ("plain-text connections", one(c, "ciamTlsOnly") == "FALSE"),
              (f"{unindexed} unindexed searches/day", unindexed > 0),
              (f"reads high-PII attributes: {', '.join(sensitive)}", bool(sensitive)),
              ("no ACI grants its access", not any(True for _ in referrers(d, c, "ciamAciGrantee"))),
              ("never seen in access logs", seen is None),
              (f"not seen for {(as_of - seen).days} days" if seen else "", bool(seen)
               and (as_of - seen).days > UNSEEN_DAYS),
              ("never reviewed", reviewed is None),
              (f"review over a year old ({reviewed})", bool(reviewed) and (as_of - reviewed).days > REVIEW_DAYS))
    return "; ".join(phrase for phrase, applies in checks if applies)


def consumer_rows(d, dn=None, as_of=None):
    """One row per consumer: identity, what operators recorded, what the logs observed, and what to check."""
    day = as_of or dt.date.today()
    return [(one(c, "cn"), one(c, "ciamBindDn", ""), _owners(d, c), one(c, "ciamCriticality", ""),
             one(c, "ciamMigrationStatus", ""), {"TRUE": "yes", "FALSE": "no"}.get(one(c, "ciamTlsOnly"), ""),
             ", ".join(values(c, "ciamObservedSource")), one(c, "ciamUnindexedSearchesPerDay", ""),
             one(c, "ciamPeakOpsPerSec", ""), str(_date(one(c, "ciamLastSeen")) or ""),
             str(_date(one(c, "ciamReviewedOn")) or ""), to_check(d, c, day))
            for c in children(d, CONSUMERS, "ciamConsumer")]

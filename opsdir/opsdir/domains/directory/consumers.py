"""The consumers review list: every client of the user directory with what the access logs observed and what its
operators recorded, and what to check about it. A pure function of a snapshot, dated (ages are as of a day)."""
import datetime as dt

from ...core.directory import children, date_of, follow_all, get, one, rdn_value, referrers, values
from ...core.settings import setting_value
from .naming import CONSUMERS
from .settings import REVIEW_DAYS, UNSEEN_DAYS

CONSUMERS_HEADERS = ("consumer", "bind DN", "owner", "criticality", "status", "TLS only", "sources", "unindexed/day",
                     "peak/s", "last seen", "reviewed", "to check")


def consumer_by_bind_dn(d, bind_dn):
    """The consumer record whose ciamBindDn is bind_dn (case-insensitive), or None: how an importer links the account
    a product binds to the directory as (an IDM connector's principal, a PingFederate data store's user DN)."""
    return next((c for c in children(d, CONSUMERS, "ciamConsumer")
                 if bind_dn and (one(c, "ciamBindDn") or "").lower() == bind_dn.lower()), None)


def _owners(d, c):
    return ", ".join(rdn_value(get(d, o)) for o in values(c, "ciamOwner") if get(d, o))


def to_check(d, c, as_of):
    """What an operator should look at for one consumer, as short phrases."""
    seen, reviewed = date_of(c, "ciamLastSeen"), date_of(c, "ciamReviewedOn")
    unseen, every = setting_value(d, UNSEEN_DAYS), setting_value(d, REVIEW_DAYS)
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
               and (as_of - seen).days > unseen),
              ("never reviewed", reviewed is None),
              (f"review older than {every} days ({reviewed})", bool(reviewed) and (as_of - reviewed).days > every))
    return "; ".join(phrase for phrase, applies in checks if applies)


def consumer_rows(d, dn=None, as_of=None):
    """One row per consumer: identity, what operators recorded, what the logs observed, and what to check."""
    day = as_of or dt.date.today()
    return [(one(c, "cn"), one(c, "ciamBindDn", ""), _owners(d, c), one(c, "ciamCriticality", ""),
             one(c, "ciamMigrationStatus", ""), {"TRUE": "yes", "FALSE": "no"}.get(one(c, "ciamTlsOnly"), ""),
             ", ".join(values(c, "ciamObservedSource")), one(c, "ciamUnindexedSearchesPerDay", ""),
             one(c, "ciamPeakOpsPerSec", ""), str(date_of(c, "ciamLastSeen") or ""),
             str(date_of(c, "ciamReviewedOn") or ""), to_check(d, c, day))
            for c in children(d, CONSUMERS, "ciamConsumer")]

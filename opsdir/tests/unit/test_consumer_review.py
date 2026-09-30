"""The consumers review list: one row per consumer with what operators recorded and what the access logs observed,
and what to check (no owner or criticality, plain-text connections, unindexed searches, high-PII attributes read, no
ACI granting its access, not seen lately or never, never reviewed or reviewed too long ago), ages as of a day."""
import datetime as dt

from opsdir.core.directory import make_directory
from opsdir.domains.directory.consumers import CONSUMERS_HEADERS, consumer_rows
from opsdir.domains.directory.naming import ACIS, CONSUMERS, USER_SCHEMA

AS_OF = dt.date(2026, 9, 23)


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return make_directory((("ciamAciGrantee", "dn", "intent"), ("ciamAttrRead", "dn", "observed")), {}, (
        _row("cn=platform,ou=owners,dc=ciam-ops", ("ciamParty",), cn="platform"),
        _row(f"cn=mail,{USER_SCHEMA}", ("ciamUserAttribute",), cn="mail", ciamLdapName="mail", ciamPiiClass="moderate"),
        _row(f"cn=screening,{USER_SCHEMA}", ("ciamUserAttribute",), cn="screening", ciamLdapName="screening",
             ciamPiiClass="high"),
        _row(f"cn=app,{CONSUMERS}", ("ciamConsumer",), cn="app", ciamBindDn="uid=app,dc=example,dc=test",
             ciamOwner="cn=platform,ou=owners,dc=ciam-ops", ciamCriticality="high", ciamMigrationStatus="tested",
             ciamTlsOnly="TRUE", ciamObservedSource=["10.0.1.0/24", "10.0.2.7/32"], ciamUnindexedSearchesPerDay="0",
             ciamPeakOpsPerSec="40", ciamAttrRead=f"cn=mail,{USER_SCHEMA}", ciamLastSeen="20260922000000Z",
             ciamReviewedOn="20260302000000Z"),
        _row(f"cn=legacy,{CONSUMERS}", ("ciamConsumer",), cn="legacy", ciamBindDn="uid=legacy,dc=example,dc=test",
             ciamMigrationStatus="unknown", ciamTlsOnly="FALSE", ciamUnindexedSearchesPerDay="12",
             ciamAttrRead=[f"cn=mail,{USER_SCHEMA}", f"cn=screening,{USER_SCHEMA}"], ciamLastSeen="20260801000000Z",
             ciamReviewedOn="20250101000000Z"),
        _row(f"cn=quiet,{CONSUMERS}", ("ciamConsumer",), cn="quiet", ciamBindDn="uid=quiet,dc=example,dc=test",
             ciamOwner="cn=platform,ou=owners,dc=ciam-ops", ciamCriticality="low"),
        _row(f"cn=aci-app,{ACIS}", ("ciamAci",), cn="aci-app", ciamAciGrantee=f"cn=app,{CONSUMERS}"),
        _row(f"cn=aci-quiet,{ACIS}", ("ciamAci",), cn="aci-quiet", ciamAciGrantee=f"cn=quiet,{CONSUMERS}")))


def _by_name(rows):
    return {r[0]: dict(zip(CONSUMERS_HEADERS, r)) for r in rows}


def test_a_consumer_in_good_order_has_nothing_to_check():
    app = _by_name(consumer_rows(_record(), None, AS_OF))["app"]
    assert app == {"consumer": "app", "bind DN": "uid=app,dc=example,dc=test", "owner": "platform",
                   "criticality": "high", "status": "tested", "TLS only": "yes", "sources": "10.0.1.0/24, 10.0.2.7/32",
                   "unindexed/day": "0", "peak/s": "40", "last seen": "2026-09-22", "reviewed": "2026-03-02",
                   "to check": ""}


def test_everything_to_look_at_is_named():
    rows = _by_name(consumer_rows(_record(), None, AS_OF))
    assert rows["legacy"]["to check"] == (
        "no owner; no criticality; plain-text connections; 12 unindexed searches/day; reads high-PII attributes: "
        "screening; no ACI grants its access; not seen for 53 days; review over a year old (2025-01-01)")
    assert rows["quiet"]["to check"] == "never seen in access logs; never reviewed"

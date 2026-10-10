"""The kept-line clauses as KQL: rules as case-sensitive prefix tests on a JSON field (or the field being there),
excluded rules negated, clauses or'ed; true when a clause keeps everything, false when there are none."""
from opsdir.core.contract import LogSource
from opsdir.domains.observability.sources import kept_clauses
from opsdir_adapter_azure.kql import field_of, kept, literal

AM = LogSource("am", "kubernetes", None, "mixed", "debug",
               (("eventName", "AM-ACCESS-", "access"), ("eventName", "", "audit")))
FIELD = field_of("LogMessage")
EVENT = 'tostring(parse_json(LogMessage)["eventName"])'


def test_clauses_become_kql():
    assert kept(kept_clauses(AM, ("access",)), FIELD) == f'{EVENT} startswith_cs "AM-ACCESS-"'
    assert kept(kept_clauses(AM, ("audit",)), FIELD) == (
        f'isnotempty({EVENT}) and not({EVENT} startswith_cs "AM-ACCESS-")')
    assert kept(kept_clauses(AM, ("access", "debug")), FIELD) == (
        f'({EVENT} startswith_cs "AM-ACCESS-") or (not(isnotempty({EVENT})))')
    assert kept(kept_clauses(AM, ("access", "audit", "debug")), FIELD) == "true"
    assert kept(kept_clauses(AM, ("error",)), FIELD) == "false"


def test_literals_are_escaped():
    assert literal('a"b\\c') == '"a\\"b\\\\c"'

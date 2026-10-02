"""Observability entries in the store, against Postgres: alert rules, log routes, canaries and the channels and
destinations environments bind, and the alarms and checks a cloud runs, pass the store's rules (enums, duration and
threshold patterns, links), the reports read them back, and values the definitions don't allow are refused."""
import re

import pytest

from opsdir.connectors.registry import store_parts
from opsdir.core.interchange.ldif import parse
from opsdir.domains.observability.alerts import alert_rows, canary_rows
from opsdir.domains.observability.logs import log_rows
from opsdir.domains.observability.realized import monitor_rows
from opsdir.store import migrations, postgres as db

pytestmark = pytest.mark.integration

ENV = "env=prod,cloud=home,ou=environments,dc=ciam-ops"
BASE = f"""dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=environments,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: environments

dn: cloud=home,ou=environments,dc=ciam-ops
objectClass: top
objectClass: ciamCloud
cloud: home
ciamCloudProvider: aws
ciamRegion: region-1

dn: {ENV}
objectClass: top
objectClass: ciamEnvironment
env: prod

dn: ou=bindings,{ENV}
objectClass: top
objectClass: organizationalUnit
ou: bindings

dn: cn=page,ou=bindings,{ENV}
objectClass: top
objectClass: ciamAlertChannel
cn: page
ciamBindingRole: alerts-page
ciamChannelKind: topic
ciamProviderRef: arn:aws:sns:region-1:111122223333:page

dn: cn=audit,ou=bindings,{ENV}
objectClass: top
objectClass: ciamLogDestination
cn: audit
ciamBindingRole: audit-logs
ciamDestinationKind: log-group
ciamRetentionDays: 400

dn: ou=alert-rules,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: alert-rules

dn: ou=log-routes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: log-routes

dn: ou=canaries,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: canaries
"""
RULE = """dn: cn=replication-lag,ou=alert-rules,dc=ciam-ops
objectClass: top
objectClass: ciamObject
objectClass: ciamAlertRule
cn: replication-lag
ciamSignal: replication-delay
ciamComparison: gt
ciamThreshold: 5000 ms
ciamEvaluationPeriod: 5m
ciamSeverity: sev2
ciamAlertRole: alerts-page
"""
OTHERS = """dn: cn=audit,ou=log-routes,dc=ciam-ops
objectClass: top
objectClass: ciamObject
objectClass: ciamLogRoute
cn: audit
ciamLogKind: audit
ciamLogKind: admin
ciamLogDestinationRole: audit-logs
ciamRetentionDays: 365
ciamLegalHold: TRUE

dn: cn=login,ou=canaries,dc=ciam-ops
objectClass: top
objectClass: ciamObject
objectClass: ciamCanary
cn: login
ciamCheckedService: login-service
ciamCanaryFlow: oidc-token
ciamInterval: 5m
ciamFeedsAlert: cn=replication-lag,ou=alert-rules,dc=ciam-ops
"""


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    migrations.init(c, *store_parts())
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def test_observability_entries_are_stored_and_reported(conn):
    db.load_records(conn, parse(RULE + "\n" + OTHERS))
    d = db.load_directory(conn)
    assert alert_rows(d)[0][:6] == ("replication-lag", "replication-delay", "", "gt 5000 ms for 5m", "sev2",
                                    "alerts-page")
    assert log_rows(d) == [("audit", "audit, admin", "", "audit-logs", "365", "yes")]
    assert canary_rows(d)[0][-1] == "replication-lag"


@pytest.mark.parametrize("attr, value", [("ciamComparison", "above"), ("ciamThreshold", "five seconds"),
                                         ("ciamEvaluationPeriod", "5 minutes")])
def test_the_store_refuses_what_the_definitions_dont_allow(conn, attr, value):
    wrong = re.sub(rf"^{attr}: .*$", f"{attr}: {value}", RULE, flags=re.M)
    with pytest.raises(Exception) as refused:
        db.load_records(conn, parse(wrong))
    assert attr in str(refused.value)


def test_realization_bindings_are_stored(conn):
    db.load_records(conn, parse(RULE + f"""
dn: cn=ds-lag,ou=bindings,{ENV}
objectClass: top
objectClass: ciamAlarmBinding
cn: ds-lag
ciamBindingRole: alarm-replication-lag
ciamProviderRef: arn:aws:cloudwatch:region-1:111122223333:alarm:ds-lag
ciamRealizes: replication-lag
ciamMetric: CIAM/DS ReplicationDelay
ciamNotifies: arn:aws:sns:region-1:111122223333:page

dn: cn=login,ou=bindings,{ENV}
objectClass: top
objectClass: ciamCanaryBinding
cn: login
ciamBindingRole: canary-login
ciamProviderRef: arn:aws:synthetics:region-1:111122223333:canary:login
ciamRealizes: login
ciamInterval: 5m
"""))
    assert [r[1:4] for r in monitor_rows(db.load_directory(conn))] == [
        ("ds-lag", "alarm", "replication-lag"), ("login", "check", "login")]

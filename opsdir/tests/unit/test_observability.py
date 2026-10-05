"""The observability domain: alert rules, log routes and canaries as intent, the channels and destinations each
environment binds, what each cloud runs of it (alarms and synthetic checks realizing rules and canaries), their
reports, and the planner's findings when a move would leave alerts going nowhere, checks checking nothing, logs kept
for less time than they must be, or monitoring nobody described."""
import datetime as dt

from opsdir.core.contract import PlanContext
from opsdir.core.environment import env_model
from opsdir.core.directory import one
from opsdir.core.findings import findings
from opsdir.core.interchange.ldif import LdifRecord, parse
from opsdir.core.inventory import duration_text, environment_groups, realization_roles, resource
from opsdir.domains.observability.alerts import alert_rows, canary_rows, check_alerts
from opsdir.domains.observability.logs import check_logs, log_rows
from opsdir.domains.observability.naming import ALERT_RULES, CANARIES, LOG_ROUTES
from opsdir.domains.observability.realized import check_realized, monitor_rows
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
OPS = "cn=ops,ou=owners,dc=ciam-ops"
RUNBOOK = "cn=WI-1,ou=runbooks,dc=ciam-ops"


def _ou(dn, ou):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {ou}\n"


def _binding(env, cn, oc, role, extra=""):
    return (f"dn: cn={cn},ou=bindings,{env}\nobjectClass: top\nobjectClass: {oc}\ncn: {cn}\nciamBindingRole: {role}\n"
            f"{extra}")


def _entry(dn, oc, attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: {oc}\n" + "".join(
        f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))


BASE = (
    "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    f"dn: {OPS}\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n",
    _ou("ou=runbooks,dc=ciam-ops", "runbooks"),
    f"dn: {RUNBOOK}\nobjectClass: top\nobjectClass: ciamRunbook\ncn: WI-1\nciamTitle: Replication lag\n"
    "ciamLastReviewed: 20260101000000Z\n",
    _binding(ALPHA, "svc-login", "ciamServiceName", "login-service",
             "ciamFqdn: login.alpha.example.test\nciamTargetRole: web\nciamPort: 443\n"),
    _binding(BETA, "svc-login", "ciamServiceName", "login-service",
             "ciamFqdn: login.beta.example.test\nciamTargetRole: web\nciamPort: 443\n"),
    _binding(ALPHA, "page", "ciamAlertChannel", "alerts-page", "ciamChannelKind: topic\nciamProviderRef: sns-1\n"),
    _binding(BETA, "page", "ciamAlertChannel", "alerts-page",
             "ciamChannelKind: action-group\nciamProviderRef: ag-1\n"),
    _binding(ALPHA, "audit", "ciamLogDestination", "audit-logs",
             "ciamDestinationKind: log-group\nciamProviderRef: lg-1\nciamRetentionDays: 400\n"),
    _binding(BETA, "audit", "ciamLogDestination", "audit-logs",
             "ciamDestinationKind: workspace\nciamProviderRef: ws-1\nciamRetentionDays: 90\n"),
    _binding(ALPHA, "canary-creds", "ciamSecretRef", "canary-user",
             "ciamRefUri: aws-sm://arn:aws:secretsmanager:region-1:111122223333:secret:canary\n"),
    _ou(ALERT_RULES, "alert-rules"),
    _entry(f"cn=replication-lag,{ALERT_RULES}", "ciamAlertRule",
           {"cn": "replication-lag", "ciamSignal": "replication-delay", "ciamTargetRole": "web",
            "ciamComparison": "gt", "ciamThreshold": "5000 ms", "ciamEvaluationPeriod": "5m", "ciamSeverity": "sev2",
            "ciamAlertRole": "alerts-page", "ciamRunbookRef": RUNBOOK, "ciamOwner": OPS}),
    _entry(f"cn=login-failures,{ALERT_RULES}", "ciamAlertRule",
           {"cn": "login-failures", "ciamSignal": "login-failures", "ciamAlertRole": "alerts-ticket"}),
    _ou(LOG_ROUTES, "log-routes"),
    _entry(f"cn=audit,{LOG_ROUTES}", "ciamLogRoute",
           {"cn": "audit", "ciamLogKind": ("audit", "admin"), "ciamPublishedBy": "web",
            "ciamLogDestinationRole": "audit-logs", "ciamRetentionDays": "365", "ciamLegalHold": "TRUE",
            "ciamOwner": OPS}),
    _ou(CANARIES, "canaries"),
    _entry(f"cn=login,{CANARIES}", "ciamCanary",
           {"cn": "login", "ciamCheckedService": "login-service", "ciamCanaryFlow": "oidc-token",
            "ciamInterval": "5m", "ciamUsesRole": "canary-user",
            "ciamFeedsAlert": f"cn=login-failures,{ALERT_RULES}"}),
    _entry(f"cn=ldap,{CANARIES}", "ciamCanary",
           {"cn": "ldap", "ciamCheckedService": "ldaps-service", "ciamCanaryFlow": "ldap-bind"}),
)


def _record(*extra):
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join((*BASE, *extra)))))


def _plan(d, check):
    return check(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, dt.date(2026, 10, 1),
                             {}, {}, ()))


def test_the_reports():
    d = _record()
    assert alert_rows(d) == [
        ("login-failures", "login-failures", "", "", "", "alerts-ticket", "", ""),
        ("replication-lag", "replication-delay", "web", "gt 5000 ms for 5m", "sev2", "alerts-page", "WI-1", "ops")]
    assert canary_rows(d) == [("ldap", "ldap-bind", "ldaps-service", "", "", ""),
                              ("login", "oidc-token", "login-service", "5m", "canary-user", "login-failures")]
    assert log_rows(d) == [("audit", "audit, admin", "web", "audit-logs", "365", "yes")]


def test_alerts_that_go_nowhere_and_canaries_that_check_nothing_block():
    f = _plan(_record(), check_alerts)
    assert [t for _, t, _ in f.blockers] == [
        "Alert rule `login-failures` is delivered by role `alerts-ticket`, which neither alpha/prod nor beta/prod "
        "binds: its alerts go nowhere. Record each environment's channel.",
        "Canary `ldap` needs role `ldaps-service`, which neither alpha/prod nor beta/prod binds: it checks nothing. "
        "Record each environment's."]
    assert [t for _, t, _, _ in f.actions] == [
        "Alert rule `login-failures` names no runbook: whoever it pages doesn't know what to do. Link one "
        "(ciamRunbookRef).",
        "Alert rule `login-failures` has no owner: nobody answers for it after a move. Name who owns it.",
        "Canary `ldap` fires no alert rule: when it fails, nobody hears. Name the rule it feeds (ciamFeedsAlert)."]
    # canary-user is bound in alpha only: the core role check says so, not this one
    assert not any("canary-user" in t for _, t, _ in f.blockers)


def test_logs_kept_less_long_in_the_target_block():
    f = _plan(_record(), check_logs)
    assert [t for _, t, _ in f.blockers] == [
        "Log route `audit` must keep logs 365 days; beta/prod's `audit-logs` keeps them 90. Raise its retention "
        "before cutover."]
    assert [t for _, t, _, _ in f.actions] == [
        "Log route `audit` is under legal hold: alpha/prod's `audit-logs` must outlive the source's decommissioning. "
        "Keep it, or move what it holds, before deleting the source."]
    (fix,) = f.fixes
    assert (fix.key, fix.title) == ("log-retention:audit", "Keep beta/prod's `audit-logs` logs 365 days, as log route "
                                                           "`audit` requires")
    assert fix.records[0].mods == (("replace", "ciamRetentionDays", ("365",)),)
    fixed = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(BASE))), fix.records)
    assert _plan(fixed, check_logs).blockers == ()


def test_nothing_to_watch_finds_nothing_and_a_sound_setup_says_so():
    bare = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)))
    assert _plan(bare, check_alerts) == findings() and _plan(bare, check_logs) == findings()
    sound = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(
        e for e in BASE if "cn=login-failures," not in e.split("\n")[0] and "cn=ldap," not in e.split("\n")[0]
        and "cn=login,ou=canaries" not in e.split("\n")[0]))))
    assert _plan(sound, check_alerts).ok == ("Alert rules (1) and canaries (0) are delivered and exercised in "
                                             "beta/prod.",)


def test_tags_say_what_an_alarm_realizes_and_durations_read_as_the_record_writes_them():
    assert realization_roles({"Realizes": "replication-lag"}, "alarm") == ("alarm-replication-lag", "replication-lag")
    assert realization_roles({"Realizes": "x", "Role": "pager"}, "alarm") == ("pager", "x")
    assert realization_roles({}, "canary") == (None, None)
    assert [duration_text(s) for s in (None, 0, 45, 300, 7200, 86400)] == [None, None, "45s", "5m", "2h", "1d"]


RUNS = (
    resource("channel", "sns-1", {"ciamChannelKind": "topic"}, name="page", role="alerts-page"),
    resource("logs", "lg-2", {"ciamDestinationKind": "log-group", "ciamRetentionDays": 0}, name="archive",
             role="archive-logs"),
    resource("alarm", "arn:alarm:lag", {"ciamRealizes": "replication-lag", "ciamMetric": "CIAM/DS ReplicationDelay",
                                        "ciamNotifies": "sns-1"}, name="ds-lag", role="alarm-replication-lag"),
    resource("alarm", "arn:alarm:cpu", {"ciamMetric": "AWS/EC2 CPUUtilization"}, name="cpu-high", role="alarm-cpu"),
    resource("canary", "arn:canary:login", {"ciamRealizes": "login", "ciamInterval": "5m"}, name="login",
             role="canary-login"))


def _with_runs():
    """(the record with RUNS imported into alpha/prod, the import's notices)."""
    groups, notices = environment_groups(_record(), "alpha/prod", RUNS)
    added = tuple(LdifRecord(e.dn, "add", {"objectClass": e.classes, **e.attrs}, ()) for _, es in groups for e in es)
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(BASE))), added), notices


def test_what_a_cloud_runs_is_placed_as_bindings():
    groups, notices = environment_groups(_record(), "alpha/prod", RUNS)
    placed = {e.dn: e for _, entries in groups for e in entries}
    lag, canary = placed[f"cn=ds-lag,ou=bindings,{ALPHA}"], placed[f"cn=login,ou=bindings,{ALPHA}"]
    assert (lag.classes, one(lag, "ciamRealizes"), one(lag, "ciamProviderRef")) == (
        ("top", "ciamAlarmBinding"), "replication-lag", "arn:alarm:lag")
    assert (canary.classes, one(canary, "ciamInterval")) == (("top", "ciamCanaryBinding"), "5m")
    d, _ = _with_runs()
    assert ("alpha/prod", "ds-lag", "alarm", "replication-lag", "CIAM/DS ReplicationDelay", "sns-1", "",
            "arn:alarm:lag") in monitor_rows(d)


def test_alarms_nobody_described_and_rules_nothing_runs_are_actions():
    d, _ = _with_runs()
    assert [t for _, t, _, _ in _plan(d, check_realized).actions] == [
        "alpha/prod runs alarm `cpu-high` (arn:alarm:cpu), which realizes no recorded alert rule: record what it "
        "watches, or retire it.",
        "Alert rule `login-failures` isn't realized in alpha/prod: nothing there runs it today.",
        "Canary `ldap` isn't realized in alpha/prod: nothing there runs it today."]
    assert _plan(_record(), check_realized) == findings()           # nothing recorded as run: nothing asked
    indefinite = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(BASE).replace(
        "ciamRetentionDays: 90", "ciamRetentionDays: 0"))))
    assert _plan(indefinite, check_logs).blockers == ()               # 0: the target never expires them

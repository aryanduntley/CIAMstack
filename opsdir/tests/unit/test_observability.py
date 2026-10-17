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
from opsdir.domains.observability.siem import check_siem, detection_index, detections, siem_destinations
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
    route = ("audit", "audit, admin", "web", "audit-logs", "365", "yes")
    assert log_rows(d) == [(*route, "alpha/prod", "log-group", "400", "400"),
                           (*route, "beta/prod", "workspace", "90", "90")]
    # a route nobody keeps is still one row
    lost = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(
        e.replace("ciamLogDestinationRole: audit-logs", "ciamLogDestinationRole: nowhere") for e in BASE))))
    assert log_rows(lost) == [("audit", "audit, admin", "web", "nowhere", "365", "yes", "", "", "", "")]


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


def test_a_saml_sign_in_check_names_the_service_provider_it_starts_from():
    saml = _entry(f"cn=saml,{CANARIES}", "ciamCanary",
                  {"cn": "saml", "ciamCheckedService": "login-service", "ciamCanaryFlow": "saml-sso",
                   "ciamFeedsAlert": f"cn=login-failures,{ALERT_RULES}"})
    f = _plan(_record(saml), check_alerts)
    assert ("Canary `saml` is a SAML sign-in but names no SAML service provider with an entity ID to start from "
            "(ciamStartsFrom): no cloud renders it. Name the integration.") in [t for _, t, _, _ in f.actions]


def _rebind(old, new):
    """BASE with one binding's text replaced (old must occur once), plus nothing else."""
    assert sum(e.count(old) for e in BASE) == 1
    return tuple(e.replace(old, new) for e in BASE)


def _with(base, *extra):
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join((*base, *extra)))))


BETA_AUDIT = "ciamDestinationKind: workspace\nciamProviderRef: ws-1\nciamRetentionDays: 90\n"


def test_a_destination_archiving_long_enough_is_an_action_and_a_short_total_is_the_one_raised():
    archived = _with(_rebind(BETA_AUDIT, BETA_AUDIT + "ciamTotalRetentionDays: 400\n"))
    f = _plan(archived, check_logs)
    assert not f.blockers and not f.fixes
    assert [t for _, t, _, _ in f.actions][0] == (
        "Log route `audit` must keep logs 365 days; beta/prod's `audit-logs` keeps them 400 days in all but searchable "
        "only 90: older logs must be restored from its archive before anyone can search them. Confirm that is "
        "acceptable, or raise its searchable retention.")
    assert log_rows(archived)[1][-2:] == ("90", "400")
    short = _with(_rebind(BETA_AUDIT, BETA_AUDIT + "ciamTotalRetentionDays: 180\n"))
    f = _plan(short, check_logs)
    assert [t for _, t, _ in f.blockers] == [
        "Log route `audit` must keep logs 365 days; beta/prod's `audit-logs` keeps them 180. Raise its retention "
        "before cutover."]
    (fix,) = f.fixes
    assert fix.records[0].mods == (("replace", "ciamTotalRetentionDays", ("365",)),)
    forever = _with(_rebind(BETA_AUDIT, BETA_AUDIT + "ciamTotalRetentionDays: 0\n"))
    assert _plan(forever, check_logs).blockers == () and log_rows(forever)[1][-1] == "forever"


SIEM = "cn=siem,ou=bindings,"


def _siem(env, extra=""):
    return _binding(env, "siem", "ciamLogDestination", "siem",
                    f"ciamDestinationKind: siem-index\nciamProviderRef: ciam_security\nciamRetentionDays: 400\n{extra}")


def _detection(env, rule, index="siem", search="index=ciam_security status=failure"):
    return _binding(env, f"det-{rule}", "ciamAlarmBinding", f"det-{rule}",
                    f"ciamProviderRef: saved-search:{rule}\nciamRealizes: {rule}\nciamLogDestinationRole: {index}\n"
                    + (f"ciamMetric: {search}\n" if search else ""))


def test_siem_indexes_and_the_detections_searching_them():
    d = _with(BASE, _siem(ALPHA), _detection(ALPHA, "replication-lag"),
              _binding(ALPHA, "alarm", "ciamAlarmBinding", "alarm", "ciamProviderRef: a-1\nciamRealizes: x\n"))
    alpha = env_model(d, "alpha/prod")
    assert [one(b, "cn") for b in siem_destinations(alpha)] == ["siem"]
    (det,) = detections(alpha)                     # the plain alarm names no index: not a detection
    assert one(detection_index(alpha, det), "cn") == "siem"
    assert siem_destinations(env_model(d, "beta/prod")) == ()


def test_detections_the_target_loses_or_breaks_and_holds_a_siem_keeps_are_actions():
    routed = _rebind("ciamLogDestinationRole: audit-logs", "ciamLogDestinationRole: siem")
    d = _with(routed, _siem(ALPHA), _siem(BETA), _detection(ALPHA, "replication-lag"),
              _detection(ALPHA, "login-failures"), _detection(BETA, "login-failures", search=None),
              _detection(BETA, "nothing", index="audit-logs"))
    texts = [t for _, t, _, _ in _plan(d, check_siem).actions]
    assert texts == [
        "alpha/prod's SIEM runs detection `det-replication-lag` for alert rule `replication-lag`; beta/prod records "
        "none: after the move its SIEM no longer raises it. Record the search beta/prod's SIEM runs (an alarm binding "
        "naming the rule in ciamRealizes, the SIEM index in ciamLogDestinationRole and the search in ciamMetric).",
        "beta/prod's detection `det-nothing` searches `audit-logs`, which beta/prod doesn't bind to a SIEM index: it "
        "searches nothing. Bind the role to the SIEM's index (a log destination of kind siem-index).",
        "beta/prod's detection `det-login-failures` records no search (ciamMetric): nothing renders it. Record the "
        "search its SIEM runs.",
        "Log route `audit` is under legal hold, and beta/prod keeps its logs in a SIEM index (`siem`): its retention "
        "doesn't prove a hold (a SIEM expires, or an administrator deletes, what it keeps). Record how the hold is "
        "kept there (an immutable archive, the SIEM's own hold), or keep the source's copy."]
    assert _plan(_record(), check_siem) == findings()


def test_total_days_falls_back_to_the_searchable_days_and_reads_as_reports_write_it():
    from opsdir.domains.observability.retention import INDEFINITE, days_text, total_days
    d = _with(_rebind(BETA_AUDIT, BETA_AUDIT + "ciamTotalRetentionDays: 730\n"))
    alpha, beta = (one_role_of(d, env) for env in ("alpha/prod", "beta/prod"))
    assert (total_days(alpha), total_days(beta), total_days(None)) == (400, 730, None)
    assert [days_text(x) for x in (None, INDEFINITE, 30)] == ["", "forever", "30"]


def one_role_of(d, env):
    from opsdir.core.environment import one_role
    return one_role(env_model(d, env), "audit-logs")


def test_entity_mappings_need_a_rows_detection_and_an_identifier_their_entity_has():
    from opsdir.domains.observability.siem import detection_mode, entity_mappings
    counted = _detection(BETA, "login-failures") + "ciamEntityMapping: account name=UserPrincipalName\n"
    rows = (_binding(BETA, "det-spray", "ciamAlarmBinding", "det-spray",
                     "ciamProviderRef: saved-search:spray\nciamRealizes: login-failures\nciamLogDestinationRole: siem\n"
                     "ciamMetric: index=ciam_security | stats count by user, src\nciamDetectionMode: rows\n"
                     "ciamEntityMapping: account name=user\nciamEntityMapping: ip hostname=src\n"))
    d = _with(BASE, _siem(BETA), counted, rows)
    texts = [t for _, t, _ in _plan(d, check_siem).blockers]
    assert texts == [
        "beta/prod's detection `det-login-failures` maps entities but counts events (ciamDetectionMode count): its "
        "results hold no rows to name them; make it a rows detection (a search returning one row per finding) or "
        "drop the mappings.",
        "beta/prod's detection `det-spray` maps ip by `hostname`, an identifier ip doesn't have (address)."]
    spray = next(b for b in detections(env_model(d, "beta/prod")) if b.dn.startswith("cn=det-spray,"))
    assert detection_mode(spray) == "rows"
    assert entity_mappings(spray) == (("account", "name", "user"), ("ip", "hostname", "src"))

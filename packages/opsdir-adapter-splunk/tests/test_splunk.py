"""The Splunk add-on: the indexes an environment keeps logs in (searchable and archived days), its detections as
scheduled saved searches counting events per window (a rows detection as written, alerting per row; on Splunk ES a
correlation search with its ATT&CK annotations, notable and risk objects), the forwarders' inputs per role and
install root, what it leaves to the Splunk team as render notes; read back from its own .conf files unchanged, and
from the management API's answers; collected read-only; and the provider adapters leaving its indexes to it."""
import json

from opsdir.connectors.collecting import collect
from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.core.notes import note_comment
from opsdir.domains.observability.alarms import condition
from opsdir.domains.observability.naming import ALERT_RULES, LOG_ROUTES
from opsdir_adapter_splunk.adapter import ADAPTER
from opsdir_adapter_splunk.collect import COLLECTORS, rest_steps
from opsdir_adapter_splunk.conf import read_conf, setting, write_conf
from opsdir_adapter_splunk.naming import INDEXES, SAVED_SEARCHES, index_name
from opsdir_adapter_splunk.read import base_search, parse_conf, parse_rest, read_conf_files, read_rest
from opsdir_adapter_splunk.render import (cron_schedule, detection_search, host_files, index_stanza, render,
                                          render_notes)
from network_fixtures import ALPHA, entry, model

OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"
SOURCES = (LogSource("ds", "servers", "logs/ldap-access.audit.json", "json-lines", "access"),
           LogSource("ds", "servers", "logs/errors", "text", "error", line_start=r"^\["),
           LogSource("ds", "servers", "audit/*.json", "json-lines", "audit", (("eventName", "DJ-", "access"),)))
SEARCH = 'index=ciam_security sourcetype=_json status=failure'


def _route(cn, kinds, roles, dest):
    return (f"dn: cn={cn},{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
            f"cn: {cn}\n" + "".join(f"ciamLogKind: {k}\n" for k in kinds)
            + "".join(f"ciamPublishedBy: {r}\n" for r in roles) + f"ciamLogDestinationRole: {dest}\n")


def _rule(cn, **attrs):
    return (f"dn: cn={cn},{ALERT_RULES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamAlertRule\n"
            f"cn: {cn}\n" + "".join(f"{k}: {v}\n" for k, v in attrs.items()))


TREE = (OU.format(LOG_ROUTES, "log-routes"), OU.format(ALERT_RULES, "alert-rules"),
        _route("security", ("audit",), ("ds", "web"), "siem"),
        _route("errors", ("error",), ("ds",), "siem-ops"),
        _rule("login-failures", ciamSignal="login-failures", ciamComparison="gt", ciamThreshold="50 /min",
              ciamEvaluationPeriod="5m", ciamAlertRole="alerts-page"),
        _rule("too-quiet", ciamSignal="logins", ciamComparison="lt", ciamThreshold="1 /min",
              ciamAlertRole="alerts-page"),
        _rule("unsearched", ciamSignal="x", ciamComparison="gt", ciamThreshold="1 /min", ciamAlertRole="alerts-page"),
        f"dn: cn=siem,ou=stack,{ALPHA}\nobjectClass: top\nobjectClass: ciamStackComponent\ncn: siem\n"
        "ciamStackRole: siem\nciamAdapter: splunk\nciamAdapterVersion: >=0.1,<1\n"
        "ciamAdapterSource: https://example.test/splunk\n")
BINDINGS = (entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef="ciam_security", ciamRetentionDays="90", ciamTotalRetentionDays="400"),
            entry(ALPHA, "siem-ops", "ciamLogDestination", ciamBindingRole="siem-ops",
                  ciamDestinationKind="siem-index", ciamProviderRef="ciam_ops", ciamRetentionDays="0"),
            entry(ALPHA, "page", "ciamAlertChannel", ciamBindingRole="alerts-page", ciamChannelKind="email",
                  ciamProviderRef="soc@example.test"),
            entry(ALPHA, "det-login", "ciamAlarmBinding", ciamBindingRole="alarm-login-failures",
                  ciamProviderRef="ciam-login-failures", ciamRealizes="login-failures", ciamMetric=SEARCH,
                  ciamLogDestinationRole="siem"),
            entry(ALPHA, "det-quiet", "ciamAlarmBinding", ciamBindingRole="alarm-too-quiet",
                  ciamProviderRef="ciam-too-quiet", ciamRealizes="too-quiet", ciamMetric=SEARCH,
                  ciamLogDestinationRole="siem"),
            entry(ALPHA, "det-none", "ciamAlarmBinding", ciamBindingRole="alarm-unsearched",
                  ciamProviderRef="ciam-unsearched", ciamRealizes="unsearched", ciamLogDestinationRole="siem"))


def _root(server, root):
    return LdifRecord(f"cn={server},{ALPHA}", "modify", {}, (("add", "ciamInstallRoot", (root,)),))


def _alpha(*bindings):
    _, alpha, _ = model(alpha=bindings or BINDINGS, tree=TREE,
                        changes=(_root("ds-1", "/opt/ds"), _root("ds-2", "/srv/ds"), _root("web-1", "/opt/web")))
    return alpha


SERVICES = services()._replace(logs=lambda m: SOURCES)


def test_splunk_indexes_are_named_by_their_index_and_kept_by_the_add_on():
    m = _alpha()
    siem, ops = (b for b in m.bindings if b.dn.startswith(("cn=siem,", "cn=siem-ops,")))
    assert (index_name(siem), index_name(ops)) == ("ciam_security", "ciam_ops")
    workspace = entry(ALPHA, "ws", "ciamLogDestination", ciamBindingRole="ws", ciamDestinationKind="siem-index",
                      ciamProviderRef="/subscriptions/0/resourceGroups/rg/providers/Microsoft.OperationalInsights/"
                                      "workspaces/law")
    other = _alpha(*BINDINGS, workspace)
    (ws,) = (b for b in other.bindings if b.dn.startswith("cn=ws,"))
    assert index_name(ws) is None and not ADAPTER.siem_indexes(other, ws) and ADAPTER.siem_indexes(other, siem)
    assert services().siem_keeper(m, siem) == "splunk" and services().siem_keeper(other, ws) is None


def test_indexes_conf_keeps_the_searchable_days_and_the_archive_when_longer():
    m = _alpha()
    files = render(m, SERVICES)
    stanzas = dict(read_conf(files[INDEXES]))
    assert stanzas["ciam_security"] == (
        ("homePath", "$SPLUNK_DB/ciam_security/db"), ("coldPath", "$SPLUNK_DB/ciam_security/colddb"),
        ("thawedPath", "$SPLUNK_DB/ciam_security/thaweddb"), ("frozenTimePeriodInSecs", str(90 * 86400)),
        ("archiver.enableDataArchive", "true"), ("archiver.coldStorageRetentionPeriod", "400"))
    assert "frozenTimePeriodInSecs" not in dict(stanzas["ciam_ops"])          # kept forever: Splunk can't say it
    assert files[INDEXES].startswith("# Generated by opsdir from " + m.dn)


def test_a_detection_counts_events_per_window_every_window_of_the_period_breaching():
    m = _alpha()
    searches = dict(read_conf(render(m, SERVICES)[SAVED_SEARCHES]))
    assert set(searches) == {"ciam-login-failures"}       # too-quiet compares lt; unsearched records no search
    c = condition(next(r for r in m.d.entries.values() if r.dn.startswith("cn=login-failures,")))
    assert dict(searches["ciam-login-failures"]) == {
        "description": "opsdir: realizes alert rule login-failures",
        "search": f"{SEARCH} | bin _time span=60s | stats count by _time | where count > 50 | stats count AS "
                  "breaching | where breaching >= 5",
        "is_scheduled": "1", "cron_schedule": "*/5 * * * *", "dispatch.earliest_time": "-300s",
        "dispatch.latest_time": "now", "alert_type": "number of events", "alert_comparator": "greater than",
        "alert_threshold": "0", "disabled": "0"}
    assert (c.window, c.windows) == (60, 5)
    assert cron_schedule(7200) == ("0 */2 * * *", None) and cron_schedule(420)[0] is None
    assert base_search(detection_search(SEARCH, next(r for r in m.d.entries.values()
                                                     if r.dn.startswith("cn=login-failures,")), c)) == SEARCH


SPRAY = "index=ciam_security action=failure | stats dc(user) AS users BY src, dest, user | where users > 10"
ATTACK_RULES = (_rule("password-spray", ciamSignal="spray", ciamComparison="gt", ciamThreshold="10",
                      ciamEvaluationPeriod="15m", ciamSeverity="sev1", ciamAlertRole="alerts-page",
                      ciamAttackTactic="credential-access",
                      ciamAttackTechnique="T1110.003\nciamAttackTechnique: T1078.004"),
                _rule("admin-changes", ciamSignal="changes", ciamComparison="gt", ciamThreshold="5 /min",
                      ciamEvaluationPeriod="5m", ciamAlertRole="alerts-page", ciamAttackTactic="persistence"))
ES_STACK = TREE[-1].replace("ciamAdapterSource: https://example.test/splunk\n",
                            "ciamAdapterSource: https://example.test/splunk\nciamOffering: enterprise-security\n")
ES_TREE = (*TREE[:-1], *ATTACK_RULES, ES_STACK)
PLATFORM_TREE = (*TREE, *ATTACK_RULES)
SPRAYING = entry(ALPHA, "det-spray", "ciamAlarmBinding", ciamBindingRole="alarm-password-spray",
                 ciamProviderRef="ciam-password-spray", ciamRealizes="password-spray", ciamMetric=SPRAY,
                 ciamLogDestinationRole="siem", ciamDetectionMode="rows",
                 ciamEntityMapping=("account name=user", "ip address=src", "host hostname=dest"))
CHANGES = entry(ALPHA, "det-changes", "ciamAlarmBinding", ciamBindingRole="alarm-admin-changes",
                ciamProviderRef="ciam-admin-changes", ciamRealizes="admin-changes", ciamMetric=SEARCH,
                ciamLogDestinationRole="siem")


def _attack(tree, spraying=SPRAYING):
    _, alpha, _ = model(alpha=(*BINDINGS, spraying, CHANGES), tree=tree,
                        changes=(_root("ds-1", "/opt/ds"), _root("ds-2", "/srv/ds"), _root("web-1", "/opt/web")))
    return alpha


def test_on_enterprise_security_a_detection_is_a_correlation_search_with_its_attack_and_risk_objects():
    searches = dict(read_conf(render(_attack(ES_TREE), SERVICES)[SAVED_SEARCHES]))
    assert dict(searches["ciam-password-spray"]) == {
        "description": "opsdir: realizes alert rule password-spray", "search": SPRAY, "is_scheduled": "1",
        "cron_schedule": "*/15 * * * *", "dispatch.earliest_time": "-900s", "dispatch.latest_time": "now",
        "alert_type": "number of events", "alert_comparator": "greater than", "alert_threshold": "0",
        "disabled": "0", "alert.digest_mode": "0",
        "action.correlationsearch.enabled": "1", "action.correlationsearch.label": "password-spray",
        "action.correlationsearch.annotations": '{"mitre_attack":["T1110.003","T1078.004"]}',
        "action.notable": "1", "action.notable.param.rule_title": "password-spray",
        "action.notable.param.rule_description": "opsdir: realizes alert rule password-spray",
        "action.risk": "1",
        "action.risk.param._risk": '[{"risk_object_field": "user", "risk_object_type": "user", "risk_score": 73}, '
                                   '{"threat_object_field": "src", "threat_object_type": "ip_address"}, '
                                   '{"risk_object_field": "dest", "risk_object_type": "system", "risk_score": 73}]'}
    counted = dict(searches["ciam-login-failures"])          # a count detection: no annotations, no risk objects
    assert counted["action.correlationsearch.enabled"] == "1" and counted["action.notable"] == "1"
    assert "action.risk" not in counted and "action.correlationsearch.annotations" not in counted
    assert "alert.digest_mode" not in counted and counted["search"].endswith("| where breaching >= 5")


def test_what_enterprise_security_leaves_to_the_splunk_team_is_named():
    with_url = entry(ALPHA, "det-spray", "ciamAlarmBinding", ciamBindingRole="alarm-password-spray",
                     ciamProviderRef="ciam-password-spray", ciamRealizes="password-spray", ciamMetric=SPRAY,
                     ciamLogDestinationRole="siem", ciamDetectionMode="rows",
                     ciamEntityMapping=("account name=user", "url url=uri", "account object-id=user_id"))
    texts = [(n.severity, note_comment(n)) for n in render_notes(_attack(ES_TREE, with_url), SERVICES)]
    assert ("note", "NOTE: alert rule password-spray: its entity mappings url url, account object-id aren't risk or "
            "threat objects of its correlation search: opsdir renders an account's name and a host's name as risk "
            "objects and an IP address as a threat object, the types ES documents") in texts
    assert ("note", "NOTE: alert rule admin-changes: its ATT&CK tactics persistence aren't annotated: ES annotates a "
            "correlation search by technique (mitre_attack) and derives the tactics, and the rule records no "
            "technique (ciamAttackTechnique)") in texts
    (es,) = (n for n in render_notes(_attack(ES_TREE), SERVICES) if n.subject == "Splunk Enterprise Security")
    assert es.severity == "action" and es.how[0] == ("Set each correlation search's finding severity and security "
                                                     "domain in ES")


def test_annotations_leave_out_techniques_attack_v20_doesnt_hold_with_a_note():
    retired = ES_TREE[:-3] + (ATTACK_RULES[0].replace("ciamAttackTechnique: T1078.004",
                                                       "ciamAttackTechnique: T1562.001\nciamAttackTechnique: T9999"),
                              *ES_TREE[-2:])
    m = _attack(retired)
    spray = dict(dict(read_conf(render(m, SERVICES)[SAVED_SEARCHES]))["ciam-password-spray"])
    assert spray["action.correlationsearch.annotations"] == '{"mitre_attack":["T1110.003"]}'
    texts = [(n.severity, note_comment(n)) for n in render_notes(m, SERVICES)]
    assert ("note", "NOTE: alert rule password-spray: its ATT&CK techniques T1562.001, T9999 aren't annotated: they "
            "aren't in ATT&CK v20 (retired, or never in ATT&CK)") in texts


def test_on_the_plain_platform_a_rows_detection_alerts_per_row_and_its_mappings_are_named():
    m = _attack(PLATFORM_TREE)
    searches = dict(read_conf(render(m, SERVICES)[SAVED_SEARCHES]))
    spray = dict(searches["ciam-password-spray"])
    assert spray["search"] == SPRAY and spray["alert.digest_mode"] == "0" and spray["cron_schedule"] == "*/15 * * * *"
    assert not any(k.startswith("action.") for s in searches.values() for k, _ in s)
    texts = [(n.severity, note_comment(n)) for n in render_notes(m, SERVICES)]
    assert ("note", "NOTE: alert rule password-spray: its ATT&CK tactics and techniques and its entity mappings "
            "aren't rendered: a saved search has no place for them (a Splunk Enterprise Security correlation search "
            "does)") in texts
    assert ("note", "NOTE: alert rule admin-changes: its ATT&CK tactics and techniques aren't rendered: a saved "
            "search has no place for them (a Splunk Enterprise Security correlation search does)") in texts
    assert not any(n.subject == "Splunk Enterprise Security" for n in render_notes(m, SERVICES))


def test_a_rows_detection_reads_back_with_its_entity_mappings_without_drift():
    from opsdir.connectors.roundtrip import round_trip
    from mini_estate import FAKE
    for tree in (ES_TREE, PLATFORM_TREE):
        m = _attack(tree)
        (rt,) = round_trip(m.d, "alpha/prod", installed=(FAKE, ADAPTER._replace(logs=SOURCES)))
        assert rt.drift == ()
    resources, _ = parse_conf({"savedsearches.conf": render(_attack(ES_TREE), SERVICES)[SAVED_SEARCHES]})
    spray = next(r for r in resources if r.ref == "ciam-password-spray")
    assert spray.attrs["ciamDetectionMode"] == ("rows",) and spray.attrs["ciamEntityMapping"] == (
        "account name=user", "ip address=src", "host hostname=dest")
    counted = next(r for r in resources if r.ref == "ciam-login-failures")
    assert "ciamDetectionMode" not in counted.attrs and "ciamEntityMapping" not in counted.attrs


def test_forwarder_inputs_per_role_and_install_root():
    m = _alpha()
    files = host_files(m, SERVICES)
    assert [(f.server_role, f.hosts, f.path, f.reload) for f in files] == [
        ("ds", ("ds-1",), "/opt/splunkforwarder/etc/apps/opsdir_ciam/local/inputs.conf",
         ("/opt/splunkforwarder/bin/splunk", "restart")),
        ("ds", ("ds-2",), "/opt/splunkforwarder/etc/apps/opsdir_ciam/local/inputs.conf",
         ("/opt/splunkforwarder/bin/splunk", "restart"))]
    stanzas = read_conf(files[0].text)
    assert [(n, setting((n, p), "index"), setting((n, p), "sourcetype")) for n, p in stanzas] == [
        ("monitor:///opt/ds/logs/errors", "ciam_ops", "ciam:ds:errors"),
        ("monitor:///opt/ds/audit/*.json", "ciam_security", "_json")]


def test_what_it_leaves_to_the_splunk_team_and_cannot_ship_is_named():
    texts = [(n.severity, note_comment(n)) for n in render_notes(_alpha(), SERVICES)]
    severities = {t.split(": ", 2)[1]: s for s, t in texts}
    assert severities["Splunk app opsdir_ciam"] == "action" and severities["Splunk forwarding"] == "action"
    assert severities["Splunk alert actions"] == "action"
    assert ("action", "NOTE: Splunk index ciam_ops: kept searchable indefinitely in the record, which Splunk can't say "
            "(it freezes by age): frozenTimePeriodInSecs not rendered, so Splunk's default applies") in texts
    assert ("blocker", "NOTE: alert rule too-quiet: not rendered: a SIEM detection fires on more matching events "
            "than its threshold, not on comparison lt (windows without events aren't counted)") in texts
    assert ("note", "NOTE: alert rule unsearched: not rendered: its alarm det-none records no metric (ciamMetric)") \
        in texts
    assert ("note", "NOTE: log route security: /opt/ds/audit/*.json on role ds is shipped whole: the Universal "
            "Forwarder doesn't filter lines by their fields, so lines of the kinds the route doesn't take reach the "
            "index too") in texts
    assert any("records spanning lines are joined" in t for _, t in texts)
    rendered = render(_alpha(), SERVICES)[INDEXES]
    assert all(f"# {t}" in rendered.splitlines() for _, t in texts)


def test_a_file_two_routes_send_to_different_indexes_is_monitored_once():
    tree = (*TREE, _route("errors-too", ("error",), ("ds",), "siem"))
    _, m, _ = model(alpha=BINDINGS, tree=tree, changes=(_root("ds-1", "/opt/ds"),))
    texts = [note_comment(n) for n in render_notes(m, SERVICES) if n.severity == "blocker"]
    assert ("NOTE: log route errors-too: /opt/ds/logs/errors on role ds not shipped to ciam_security: route errors "
            "already ships it to ciam_ops, and a forwarder monitors a file once") in texts


def test_its_own_conf_files_read_back_unchanged():
    m = _alpha()
    files = render(m, SERVICES)
    read = read_conf_files({f"alpha/prod/{p.rsplit('/', 1)[1]}": t for p, t in files.items()}, m.d)
    recorded = {b.dn: b for b in m.bindings}
    for _, entries in read.groups:
        for e in entries:
            assert dict(e.attrs) == {k: v for k, v in recorded[e.dn].attrs.items() if k != "objectClass"}
    resources, notices = parse_conf({p.rsplit("/", 1)[1]: t for p, t in files.items()})
    by_ref = {r.ref: r for r in resources}
    assert by_ref["ciam_security"].attrs == {"ciamDestinationKind": ("siem-index",), "ciamRetentionDays": ("90",),
                                             "ciamTotalRetentionDays": ("400",)}
    assert by_ref["ciam-login-failures"].attrs == {"ciamRealizes": ("login-failures",), "ciamMetric": (SEARCH,)}
    assert by_ref["ciam-login-failures"].links == {"ciamLogDestinationRole": "ciam_security"}
    # the detections not rendered (their notes say why) are named; nothing about the environment's other bindings
    assert [n for n in read.notices if "is in the record but not" in n] == [
        "alpha/prod: det-none (ciamAlarmBinding) is in the record but not in what the cloud reports",
        "alpha/prod: det-quiet (ciamAlarmBinding) is in the record but not in what the cloud reports"]
    assert notices == ()


def test_the_management_api_answers_read_as_retention_and_detections():
    indexes = {"entry": [{"name": "ciam_security", "content": {"frozenTimePeriodInSecs": 15552000,
                                                              "maxTotalDataSizeMB": 500000,
                                                              "archiver.enableDataArchive": True,
                                                              "archiver.coldStorageRetentionPeriod": 400}},
                         {"name": "_internal", "content": {"frozenTimePeriodInSecs": 2592000}},
                         {"name": "main", "content": {"frozenTimePeriodInSecs": 100000}}]}
    searches = {"entry": [{"name": "ciam-login-failures", "content": {
                    "search": SEARCH, "description": "opsdir: realizes alert rule login-failures"}},
                          {"name": "Errors in the last hour", "content": {"search": "index=_internal error"}}]}
    files = {"indexes.json": json.dumps(indexes), "saved-searches.json": json.dumps(searches)}
    resources, notices = parse_rest(files)
    assert [r.ref for r in resources] == ["ciam_security", "main", "ciam-login-failures", "Errors in the last hour"]
    assert resources[0].attrs["ciamRetentionDays"] == ("180",)
    assert notices == ("Splunk index main: frozenTimePeriodInSecs 100000 isn't whole days; read as 1",)
    m = _alpha()
    read = read_rest({f"alpha/prod/{k}": v for k, v in files.items()}, m.d)
    (index,) = (e for _, es in read.groups for e in es if e.dn.startswith("cn=siem,"))
    assert index.attrs["ciamRetentionDays"] == ("180",)
    assert ("alpha/prod: Splunk index ciam_security also freezes its oldest data past maxTotalDataSizeMB 500000: its "
            "days are a ceiling, not a guarantee") in read.notices
    assert any("alarm resource(s) not in the record and naming no role" in n for n in read.notices)
    assert not any(n.startswith("alpha/prod: page (") for n in read.notices)


SOURCE = dict(ciamBindingRole="collect-splunk", ciamImporter="splunk/rest",
              ciamSourceRef="https://splunk.example.test:8089", ciamCredentialRole="splunk-reader",
              ciamCredentialScheme="bearer")


def test_the_collector_reads_the_two_answers_with_a_bearer_token():
    m = _alpha(*BINDINGS, entry(ALPHA, "splunk", "ciamCollectionSource", **SOURCE),
               entry(ALPHA, "splunk-reader", "ciamSecretRef", ciamBindingRole="splunk-reader",
                     ciamRefUri="fake://kv/splunk-reader"))
    steps = rest_steps(m.d, m, {}, {})
    assert [(p, r.url, r.credential) for p, r in steps] == [
        ("alpha/prod/indexes.json", "https://splunk.example.test:8089/services/data/indexes?output_mode=json&count=0",
         ("bearer", "fake://kv/splunk-reader", None)),
        ("alpha/prod/saved-searches.json",
         "https://splunk.example.test:8089/servicesNS/-/-/saved/searches?output_mode=json&count=0",
         ("bearer", "fake://kv/splunk-reader", None))]
    c = collect("splunk/rest", COLLECTORS[0], m.d, m, lambda r: (json.dumps({"entry": []}), None))
    assert c.problems == () and set(c.files) == {"alpha/prod/indexes.json", "alpha/prod/saved-searches.json"}


def test_conf_text_round_trips_with_continued_lines_and_defaults():
    text = write_conf("# head\n", (("a", (("k", "one\ntwo"),)), ("b", (("x", "1"),))))
    assert read_conf("top = 1\n" + text) == (("default", (("top", "1"),)), ("a", (("k", "one\ntwo"),)),
                                              ("b", (("x", "1"),)))
    assert write_conf("", ()) == ""


def test_provider_adapters_leave_a_splunk_index_to_it():
    from opsdir_adapter_aws.log_agent import log_notes
    _, m, _ = model(alpha=BINDINGS, tree=TREE, changes=(_root("ds-1", "/opt/ds"),))
    theirs = SERVICES._replace(siem_keeper=lambda m, b: None)
    assert any("isn't a CloudWatch log group" in note_comment(n) for n in log_notes(m, theirs))
    assert not any("isn't a CloudWatch log group" in note_comment(n) for n in log_notes(m, SERVICES))


def test_the_render_reads_back_through_the_round_trip_without_drift():
    from opsdir.connectors.roundtrip import round_trip
    m = _alpha()
    from mini_estate import FAKE
    (rt,) = round_trip(m.d, "alpha/prod", installed=(FAKE, ADAPTER._replace(logs=SOURCES)))
    assert rt.importer == "splunk/conf" and rt.drift == ()
    assert sorted(rt.files) == ["alpha/prod/indexes.conf", "alpha/prod/savedsearches.conf"]

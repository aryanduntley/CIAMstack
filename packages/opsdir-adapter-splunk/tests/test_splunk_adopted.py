"""Alert rules adopting a product's declared detection as Splunk saved searches: the SPL written from the rule's
canonical selector in the product's fields and values over the indexes its role's routes reach, counted per group
(or distinct values) to its threshold; a fixed window on a cron schedule over the clock-aligned window just ended, a
sliding one searched again every step over the whole window with its groups suppressed; on Splunk ES a correlation
search with its group-by as risk and threat objects; the rules it can't write named as blockers; and its own saved
searches left out when read back."""
from opsdir.connectors.registry import services
from opsdir.core.contract import DetectionMapping, LogSource, ProductDetection
from opsdir.core.notes import note_comment
from opsdir.domains.observability.detections import overlap_step
from opsdir.domains.observability.naming import ALERT_RULES, LOG_ROUTES
from opsdir_adapter_splunk.adapter import ADAPTER
from opsdir_adapter_splunk.adopted import spl_search, splunk_rules, timing
from opsdir_adapter_splunk.conf import read_conf
from opsdir_adapter_splunk.naming import SAVED_SEARCHES
from opsdir_adapter_splunk.read import parse_conf
from opsdir_adapter_splunk.render import render, render_notes
from opsdir_adapter_splunk.schedule import aligned_window
from network_fixtures import ALPHA, entry, model

OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"
FIELDS = (("subject", "principal"), ("realm", "realm"), ("outcome", "result"), ("action", "eventName"),
          ("source-ip", "client.ip"))
SAID = (("outcome", "failure", ("FAILED",)), ("action", "login", ("LOGIN-COMPLETED", "LOGIN-FAILED")))
DETECTION = ProductDetection(
    id="brute-force", title="Brute force", description="Repeated failed sign-ins for one subject",
    products=(("idp", ">=8"),), server_role="ds", log_source="authentication",
    mappings=(DetectionMapping("idp", ">=8", FIELDS, SAID),),
    selector=(("action", ("login",)), ("outcome", ("failure",))), group_by=("subject", "realm"), distinct=None,
    threshold=10, window_seconds=300, window_kind="sliding", tactics=("credential-access",), techniques=("T1110",),
    severity="sev2", prerequisites=(), evidence=("https://docs.example.test/audit",), validation="documented")
SPRAY = DETECTION._replace(id="password-spray", title="Password spray", group_by=("source-ip",), distinct="subject",
                           threshold=20, window_seconds=900, window_kind="fixed", techniques=("T1110.003",),
                           validation="lab-verified")
PAIRS = (("fake-cloud", DETECTION), ("fake-cloud", SPRAY))
SOURCES = (LogSource("ds", "servers", "audit/*.json", "json-lines", "audit"),)


def _route(cn, kinds, roles, dest):
    return (f"dn: cn={cn},{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
            f"cn: {cn}\n" + "".join(f"ciamLogKind: {k}\n" for k in kinds)
            + "".join(f"ciamPublishedBy: {r}\n" for r in roles) + f"ciamLogDestinationRole: {dest}\n")


def _adopting(cn, det, **changes):
    attrs = {"ciamSignal": (det.id,), "ciamTargetRole": (det.server_role,),
             "ciamDetectionSelector": tuple(f"{f}={'|'.join(v)}" for f, v in det.selector),
             "ciamGroupBy": det.group_by, "ciamDistinctField": (det.distinct,) if det.distinct else (),
             "ciamComparison": ("ge",), "ciamThreshold": (str(det.threshold),),
             "ciamEvaluationPeriod": (f"{det.window_seconds}s",), "ciamWindowKind": (det.window_kind,),
             "ciamSeverity": (det.severity,), "ciamAttackTactic": det.tactics, "ciamAttackTechnique": det.techniques,
             "ciamDeclaredDetection": (f"fake-cloud:{det.id}",), "ciamAlertRole": ("alerts-page",), **changes}
    return (f"dn: cn={cn},{ALERT_RULES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamAlertRule\n"
            f"cn: {cn}\n" + "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in vs))


STACK = (f"dn: cn=siem,ou=stack,{ALPHA}\nobjectClass: top\nobjectClass: ciamStackComponent\ncn: siem\n"
         "ciamStackRole: siem\nciamAdapter: splunk\nciamAdapterVersion: >=0.1,<1\n"
         "ciamAdapterSource: https://example.test/splunk\n")
TREE = (OU.format(LOG_ROUTES, "log-routes"), OU.format(ALERT_RULES, "alert-rules"),
        _route("security", ("audit",), ("ds", "web"), "siem"), _route("errors", ("error",), ("ds",), "siem-ops"))
RULES = {"idp-brute-force": _adopting("idp-brute-force", DETECTION),
         "idp-password-spray": _adopting("idp-password-spray", SPRAY)}
BINDINGS = (entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef="ciam_security", ciamRetentionDays="90"),
            entry(ALPHA, "siem-ops", "ciamLogDestination", ciamBindingRole="siem-ops",
                  ciamDestinationKind="siem-index", ciamProviderRef="ciam_ops", ciamRetentionDays="30"),
            entry(ALPHA, "page", "ciamAlertChannel", ciamBindingRole="alerts-page", ciamChannelKind="email",
                  ciamProviderRef="soc@example.test"))
SERVICES = services()._replace(logs=lambda m: SOURCES, detections=lambda m: PAIRS)


def _alpha(*rules, stack=STACK, bindings=BINDINGS):
    """Environment alpha/prod recording RULES, those given (LDIF) in place of the one of their name."""
    given = {r.split(",", 1)[0][len("dn: cn="):]: r for r in rules}
    _, alpha, _ = model(alpha=bindings, tree=(*TREE, *{**RULES, **given}.values(), stack))
    return alpha


def _searches(m, svc=SERVICES):
    return {n: dict(s) for n, s in read_conf(render(m, svc)[SAVED_SEARCHES])}


def _comments(m, svc=SERVICES):
    return [note_comment(n) for n in render_notes(m, svc)]


def test_a_sliding_rule_is_searched_again_every_step_over_its_window_its_groups_suppressed():
    brute = _searches(_alpha())["opsdir-idp-brute-force"]
    assert brute == {
        "description": "opsdir: realizes alert rule idp-brute-force",
        "search": '(index=ciam_ops OR index=ciam_security) eventName IN ("LOGIN-COMPLETED", "LOGIN-FAILED") '
                  'result="FAILED" | stats count by principal, realm | where count >= 10',
        "is_scheduled": "1", "cron_schedule": "*/1 * * * *", "dispatch.earliest_time": "-300s",
        "dispatch.latest_time": "now", "alert.suppress": "1", "alert.suppress.fields": "principal,realm",
        "alert.suppress.period": "300s", "counttype": "number of events", "relation": "greater than", "quantity": "0",
        "alert.digest_mode": "0", "disabled": "0"}
    assert overlap_step(300, 60) == 60 and overlap_step(3600, 60) == 720 and overlap_step(60, 60) is None


def test_a_fixed_rule_counts_distinct_values_over_the_clock_aligned_window_just_ended():
    spray = _searches(_alpha())["opsdir-idp-password-spray"]
    assert spray["search"] == ('(index=ciam_ops OR index=ciam_security) eventName IN ("LOGIN-COMPLETED", '
                               '"LOGIN-FAILED") result="FAILED" | stats dc(principal) AS value_count by client.ip '
                               '| where value_count >= 20')
    assert (spray["cron_schedule"], spray["dispatch.earliest_time"], spray["dispatch.latest_time"]) == (
        "*/15 * * * *", "-15m@m", "@m")
    assert "alert.suppress" not in spray and aligned_window(7200) == ("-2h@h", "@h")


def test_a_rule_without_a_threshold_alerts_per_matching_event():
    each = _alpha(_adopting("idp-brute-force", DETECTION, ciamGroupBy=(), ciamComparison=(), ciamThreshold=(),
                            ciamEvaluationPeriod=(), ciamWindowKind=()))
    brute = _searches(each)["opsdir-idp-brute-force"]
    assert brute["search"] == ('(index=ciam_ops OR index=ciam_security) eventName IN ("LOGIN-COMPLETED", '
                               '"LOGIN-FAILED") result="FAILED"')
    assert (brute["cron_schedule"], brute["dispatch.earliest_time"], brute["dispatch.latest_time"],
            brute["alert.digest_mode"]) == ("*/5 * * * *", "-5m@m", "@m", "0")
    (x, _), _ = splunk_rules(each, SERVICES)
    assert spl_search(x.det, x.mapping, ("a",)).startswith("index=a ") and timing(x.det, ())[1] is None


def test_on_enterprise_security_its_group_by_are_risk_and_threat_objects():
    es = STACK + "ciamOffering: enterprise-security\n"
    found = _searches(_alpha(stack=es))
    brute, spray = found["opsdir-idp-brute-force"], found["opsdir-idp-password-spray"]
    assert brute["action.correlationsearch.enabled"] == "1" and brute["action.notable"] == "1"
    assert brute["action.correlationsearch.annotations"] == '{"mitre_attack":["T1110"]}'
    assert brute["action.risk.param._risk"] == ('[{"risk_object_field": "principal", "risk_object_type": "user", '
                                                '"risk_score": 47}]')
    assert spray["action.risk.param._risk"] == ('[{"threat_object_field": "client.ip", "threat_object_type": '
                                                '"ip_address"}]')
    assert any("Splunk Enterprise Security" in c for c in _comments(_alpha(stack=es)))


def test_on_the_plain_platform_its_attack_is_named_and_a_documented_declaration_noted():
    comments = _comments(_alpha())
    assert any("alert rule idp-brute-force" in c and "ATT&CK tactics and techniques aren't rendered" in c
               for c in comments)
    assert any("alert rule idp-brute-force" in c and "documented only" in c for c in comments)
    assert not any("alert rule idp-password-spray" in c and "documented only" in c for c in comments)
    assert any("Splunk alert actions" in c for c in comments)


def test_what_it_cannot_write_is_a_blocker():
    short = _adopting("idp-brute-force", DETECTION, ciamEvaluationPeriod=("1m",))
    actor = _adopting("idp-password-spray", SPRAY, ciamGroupBy=("actor",))
    m = _alpha(short, actor)
    assert "opsdir-idp-brute-force" not in render(m, SERVICES).get(SAVED_SEARCHES, "")
    blockers = [note_comment(n) for n in render_notes(m, SERVICES) if n.severity == "blocker"]
    assert any("idp-brute-force" in c and "sliding window (60s) is too short" in c for c in blockers)
    assert any("idp-password-spray" in c and "names no field for actor" in c for c in blockers)
    odd = _alpha(_adopting("idp-brute-force", DETECTION, ciamEvaluationPeriod=("7m",), ciamWindowKind=("fixed",)))
    assert any("fixed window (420s) isn't one a cron schedule keeps" in note_comment(n)
               for n in render_notes(odd, SERVICES) if n.severity == "blocker")
    old = SERVICES._replace(detections=lambda m: (("fake-cloud", DETECTION._replace(mappings=(
        DetectionMapping("idp", "<8", FIELDS, SAID),))),))
    assert any("maps no version of its product" in note_comment(n) for n in render_notes(_alpha(), old))


def test_a_rule_an_alarm_binding_realizes_or_whose_logs_go_elsewhere_isnt_rendered_from_its_declaration():
    alarm = entry(ALPHA, "det-brute", "ciamAlarmBinding", ciamBindingRole="alarm-idp-brute-force",
                  ciamProviderRef="ciam-brute", ciamRealizes="idp-brute-force",
                  ciamMetric="index=ciam_security result=FAILED", ciamLogDestinationRole="siem")
    found = _searches(_alpha(bindings=(*BINDINGS, alarm)))
    assert "opsdir-idp-brute-force" not in found and "ciam-brute" in found
    elsewhere = _alpha(_adopting("idp-brute-force", DETECTION, ciamTargetRole=("db",)))
    assert [x.rule.dn.split(",")[0] for x, _ in splunk_rules(elsewhere, SERVICES)] == ["cn=idp-password-spray"]


def test_its_own_saved_searches_are_left_out_when_read_back():
    m = _alpha()
    text = render(m, SERVICES)[SAVED_SEARCHES]
    resources, _ = parse_conf({"savedsearches.conf": text})
    assert resources == ()
    from opsdir.connectors.roundtrip import round_trip
    from mini_estate import FAKE
    declaring = FAKE._replace(detections=(DETECTION, SPRAY))
    (rt,) = round_trip(m.d, "alpha/prod", installed=(declaring, ADAPTER._replace(logs=SOURCES)))
    assert rt.drift == () and "alpha/prod/savedsearches.conf" in rt.files


def test_the_signal_check_counts_a_natively_rendered_rule_as_evaluated():
    import datetime as dt
    from opsdir.connectors.observability import signal_check
    from opsdir.core.contract import PlanContext
    product = ADAPTER._replace(name="fake-cloud", detections=(DETECTION, SPRAY), siem_indexes=None, signals=())

    def said(m, adapters):
        ctx = PlanContext(m.d, m, m, None, dt.date(2026, 10, 18), {}, {}, ())
        return [text for _, text, *_ in signal_check(adapters)(ctx).actions]
    assert said(_alpha(), (ADAPTER, product)) == []
    unkept = said(_alpha(), (product,))
    assert len(unkept) == 2 and all("no SIEM index" in t and "role ds's logs" in t for t in unkept)

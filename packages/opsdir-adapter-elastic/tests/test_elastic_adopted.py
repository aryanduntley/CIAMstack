"""Alert rules adopting a product's declared detection as Elastic Security ES|QL rules: the query written from the
rule's canonical selector in the product's fields and values over the data streams its role's routes reach, counted
per group (or distinct values) to its threshold; a fixed window searched back to back, a sliding one searched again
every step over the whole window with its alerts suppressed per group; in the API documents and the Terraform alike;
the rules it can't write named as blockers; and its own rules left out when read back."""
import json

from opsdir.connectors.registry import services
from opsdir.core.contract import DetectionMapping, LogSource, ProductDetection
from opsdir.core.notes import note_comment
from opsdir.domains.observability.naming import ALERT_RULES, LOG_ROUTES
from opsdir_adapter_elastic.adapter import ADAPTER
from opsdir_adapter_elastic.adopted import elastic_rules, esql_field, esql_search, suppression_duration
from opsdir_adapter_elastic.read import parse_kibana
from opsdir_adapter_elastic.render import render_env, render_notes
from network_fixtures import ALPHA, entry, model

STREAM = "logs-ciam.security-prod"
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
                           threshold=20, window_seconds=3600, window_kind="fixed", techniques=("T1110.003",),
                           validation="lab-verified")
PAIRS = (("fake-cloud", DETECTION), ("fake-cloud", SPRAY))
SOURCES = (LogSource("ds", "servers", "audit/*.json", "json-lines", "audit"),)
API = "elastic/api/"


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


TREE = (OU.format(LOG_ROUTES, "log-routes"), OU.format(ALERT_RULES, "alert-rules"),
        f"dn: cn=security,{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
        "cn: security\nciamLogKind: audit\nciamPublishedBy: ds\nciamLogDestinationRole: siem\n",
        f"dn: cn=siem,ou=stack,{ALPHA}\nobjectClass: top\nobjectClass: ciamStackComponent\ncn: siem\n"
        "ciamStackRole: siem\nciamAdapter: elastic\nciamAdapterVersion: >=0.1,<1\n"
        "ciamAdapterSource: https://example.test/elastic\n")
RULES = {"idp-brute-force": _adopting("idp-brute-force", DETECTION),
         "idp-password-spray": _adopting("idp-password-spray", SPRAY)}
BINDINGS = (entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef=STREAM, ciamRetentionDays="90"),
            entry(ALPHA, "page", "ciamAlertChannel", ciamBindingRole="alerts-page", ciamChannelKind="email",
                  ciamProviderRef="soc@example.test"))
SERVICES = services()._replace(logs=lambda m: SOURCES, detections=lambda m: PAIRS)


def _alpha(*rules):
    """Environment alpha/prod recording RULES, those given (LDIF) in place of the one of their name."""
    given = {r.split(",", 1)[0][len("dn: cn="):]: r for r in rules}
    _, alpha, _ = model(alpha=BINDINGS, tree=(*TREE, *{**RULES, **given}.values()))
    return alpha


def _rules(m, svc=SERVICES):
    text = render_env(m, svc, ("api",))[f"{API}detection-rules.ndjson"]
    return {r["rule_id"]: r for r in map(json.loads, text.splitlines())}


def test_a_sliding_rule_runs_every_step_over_its_window_its_alerts_suppressed_per_group():
    brute = _rules(_alpha())["opsdir-idp-brute-force"]
    assert brute == {
        "rule_id": "opsdir-idp-brute-force", "name": "idp-brute-force",
        "description": "opsdir: realizes alert rule idp-brute-force", "type": "esql", "language": "esql",
        "query": f'FROM {STREAM} | WHERE eventName IN ("LOGIN-COMPLETED", "LOGIN-FAILED") AND result == "FAILED" '
                 "AND principal IS NOT NULL AND realm IS NOT NULL | STATS events = COUNT(*) BY principal, realm "
                 "| WHERE events >= 10",
        "interval": "1m", "from": "now-5m", "to": "now", "severity": "medium", "risk_score": 47, "enabled": True,
        "tags": ["opsdir"], "threat": brute["threat"],
        "investigation_fields": {"field_names": ["principal", "realm"]},
        "alert_suppression": {"group_by": ["principal", "realm"], "duration": {"value": 5, "unit": "m"},
                              "missing_fields_strategy": "suppress"}}
    assert brute["threat"][0]["tactic"]["name"] == "Credential Access"


def test_a_fixed_rule_counts_distinct_values_over_back_to_back_windows():
    spray = _rules(_alpha())["opsdir-idp-password-spray"]
    assert spray["query"] == (f'FROM {STREAM} | WHERE eventName IN ("LOGIN-COMPLETED", "LOGIN-FAILED") AND result == '
                              '"FAILED" AND client.ip IS NOT NULL AND principal IS NOT NULL | STATS value_count = '
                              "COUNT_DISTINCT(principal) BY client.ip | WHERE value_count >= 20")
    assert (spray["interval"], spray["from"]) == ("1h", "now-1h") and "alert_suppression" not in spray
    assert any("idp-password-spray" in note_comment(n) and "back to back" in note_comment(n)
               for n in render_notes(_alpha(), SERVICES))
    assert esql_field("user-name") == "`user-name`" and esql_field("@timestamp") == "@timestamp"
    assert suppression_duration(5400) == {"value": 90, "unit": "m"}


def test_a_rule_without_a_threshold_alerts_per_matching_event_with_its_metadata():
    each = _alpha(_adopting("idp-brute-force", DETECTION, ciamGroupBy=(), ciamComparison=(), ciamThreshold=(),
                            ciamEvaluationPeriod=(), ciamWindowKind=()))
    brute = _rules(each)["opsdir-idp-brute-force"]
    assert brute["query"] == (f'FROM {STREAM} METADATA _id, _index, _version | WHERE eventName IN '
                              '("LOGIN-COMPLETED", "LOGIN-FAILED") AND result == "FAILED"')
    assert (brute["interval"], brute["from"]) == ("5m", "now-5m")
    (x, found), _ = elastic_rules(each, SERVICES)
    assert esql_search(x.det, x.mapping, ("a", "b")).startswith("FROM a, b METADATA")


def test_the_terraform_says_the_same_with_the_suppression_duration_as_text():
    main = render_env(_alpha(), SERVICES, ("terraform",))["elastic/terraform/main.tf"]
    assert 'resource "elasticstack_kibana_security_detection_rule" "opsdir_idp_brute_force" {' in main
    assert 'duration                = "5m"' in main and 'missing_fields_strategy = "suppress"' in main


def test_what_it_cannot_write_is_a_blocker_and_documented_declarations_a_note():
    m = _alpha(_adopting("idp-brute-force", DETECTION, ciamEvaluationPeriod=("1m",)),
               _adopting("idp-password-spray", SPRAY, ciamGroupBy=("actor",)))
    assert API + "detection-rules.ndjson" not in render_env(m, SERVICES, ("api",))
    blockers = [note_comment(n) for n in render_notes(m, SERVICES) if n.severity == "blocker"]
    assert any("idp-brute-force" in c and "sliding window (60s) is too short" in c for c in blockers)
    assert any("idp-password-spray" in c and "names no field for actor" in c for c in blockers)
    comments = [note_comment(n) for n in render_notes(_alpha(), SERVICES)]
    assert any("idp-brute-force" in c and "documented only" in c for c in comments)
    assert any("Elastic rule actions" in c for c in comments)


def test_its_own_rules_are_left_out_when_read_back():
    m = _alpha()
    resources, _ = parse_kibana({"detection-rules.ndjson": render_env(m, SERVICES, ("api",))[
        f"{API}detection-rules.ndjson"]})
    assert resources == ()
    from opsdir.connectors.roundtrip import round_trip
    from mini_estate import FAKE
    trips = round_trip(m.d, "alpha/prod", installed=(FAKE._replace(detections=(DETECTION, SPRAY)),
                                                      ADAPTER._replace(logs=SOURCES)))
    kibana = next(rt for rt in trips if rt.importer == "elastic/kibana")
    assert all(rt.drift == () for rt in trips) and "alpha/prod/detection-rules.ndjson" in kibana.files

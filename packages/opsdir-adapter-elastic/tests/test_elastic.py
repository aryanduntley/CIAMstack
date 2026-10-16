"""The Elastic add-on: the data streams an environment keeps logs in (an ILM policy per stream attached through its
dataset's component template, a snapshot policy archiving what it keeps longer in all), its detections as ES|QL rules
counting events per window, both as API documents and as Terraform for the elasticstack provider, what it leaves to
the Elastic team as render notes; read back from its own documents unchanged and from the Elasticsearch and Kibana
answers (ILM or the data stream lifecycle, snapshot archives, rules of every language); collected read-only with an API
key; and the provider adapters leaving its streams to it."""
import json

from opsdir.connectors.collecting import collect
from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.core.notes import note_comment
from opsdir.domains.observability.naming import ALERT_RULES, LOG_ROUTES
from opsdir_adapter_elastic.adapter import ADAPTER
from opsdir_adapter_elastic.collect import COLLECTORS, elasticsearch_steps, kibana_steps
from opsdir_adapter_elastic.detections import base_query, esql_query, rule_body, source_of
from opsdir_adapter_elastic.naming import custom_template, is_stream, stream_name
from opsdir_adapter_elastic.read import es_days, parse_elasticsearch, parse_kibana, read_elasticsearch, read_kibana
from opsdir_adapter_elastic.render import render_env, render_notes
from network_fixtures import ALPHA, entry, model

STREAM = "logs-ciam.security-prod"
OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"
SOURCES = (LogSource("ds", "servers", "audit/*.json", "json-lines", "audit"),)
SEARCH = f'FROM {STREAM} | WHERE event.category == "authentication" AND event.outcome == "failure"'
API = "elastic/api/"


def _route(cn, kinds, roles, dest):
    return (f"dn: cn={cn},{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
            f"cn: {cn}\n" + "".join(f"ciamLogKind: {k}\n" for k in kinds)
            + "".join(f"ciamPublishedBy: {r}\n" for r in roles) + f"ciamLogDestinationRole: {dest}\n")


def _rule(cn, **attrs):
    return (f"dn: cn={cn},{ALERT_RULES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamAlertRule\n"
            f"cn: {cn}\n" + "".join(f"{k}: {v}\n" for k, v in attrs.items()))


TREE = (OU.format(LOG_ROUTES, "log-routes"), OU.format(ALERT_RULES, "alert-rules"),
        _route("security", ("audit",), ("ds", "web"), "siem"),
        _rule("login-failures", ciamSignal="login-failures", ciamComparison="gt", ciamThreshold="50 /min",
              ciamEvaluationPeriod="5m", ciamSeverity="sev1", ciamAlertRole="alerts-page"),
        _rule("too-quiet", ciamSignal="logins", ciamComparison="lt", ciamThreshold="1 /min",
              ciamAlertRole="alerts-page"),
        _rule("in-kql", ciamSignal="x", ciamComparison="gt", ciamThreshold="1 /min", ciamAlertRole="alerts-page"),
        _rule("elsewhere", ciamSignal="y", ciamComparison="ge", ciamThreshold="3 /min", ciamAlertRole="alerts-page"),
        _rule("unsearched", ciamSignal="z", ciamComparison="gt", ciamThreshold="1 /min", ciamAlertRole="alerts-page"),
        f"dn: cn=siem,ou=stack,{ALPHA}\nobjectClass: top\nobjectClass: ciamStackComponent\ncn: siem\n"
        "ciamStackRole: siem\nciamAdapter: elastic\nciamAdapterVersion: >=0.1,<1\n"
        "ciamAdapterSource: https://example.test/elastic\n")


def _detection(cn, realizes, **attrs):
    return entry(ALPHA, cn, "ciamAlarmBinding", ciamBindingRole=f"alarm-{realizes}", ciamProviderRef=f"ciam-{realizes}",
                 ciamRealizes=realizes, ciamLogDestinationRole="siem", **attrs)


BINDINGS = (entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef=STREAM, ciamRetentionDays="90", ciamTotalRetentionDays="365",
                  ciamArchiveRef="found-snapshots"),
            entry(ALPHA, "page", "ciamAlertChannel", ciamBindingRole="alerts-page", ciamChannelKind="email",
                  ciamProviderRef="soc@example.test"),
            _detection("det-login", "login-failures", ciamMetric=SEARCH),
            _detection("det-quiet", "too-quiet", ciamMetric=SEARCH),
            _detection("det-kql", "in-kql", ciamMetric="event.outcome:failure", ciamSearchLanguage="kuery"),
            _detection("det-elsewhere", "elsewhere", ciamMetric="FROM logs-other-prod | WHERE true"),
            _detection("det-none", "unsearched"))


def _alpha(*bindings, tree=TREE):
    from opsdir.core.interchange.ldif import LdifRecord
    roots = tuple(LdifRecord(f"cn={s},{ALPHA}", "modify", {}, (("add", "ciamInstallRoot", (r,)),))
                  for s, r in (("ds-1", "/opt/ds"), ("web-1", "/opt/web")))
    _, alpha, _ = model(alpha=bindings or BINDINGS, tree=tree, changes=roots)
    return alpha


SERVICES = services()._replace(logs=lambda m: SOURCES)


def _siem(m):
    return next(b for b in m.bindings if b.dn.startswith("cn=siem,"))


def _spec(m, rule):
    from opsdir_adapter_elastic.detections import elastic_detections
    return next(s for s in elastic_detections(m) if s.rule.dn.startswith(f"cn={rule},"))


def test_elastic_data_streams_are_named_by_their_stream_and_kept_by_the_add_on():
    m = _alpha()
    assert stream_name(_siem(m)) == STREAM and custom_template(STREAM) == "logs-ciam.security@custom"
    assert is_stream("logs-a_b.c-ns1") and not is_stream("ciam_security") and not is_stream("logs-a-b-c")
    assert not is_stream("metrics-a-b") and not is_stream("logs-.a-b")
    assert ADAPTER.siem_indexes(m, _siem(m)) and services().siem_keeper(m, _siem(m)) == "elastic"


def test_each_stream_gets_an_ilm_policy_attached_by_its_dataset_hook_and_a_snapshot_archive():
    files = render_env(_alpha(), SERVICES)
    ilm = json.loads(files[f"{API}ilm-policies.json"])
    assert ilm == {f"opsdir-{STREAM}": {"policy": {
        "phases": {"hot": {"min_age": "0ms", "actions": {"rollover": {"max_age": "1d",
                                                                      "max_primary_shard_size": "50gb"}}},
                   "delete": {"min_age": "90d", "actions": {"wait_for_snapshot": {"policy": f"opsdir-{STREAM}"},
                                                            "delete": {"delete_searchable_snapshot": True}}}},
        "_meta": {"managed_by": "opsdir", "data_stream": STREAM}}}}
    templates = json.loads(files[f"{API}component-templates.json"])["component_templates"]
    assert templates == [{"name": "logs-ciam.security@custom", "component_template": {
        "template": {"settings": {"index": {"lifecycle": {"name": f"opsdir-{STREAM}"}}}},
        "_meta": {"managed_by": "opsdir"}}}]
    slm = json.loads(files[f"{API}slm-policies.json"])
    assert slm == {f"opsdir-{STREAM}": {"policy": {
        "name": f"<opsdir-{STREAM}-{{now/d}}>", "schedule": "0 30 1 * * ?", "repository": "found-snapshots",
        "config": {"indices": [STREAM], "include_global_state": False}, "retention": {"expire_after": "275d"}}}}


def test_a_stream_kept_forever_has_no_delete_phase_and_one_without_retention_renders_no_policy():
    forever = entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                    ciamProviderRef=STREAM, ciamRetentionDays="0")
    files = render_env(_alpha(forever, *BINDINGS[1:]), SERVICES)
    assert set(json.loads(files[f"{API}ilm-policies.json"])[f"opsdir-{STREAM}"]["policy"]["phases"]) == {"hot"}
    assert f"{API}slm-policies.json" not in files
    unkept = entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                   ciamProviderRef=STREAM)
    m = _alpha(unkept, *BINDINGS[1:])
    assert f"{API}ilm-policies.json" not in render_env(m, SERVICES)
    assert any("records no retention (ciamRetentionDays): no lifecycle policy rendered" in note_comment(n)
               for n in render_notes(m, SERVICES))


def test_a_detection_counts_events_per_window_every_window_of_the_period_breaching():
    m = _alpha()
    rules = [json.loads(x) for x in render_env(m, SERVICES)[f"{API}detection-rules.ndjson"].splitlines()]
    query = (f"{SEARCH} | STATS events = COUNT(*) BY slot = BUCKET(@timestamp, 60 seconds) | WHERE events > 50 "
             "| STATS breaching = COUNT(*) | WHERE breaching >= 5")
    assert rules == [{"rule_id": "ciam-login-failures", "name": "login-failures",
                      "description": "opsdir: realizes alert rule login-failures", "type": "esql", "language": "esql",
                      "query": query, "interval": "5m", "from": "now-5m", "to": "now", "severity": "high",
                      "risk_score": 73, "enabled": True, "tags": ["opsdir"]}]
    spec = _spec(m, "login-failures")
    from opsdir.domains.observability.alarms import detection_condition
    assert esql_query(SEARCH, spec.rule, detection_condition(spec.rule)[0]) == query
    assert base_query(query) == SEARCH and source_of(SEARCH) == STREAM and source_of("ROW a = 1") is None
    assert rule_body(m, _spec(m, "in-kql")) is None and rule_body(m, _spec(m, "elsewhere")) is None


def test_the_terraform_target_says_the_same_with_credentials_left_to_the_environment():
    files = render_env(_alpha(), SERVICES, ("terraform",))
    assert set(files) == {"elastic/terraform/versions.tf", "elastic/terraform/main.tf"}
    versions, main = files["elastic/terraform/versions.tf"], files["elastic/terraform/main.tf"]
    assert 'source  = "elastic/elasticstack"' in versions and 'version = "~> 0.16.6"' in versions
    assert 'provider "elasticstack" {\n  elasticsearch {\n  }\n  kibana {\n  }\n}\n' in versions
    assert "api_key" not in versions + main and "password" not in versions + main
    for kind in ("elasticstack_elasticsearch_index_lifecycle", "elasticstack_elasticsearch_component_template",
                 "elasticstack_elasticsearch_snapshot_lifecycle", "elasticstack_kibana_security_detection_rule"):
        assert f'resource "{kind}"' in main
    assert 'expire_after         = "275d"' in main and '    wait_for_snapshot {\n      policy = ' in main
    assert '\\"authentication\\"' in main and "space_id" not in main
    assert main.startswith("# Generated by opsdir from " + ALPHA)
    assert all(f"# {note_comment(n)}" in main.splitlines() for n in render_notes(_alpha(), SERVICES))


def test_what_it_leaves_to_the_elastic_team_and_cannot_ship_is_named():
    texts = [(n.severity, note_comment(n)) for n in render_notes(_alpha(), SERVICES)]
    subjects = {t.split(": ", 2)[1]: s for s, t in texts}
    assert subjects["Elastic rule actions"] == "action" and subjects["Elastic Agent"] == "action"
    assert subjects[f"Elastic data stream {STREAM}"] == "action"
    assert ("blocker", "NOTE: alert rule too-quiet: not rendered: a SIEM detection fires on more matching events "
            "than its threshold, not on comparison lt (windows without events aren't counted)") in texts
    assert ("blocker", "NOTE: alert rule in-kql: not rendered: its search is written in kuery (ciamSearchLanguage), "
            "and opsdir renders Elastic's detections as ES|QL rules (a threshold rule can't require every window of "
            "the period)") in texts
    assert ("blocker", f"NOTE: alert rule elsewhere: not rendered: its search (ciamMetric) doesn't start FROM "
            f"{STREAM}, the data stream it searches") in texts
    assert ("note", "NOTE: alert rule unsearched: not rendered: its alarm det-none records no metric (ciamMetric)") \
        in texts
    (agent,) = (n for n in render_notes(_alpha(), SERVICES) if n.subject == "Elastic Agent")
    assert agent.how == (f"Collect /opt/ds/audit/*.json on role ds (ds-1) into {STREAM}",)


def test_a_containers_output_to_a_stream_is_a_blocker():
    from opsdir.domains.compute.naming import WORKLOADS, workload_dn
    tree = (*TREE, OU.format(WORKLOADS, "workloads"),
            f"dn: {workload_dn('web')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: web\n"
            "ciamWorkloadKind: deployment\nciamTargetRole: web\nciamNamespace: ciam\nciamClusterRole: k8s\n"
            "ciamWorkloadRole: web-workload\n")
    m = _alpha(*BINDINGS, entry(ALPHA, "web", "ciamWorkloadBinding", ciamBindingRole="web-workload",
                                ciamContainerImage="web=registry.example.test/web:1"),
               entry(ALPHA, "k8s", "ciamCluster", ciamBindingRole="k8s", ciamProviderRef="cluster-1"), tree=tree)
    found = services()._replace(logs=lambda m: (*SOURCES, LogSource("web", "kubernetes", None, "json-lines", "audit")))
    assert ("blocker", "NOTE: log route security: role web's container output not shipped: its destination "
            f"{STREAM} is an Elastic data stream, and nothing rendered ships a container's output there") in [
        (n.severity, note_comment(n)) for n in render_notes(m, found)]


def test_an_archive_with_no_place_recorded_and_streams_sharing_a_dataset_are_named():
    unplaced = entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                     ciamProviderRef=STREAM, ciamRetentionDays="90", ciamTotalRetentionDays="365")
    sibling = entry(ALPHA, "siem-stage", "ciamLogDestination", ciamBindingRole="siem-stage",
                    ciamDestinationKind="siem-index", ciamProviderRef="logs-ciam.security-stage",
                    ciamRetentionDays="30")
    m = _alpha(unplaced, sibling, *BINDINGS[1:])
    texts = {note_comment(n): n.severity for n in render_notes(m, SERVICES)}
    assert texts[f"NOTE: Elastic data stream {STREAM}: keeps logs 90 days searchable and 365 in all, but records no "
                 "archive (ciamArchiveRef: the snapshot repository): no snapshot policy rendered, so they are deleted "
                 "after 90 days"] == "action"
    assert texts["NOTE: Elastic data stream logs-ciam.security-stage: its retention isn't rendered: its dataset's "
                 f"component template logs-ciam.security@custom attaches one policy to every namespace, "
                 f"opsdir-{STREAM} (of {STREAM}, which keeps logs differently)"] == "blocker"
    files = render_env(m, SERVICES)
    assert list(json.loads(files[f"{API}ilm-policies.json"])) == [f"opsdir-{STREAM}"]
    assert f"{API}slm-policies.json" not in files


def test_its_own_documents_read_back_unchanged():
    m = _alpha()
    files = render_env(m, SERVICES, ("api",))
    recorded = {b.dn: b for b in m.bindings}
    for read in (read_elasticsearch, read_kibana):
        imported = read({f"alpha/prod/{p.rsplit('/', 1)[1]}": t for p, t in files.items()}, m.d)
        for _, entries in imported.groups:
            for e in entries:
                assert dict(e.attrs) == {k: v for k, v in recorded[e.dn].attrs.items() if k != "objectClass"}
    resources, notices = parse_elasticsearch({p.rsplit("/", 1)[1]: t for p, t in files.items()})
    assert [(r.ref, r.attrs) for r in resources] == [(STREAM, {
        "ciamDestinationKind": ("siem-index",), "ciamRetentionDays": ("90",), "ciamTotalRetentionDays": ("365",),
        "ciamArchiveRef": ("found-snapshots",)})] and notices == ()


def test_the_elasticsearch_answers_read_as_retention_from_ilm_or_the_data_stream_lifecycle():
    streams = {"data_streams": [
        {"name": STREAM, "ilm_policy": "logs", "next_generation_managed_by": "Index Lifecycle Management"},
        {"name": "logs-ciam.ops-prod", "next_generation_managed_by": "Data stream lifecycle",
         "lifecycle": {"enabled": True, "data_retention": "30d"}},
        {"name": "logs-ciam.debug-prod", "next_generation_managed_by": "Data stream lifecycle",
         "lifecycle": {"enabled": True}},
        {"name": "logs-ciam.odd-prod", "ilm_policy": "odd"},
        {"name": "metrics-system.cpu-prod", "ilm_policy": "metrics"}, {"name": ".fleet-actions"}]}
    ilm = {"logs": {"policy": {"phases": {"hot": {"actions": {}}, "delete": {"min_age": "180d", "actions": {}}}}},
           "odd": {"policy": {"phases": {"delete": {"min_age": "36h", "actions": {}}}}}}
    slm = {"nightly": {"policy": {"repository": "s3-archive", "config": {"indices": ["logs-ciam.security-*"]},
                                  "retention": {"expire_after": "185d"}}}}
    resources, notices = parse_elasticsearch({"data-streams.json": json.dumps(streams),
                                              "ilm-policies.json": json.dumps(ilm),
                                              "slm-policies.json": json.dumps(slm)})
    by_ref = {r.ref: r.attrs for r in resources}
    assert set(by_ref) == {STREAM, "logs-ciam.ops-prod", "logs-ciam.debug-prod", "logs-ciam.odd-prod"}
    assert by_ref[STREAM] == {"ciamDestinationKind": ("siem-index",), "ciamRetentionDays": ("180",),
                              "ciamTotalRetentionDays": ("365",), "ciamArchiveRef": ("s3-archive",)}
    assert by_ref["logs-ciam.ops-prod"]["ciamRetentionDays"] == ("30",)
    assert by_ref["logs-ciam.debug-prod"]["ciamRetentionDays"] == ("0",)
    assert notices == ("Elastic data stream logs-ciam.odd-prod: ILM delete min_age 36h isn't whole days; read as 1",)
    assert es_days("2d") == (2, None) and es_days("soon")[0] is None


def test_the_kibana_rules_read_as_detections_of_every_language():
    wrapped = rule_body(_alpha(), _spec(_alpha(), "login-failures"))
    kql = {"rule_id": "kql-1", "type": "threshold", "language": "kuery", "query": "event.outcome:failure",
           "index": [STREAM], "description": "opsdir: realizes alert rule in-kql"}
    export = "\n".join((json.dumps(wrapped), json.dumps(kql), json.dumps({"exported_count": 2})))
    resources, notices = parse_kibana({"detection-rules.ndjson": export})
    alarms = {r.ref: r for r in resources if r.kind == "alarm"}
    assert alarms["ciam-login-failures"].attrs == {"ciamRealizes": ("login-failures",), "ciamMetric": (SEARCH,)}
    assert alarms["ciam-login-failures"].links == {"ciamLogDestinationRole": STREAM}
    assert alarms["kql-1"].attrs == {"ciamRealizes": ("in-kql",), "ciamMetric": ("event.outcome:failure",),
                                     "ciamSearchLanguage": ("kuery",)}
    assert [r.ref for r in resources if r.kind == "logs"] == [STREAM]
    assert notices == ("Elastic detection rule kql-1: a threshold rule: its search is read, not its condition "
                       "(opsdir renders detections as ES|QL rules)",)
    pages = parse_kibana({"detection-rules.json": json.dumps({"data": [wrapped]}),
                          "detection-rules.2.json": json.dumps({"data": [kql]})})[0]
    assert sorted(r.ref for r in pages if r.kind == "alarm") == ["ciam-login-failures", "kql-1"]


SOURCE = dict(ciamCredentialRole="elastic-reader", ciamCredentialScheme="api-key")


def _collecting(space=None):
    extra = (entry(ALPHA, "es", "ciamCollectionSource", ciamBindingRole="collect-es",
                   ciamImporter="elastic/elasticsearch", ciamSourceRef="https://es.example.test:9243", **SOURCE),
             entry(ALPHA, "kb", "ciamCollectionSource", ciamBindingRole="collect-kb", ciamImporter="elastic/kibana",
                   ciamSourceRef="https://kb.example.test:9243/", **SOURCE),
             entry(ALPHA, "elastic-reader", "ciamSecretRef", ciamBindingRole="elastic-reader",
                   ciamRefUri="fake://kv/elastic-reader"))
    tree = (*TREE, *(("dn: ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: settings\n",
                      "dn: cn=elastic-kibana-space,ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: "
                      f"ciamEstateSetting\ncn: elastic-kibana-space\nciamEstateValue: {space}\n") if space else ()))
    return _alpha(*BINDINGS, *extra, tree=tree)


def test_the_collectors_read_with_an_api_key_and_page_the_rules():
    m = _collecting()
    key = ("api-key", "fake://kv/elastic-reader", None, "Authorization", "ApiKey ")
    assert [(p, r.url, r.credential) for p, r in elasticsearch_steps(m.d, m, {}, {})] == [
        ("alpha/prod/data-streams.json", "https://es.example.test:9243/_data_stream", key),
        ("alpha/prod/ilm-policies.json", "https://es.example.test:9243/_ilm/policy", key),
        ("alpha/prod/slm-policies.json", "https://es.example.test:9243/_slm/policy", key)]
    (first,) = kibana_steps(m.d, m, {}, {})
    assert first[0] == "alpha/prod/detection-rules.json" and first[1].url == (
        "https://kb.example.test:9243/api/detection_engine/rules/_find?per_page=1000&page=1")
    done = {"alpha/prod/detection-rules.json": json.dumps({"data": [], "total": 1500})}
    assert [p for p, _ in kibana_steps(m.d, m, done, {})] == ["alpha/prod/detection-rules.2.json"]
    c = collect("elastic/elasticsearch", COLLECTORS[0], m.d, m, lambda r: (json.dumps({}), None))
    assert c.problems == () and len(c.files) == 3


def test_rules_are_read_from_the_kibana_space_the_setting_names():
    m = _collecting("security")
    (first,) = kibana_steps(m.d, m, {}, {})
    assert first[1].url.startswith("https://kb.example.test:9243/s/security/api/detection_engine/rules/_find")
    assert 'space_id' in render_env(m, SERVICES, ("terraform",))["elastic/terraform/main.tf"]


def test_provider_adapters_leave_an_elastic_stream_to_it():
    from opsdir_adapter_aws.log_agent import log_notes
    m = _alpha()
    theirs = SERVICES._replace(siem_keeper=lambda m, b: None)
    assert any("isn't a CloudWatch log group" in note_comment(n) for n in log_notes(m, theirs))
    assert not any("isn't a CloudWatch log group" in note_comment(n) for n in log_notes(m, SERVICES))


def test_the_render_reads_back_through_the_round_trip_without_drift():
    from opsdir.connectors.roundtrip import round_trip
    from mini_estate import FAKE
    trips = round_trip(_alpha().d, "alpha/prod", installed=(FAKE, ADAPTER._replace(logs=SOURCES)))
    assert sorted(rt.importer for rt in trips) == ["elastic/elasticsearch", "elastic/kibana"]
    assert all(rt.drift == () for rt in trips)

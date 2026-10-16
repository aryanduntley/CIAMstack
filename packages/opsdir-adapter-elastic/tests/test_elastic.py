"""The Elastic add-on: the data streams an environment keeps logs in (an ILM policy per stream attached through its
dataset's component template, a snapshot policy archiving what it keeps longer in all; on Serverless the data stream
lifecycle), its detections as ES|QL rules counting events per window, the Fleet policies shipping the logs there (from
servers' files and Kubernetes containers), all as API documents and as Terraform for the elasticstack provider, what
it leaves to the Elastic team as render notes; read back from its own documents unchanged and from the Elasticsearch
and Kibana answers (ILM or the data stream lifecycle, snapshot archives, rules of every language, the offering);
collected read-only with an API key; and the provider adapters leaving its streams to it."""
import json
import pathlib
import subprocess

import pytest

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
    assert subjects["Elastic rule actions"] == "action" and subjects["Elastic Agent on role ds"] == "action"
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
    (agent,) = (n for n in render_notes(_alpha(), SERVICES) if n.subject == "Elastic Agent on role ds")
    assert agent.how == ("Install Elastic Agent on ds-1 enrolled in opsdir-alpha-prod-ds: elastic-agent install --url "
                         "<Fleet Server URL> --enrollment-token <its enrollment token>",
                         "Applying the API documents: install the filestream integration package 2.5.1 first (POST "
                         "/api/fleet/epm/packages/filestream/2.5.1); the Terraform installs it")


NDJSON = '- ndjson:\n    target: ""\n    overwrite_keys: true\n    add_error_key: true\n'


def test_servers_ship_their_files_through_a_fleet_agent_policy_per_role_and_a_filestream_policy_per_file():
    files = render_env(_alpha(), SERVICES)
    assert json.loads(files[f"{API}fleet-agent-policies.json"]) == {"items": [{
        "id": "opsdir-alpha-prod-ds", "name": "opsdir-alpha-prod-ds", "namespace": "prod",
        "description": "opsdir: Elastic Agent on role ds's servers in alpha/prod",
        "monitoring_enabled": ["logs", "metrics"]}]}
    assert json.loads(files[f"{API}fleet-package-policies.json"]) == {"items": [{
        "id": "opsdir-alpha-prod-ds-audit-json", "name": "opsdir-alpha-prod-ds-audit-json",
        "description": f"opsdir: audit/*.json on role ds into {STREAM} (log route security)", "namespace": "prod",
        "policy_ids": ["opsdir-alpha-prod-ds"], "package": {"name": "filestream", "version": "2.5.1"},
        "inputs": {"filestream-filestream": {"enabled": True, "streams": {"filestream.filestream": {
            "enabled": True, "vars": {"paths": ["/opt/ds/audit/*.json"], "data_stream.dataset": "ciam.security",
                                      "parsers": NDJSON}}}}}}]}
    main = files["elastic/terraform/main.tf"]
    for kind in ("elasticstack_fleet_integration", "elasticstack_fleet_agent_policy",
                 "elasticstack_fleet_integration_policy"):
        assert f'resource "{kind}"' in main
    assert "agent_policy_id     = elasticstack_fleet_agent_policy.opsdir_alpha_prod_ds.policy_id" in main
    assert 'paths                 = ["/opt/ds/audit/*.json"]' in main and "token" not in main.replace(
        "enrollment token", "")


def _version(name, value):
    return ("dn: ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: settings\n",
            f"dn: cn={name},ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamEstateSetting\ncn: {name}\n"
            f"ciamEstateValue: {value}\n")


def test_a_route_taking_some_lines_drops_the_others_and_a_file_goes_to_one_stream():
    from opsdir_adapter_elastic.fleet import line_filter, parsers
    am = LogSource("ds", "servers", "audit/*.json", "json-lines", "audit", (("eventName", "AM-ACCESS", "access"),))
    assert line_filter(am, ("audit",)) == [{"drop_event": {"when": {"regexp": {"eventName": "^AM\\-ACCESS"}}}}]
    assert line_filter(am, ("access",)) == [{"drop_event": {"when": {"not": {"regexp": {
        "eventName": "^AM\\-ACCESS"}}}}}]
    assert line_filter(am, ("audit", "access")) == []
    mixed = LogSource("ds", "servers", "x.log", "mixed", "error", (("eventName", "", "audit"),))
    assert line_filter(mixed, ("audit",)) == [{"drop_event": {"when": {"not": {"has_fields": ["eventName"]}}}}]
    assert parsers(mixed) == [{"ndjson": {"target": "", "overwrite_keys": True, "ignore_decoding_error": True}}]
    text = LogSource("ds", "servers", "logs/errors", "text", "error", line_start=r"^\[")
    assert parsers(text) == [{"multiline": {"type": "pattern", "pattern": r"^\[", "negate": True, "match": "after"}}]
    other = entry(ALPHA, "siem-ops", "ciamLogDestination", ciamBindingRole="siem-ops", ciamDestinationKind="siem-index",
                  ciamProviderRef="logs-ciam.ops-prod", ciamRetentionDays="30")
    tree = (*TREE, _route("ops", ("access",), ("ds",), "siem-ops"), *_version("elastic-filestream-version", "1.2.0"))
    m = _alpha(*BINDINGS, other, tree=tree)
    found = SERVICES._replace(logs=lambda m: (am,))
    (policy,) = json.loads(render_env(m, found, ("api",))[f"{API}fleet-package-policies.json"])["items"]
    variables = policy["inputs"]["filestream-filestream"]["streams"]["filestream.filestream"]["vars"]
    assert variables["processors"] == ('- drop_event:\n    when:\n      not:\n        regexp:\n          '
                                       'eventName: "^AM\\\\-ACCESS"\n')
    assert variables["data_stream.dataset"] == "ciam.ops" and policy["package"]["version"] == "1.2.0"
    assert ("blocker", f"NOTE: log route security: audit/*.json on role ds not shipped to {STREAM}: another route "
            "already ships it to logs-ciam.ops-prod, and its integration policy reads it into that stream") in [
        (n.severity, note_comment(n)) for n in render_notes(m, found)]


def _on_kubernetes(*sources):
    from opsdir.domains.compute.naming import WORKLOADS, workload_dn
    tree = (*TREE, OU.format(WORKLOADS, "workloads"),
            f"dn: {workload_dn('web')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: web\n"
            "ciamWorkloadKind: deployment\nciamTargetRole: web\nciamNamespace: ciam\nciamClusterRole: k8s\n"
            "ciamWorkloadRole: web-workload\n")
    m = _alpha(*BINDINGS, entry(ALPHA, "web", "ciamWorkloadBinding", ciamBindingRole="web-workload",
                                ciamContainerImage="web=registry.example.test/web:1"),
               entry(ALPHA, "k8s", "ciamCluster", ciamBindingRole="k8s", ciamProviderRef="cluster-1"), tree=tree)
    return m, services()._replace(logs=lambda m: (*SOURCES, *sources))


def test_container_output_ships_through_a_kubernetes_policy_picking_the_roles_pods():
    m, found = _on_kubernetes(LogSource("web", "kubernetes", None, "json-lines", "audit"),
                              LogSource("web", "kubernetes", None, "text", "audit", container="audit-tail"))
    files = render_env(m, found)
    agents = json.loads(files[f"{API}fleet-agent-policies.json"])["items"]
    assert [a["id"] for a in agents] == ["opsdir-alpha-prod-ds", "opsdir-alpha-prod-kubernetes"]
    policies = {p["id"]: p for p in json.loads(files[f"{API}fleet-package-policies.json"])["items"]}
    main, tail = policies["opsdir-alpha-prod-web-containers"], policies["opsdir-alpha-prod-web-audit-tail"]
    assert main["package"] == {"name": "kubernetes", "version": "1.85.5"}
    assert main["policy_ids"] == ["opsdir-alpha-prod-kubernetes"] and main["namespace"] == "prod"
    stream = main["inputs"]["container-logs-filestream"]["streams"]["kubernetes.container_logs"]
    assert stream == {"enabled": True, "vars": {"data_stream.dataset": "ciam.security", "condition": (
        "${kubernetes.labels.opsdir.io/role} == 'web' and ${kubernetes.namespace} == 'ciam' and "
        "${kubernetes.container.name} != 'audit-tail'")}}
    assert tail["inputs"]["container-logs-filestream"]["streams"]["kubernetes.container_logs"]["vars"][
        "condition"].endswith("and ${kubernetes.container.name} == 'audit-tail'")
    assert [k for k, v in main["inputs"].items() if v["enabled"]] == ["container-logs-filestream"]
    assert len(main["inputs"]) == 12
    notes = {note_comment(n).split(": ", 2)[1]: n for n in render_notes(m, found)}
    assert notes["Elastic Agent on Kubernetes"].severity == "action"
    assert notes["Elastic Agent on Kubernetes"].how[0] == (
        "Deploy Elastic Agent managed by Fleet on k8s enrolled in opsdir-alpha-prod-kubernetes (FLEET_ENROLL=1, "
        "FLEET_URL, FLEET_ENROLLMENT_TOKEN from a Secret)")
    assert not any(n.severity == "blocker" and "container output" in note_comment(n) for n in notes.values())
    assert 'condition = "${kubernetes' not in files["elastic/terraform/main.tf"]
    assert "$${kubernetes.labels.opsdir.io/role}" in files["elastic/terraform/main.tf"]


def test_a_route_taking_some_container_lines_ships_them_whole():
    m, found = _on_kubernetes(LogSource("web", "kubernetes", None, "mixed", "error", (("eventName", "", "audit"),)))
    assert ("note", "NOTE: log route security: role web's containers output is shipped whole to "
            f"{STREAM}: container lines aren't decoded here, so lines of the kinds the route doesn't take reach the "
            "stream too") in [(n.severity, note_comment(n)) for n in render_notes(m, found)]


SERVERLESS = tuple(t.replace("ciamAdapterSource: https://example.test/elastic\n",
                             "ciamAdapterSource: https://example.test/elastic\nciamOffering: serverless\n")
                   for t in TREE)


def test_on_serverless_a_stream_keeps_logs_by_its_data_stream_lifecycle_and_an_archive_is_a_blocker():
    m = _alpha(tree=SERVERLESS)
    files = render_env(m, SERVICES)
    assert json.loads(files[f"{API}data-stream-lifecycles.json"]) == {"data_streams": [
        {"name": STREAM, "lifecycle": {"enabled": True, "data_retention": "90d"}}]}
    assert not {f"{API}ilm-policies.json", f"{API}component-templates.json", f"{API}slm-policies.json"} & set(files)
    main = files["elastic/terraform/main.tf"]
    assert ('resource "elasticstack_elasticsearch_data_stream_lifecycle" "logs_ciam_security_prod" {\n'
            f'  name           = "{STREAM}"\n  enabled        = true\n  data_retention = "90d"\n}}') in main
    assert "elasticstack_elasticsearch_index_lifecycle" not in main
    texts = {note_comment(n): n.severity for n in render_notes(m, SERVICES)}
    assert texts[f"NOTE: Elastic data stream {STREAM}: keeps logs 90 days searchable and 365 in all, archived in "
                 "found-snapshots, but Elastic Cloud Serverless keeps no archive to restore (no snapshots): they are "
                 "deleted after 90 days"] == "blocker"
    assert texts["NOTE: Elastic Cloud Serverless retention: its streams keep logs up to 90 days searchable, and the "
                 "project's maximum data retention caps every stream's"] == "action"
    assert texts[f"NOTE: Elastic data stream {STREAM}: its data stream lifecycle is set on the stream itself, which "
                 f"Fleet creates at its first event: until then PUT _data_stream/{STREAM}/_lifecycle (and terraform "
                 "apply) fails"] == "action"


def test_on_serverless_a_stream_kept_forever_takes_the_projects_default_and_a_bare_archive_is_an_action():
    forever = entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                    ciamProviderRef=STREAM, ciamRetentionDays="0", ciamArchiveRef="found-snapshots")
    m = _alpha(forever, *BINDINGS[1:], tree=SERVERLESS)
    lifecycles = json.loads(render_env(m, SERVICES)[f"{API}data-stream-lifecycles.json"])
    assert lifecycles == {"data_streams": [{"name": STREAM, "lifecycle": {"enabled": True}}]}
    texts = {note_comment(n): n.severity for n in render_notes(m, SERVICES)}
    assert texts[f"NOTE: Elastic data stream {STREAM}: kept indefinitely: no data_retention rendered, so the "
                 "project's default retention applies to it"] == "note"
    assert texts[f"NOTE: Elastic data stream {STREAM}: keeps logs 0 days searchable and no longer in all, archived in "
                 "found-snapshots, but Elastic Cloud Serverless keeps no archive to restore (no snapshots): they are "
                 "deleted after 0 days"] == "action"
    assert not any(t.startswith("NOTE: Elastic Cloud Serverless retention") for t in texts)


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


def test_a_data_stream_lifecycle_reads_its_effective_retention_first():
    streams = {"data_streams": [{"name": STREAM, "next_generation_managed_by": "Data stream lifecycle",
                                 "lifecycle": {"enabled": True, "effective_retention": "396d",
                                               "retention_determined_by": "default_global_retention"}}]}
    lifecycles = {"data_streams": [{"name": "logs-ciam.ops-prod", "lifecycle": {"enabled": True,
                                                                                 "data_retention": "30d"}}]}
    resources, _ = parse_elasticsearch({"data-streams.json": json.dumps(streams),
                                        "data-stream-lifecycles.json": json.dumps(lifecycles)})
    assert {r.ref: r.attrs["ciamRetentionDays"] for r in resources} == {STREAM: ("396",),
                                                                        "logs-ciam.ops-prod": ("30",)}


def test_the_cluster_answer_is_checked_against_the_declared_offering():
    m = _alpha()
    serverless = json.dumps({"version": {"number": "9.6.0", "build_flavor": "serverless"}})
    (notice,) = (n for n in read_elasticsearch({"alpha/prod/cluster.json": serverless}, m.d).notices
                 if "build flavor" in n)
    assert notice == ("alpha/prod: Elasticsearch answers build flavor serverless (serverless), but the environment's "
                      "stack declares its Elastic component stateful (ciamOffering): record ciamOffering serverless on "
                      "it, or collect from the right cluster")
    assert not any("build flavor" in n for n in read_elasticsearch({"alpha/prod/cluster.json": serverless},
                                                                   _alpha(tree=SERVERLESS).d).notices)
    stateful = json.dumps({"version": {"number": "9.5.5", "build_flavor": "default"}})
    assert not any("build flavor" in n for n in read_elasticsearch({"alpha/prod/cluster.json": stateful}, m.d).notices)


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
        ("alpha/prod/slm-policies.json", "https://es.example.test:9243/_slm/policy", key),
        ("alpha/prod/cluster.json", "https://es.example.test:9243/", key)]
    (first,) = kibana_steps(m.d, m, {}, {})
    assert first[0] == "alpha/prod/detection-rules.json" and first[1].url == (
        "https://kb.example.test:9243/api/detection_engine/rules/_find?per_page=1000&page=1")
    done = {"alpha/prod/detection-rules.json": json.dumps({"data": [], "total": 1500})}
    assert [p for p, _ in kibana_steps(m.d, m, done, {})] == ["alpha/prod/detection-rules.2.json"]
    c = collect("elastic/elasticsearch", COLLECTORS[0], m.d, m, lambda r: (json.dumps({}), None))
    assert c.problems == () and len(c.files) == 4


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
    for tree in (TREE, SERVERLESS):
        trips = round_trip(_alpha(tree=tree).d, "alpha/prod", installed=(FAKE, ADAPTER._replace(logs=SOURCES)))
        assert sorted(rt.importer for rt in trips) == ["elastic/elasticsearch", "elastic/kibana"]
        assert all(rt.drift == () for rt in trips)


ROOT = pathlib.Path(__file__).resolve().parents[3]


@pytest.mark.terraform
@pytest.mark.skipif(not (ROOT / "tools" / "bin" / "terraform").exists(),
                    reason="no tools/bin/terraform (opsdir/scripts/fetch-tools.sh)")
def test_the_rendered_terraform_is_valid(tmp_path):
    """fmt -check, init and validate against the elasticstack provider (opsdir/scripts/validate-terraform.sh): a
    stateful environment's lifecycle, rules and Fleet policies (files, a route taking some lines, records spanning
    lines, Kubernetes containers), and a Serverless one's data stream lifecycle."""
    m, found = _on_kubernetes(
        LogSource("web", "kubernetes", None, "json-lines", "audit"),
        LogSource("ds", "servers", "logs/errors", "text", "audit", line_start=r"^\["),
        LogSource("ds", "servers", "var/audit/*.json", "json-lines", "audit", (("eventName", "AM-ACCESS", "access"),)))

    def written(root, files):
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text)
        return root
    trees = (written(tmp_path / "stateful", render_env(m, found, ("terraform",))),
             written(tmp_path / "serverless", render_env(_alpha(tree=SERVERLESS), found, ("terraform",))))
    done = subprocess.run([str(ROOT / "opsdir" / "scripts" / "validate-terraform.sh"), *map(str, trees)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr

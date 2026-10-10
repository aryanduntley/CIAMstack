"""Prometheus alerting rules from the record's alert rules: grouped by the channel role delivering them, evaluated on
the signals the environment's products declare, written by a play on the monitoring servers (checked by promtool
first) and as a PrometheusRule; rules nothing here can evaluate are named, not rendered."""
import pathlib
import subprocess
from types import SimpleNamespace

import pytest
from ansible_yaml import load

from opsdir.connectors.registry import services
from opsdir.core.contract import Signal
from opsdir.core.environment import StackComponent
from opsdir.domains.observability.naming import ALERT_RULES
from opsdir_adapter_prometheus.checks import check_placed
from opsdir_adapter_prometheus.render import OPERATOR, PLAY, RULES, prometheus_rule, render
from opsdir_adapter_prometheus.rules import rule_set
from network_fixtures import ALPHA, entry, model

ROOT = pathlib.Path(__file__).resolve().parents[3]
OWNERS, RUNBOOKS = "ou=owners,dc=ciam-ops", "ou=runbooks,dc=ciam-ops"
SIGNALS = (Signal("replication-delay", "ds", "max by (instance) (ds_replication_delay_seconds)", "s",
                  "replication delay"),
           Signal("heap-used", "ds", "ds_jvm_memory_heap_used_bytes", "bytes", "heap memory the JVM uses"))


def _rule(cn, **attrs):
    return entry(ALERT_RULES, cn, "ciamAlertRule", **attrs).replace("objectClass: ciamAlertRule",
                                                                     "objectClass: ciamObject\nobjectClass: "
                                                                     "ciamAlertRule")


TREE = (
    f"dn: {OWNERS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    f"dn: cn=dir-team,{OWNERS}\nobjectClass: top\nobjectClass: ciamParty\ncn: dir-team\nciamOwnerKind: team\n",
    f"dn: {RUNBOOKS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: runbooks\n",
    f"dn: cn=WI-7,{RUNBOOKS}\nobjectClass: top\nobjectClass: ciamRunbook\ncn: WI-7\nciamTitle: Replication lag\n"
    "ciamLastValidated: 20260101000000Z\nciamDocUrl: https://runbooks.example.test/WI-7\n",
    f"dn: {ALERT_RULES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: alert-rules\n",
    _rule("replication-lag", ciamSignal="replication-delay", ciamTargetRole="ds", ciamComparison="gt",
          ciamThreshold="5000 ms", ciamEvaluationPeriod="5m", ciamSeverity="sev2", ciamAlertRole="alerts-page",
          ciamRunbookRef=f"cn=WI-7,{RUNBOOKS}", ciamOwner=f"cn=dir-team,{OWNERS}"),
    _rule("heap-high", ciamSignal="heap-used", ciamTargetRole="ds", ciamComparison="ge", ciamThreshold="3 GiB",
          ciamAlertRole="alerts-ticket"),
    _rule("disk-low", ciamSignal="disk-free", ciamTargetRole="ds", ciamComparison="lt", ciamThreshold="10 GB",
          ciamAlertRole="alerts-page"),
    _rule("heap-in-ms", ciamSignal="heap-used", ciamTargetRole="ds", ciamComparison="gt", ciamThreshold="5 ms",
          ciamAlertRole="alerts-page"),
    _rule("pf-errors", ciamSignal="login-failures", ciamTargetRole="pf-engine", ciamComparison="gt",
          ciamThreshold="5 /min", ciamAlertRole="alerts-page"),
)
MONITOR = entry(ALPHA, "mon-1", "ciamServer", ciamServerRole="monitoring", ciamHostname="mon-1.example.test",
                ciamZone="zone-a")


def _env(*alpha):
    _, m, beta = model(alpha=alpha, tree=TREE)
    return m, beta


SERVICES = services()._replace(signals=lambda m: SIGNALS)


def test_rules_are_grouped_by_their_channel_and_read_in_the_signals_unit():
    m, _ = _env()
    groups, skipped = rule_set(m, SIGNALS)
    assert [g["name"] for g in groups] == ["ciam-alerts-ticket", "ciam-alerts-page"]     # in the record's order
    heap, lag = groups[0]["rules"][0], groups[1]["rules"][0]
    assert lag == {"alert": "replication-lag", "expr": "(max by (instance) (ds_replication_delay_seconds)) > 5",
                   "for": "5m", "labels": {"severity": "sev2", "team": "dir-team", "ciam_rule": "replication-lag",
                                           "environment": "alpha/prod"},
                   "annotations": {"summary": "replication delay: gt 5000 ms on ds",
                                   "runbook": "https://runbooks.example.test/WI-7"}}
    assert heap["expr"] == "(ds_jvm_memory_heap_used_bytes) >= 3221225472" and "for" not in heap
    # pf-engine doesn't run here: not this environment's concern
    assert skipped == ("alert rule disk-low: no product rendering alpha/prod declares signal `disk-free` for role `ds`",
                       "alert rule heap-in-ms's threshold '5 ms' can't be read in heap-used's unit (bytes)")


def test_the_rule_file_names_what_it_leaves_out_and_the_play_writes_it_on_the_monitoring_servers():
    m, _ = _env(MONITOR)
    files = render(m, SERVICES)
    assert "# NOTE: alert rule disk-low: no product rendering alpha/prod declares signal `disk-free` for role `ds`: " \
           "not rendered\n" in files[RULES]
    assert load(files[RULES])["groups"][1]["rules"][0]["alert"] == "replication-lag"
    (play,) = load(files[PLAY])
    assert play["hosts"] == "monitoring"
    copy = play["tasks"][1]["ansible.builtin.copy"]
    assert copy == {"src": "{{ playbook_dir }}/../prometheus/rules/ciam.rules.yml",
                    "dest": "/etc/prometheus/rules/ciam.rules.yml", "mode": "0644",
                    "validate": "promtool check rules %s"}
    assert play["handlers"][0]["ansible.builtin.systemd_service"] == {"name": "prometheus", "state": "reloaded"}
    assert OPERATOR not in files                      # no role on Kubernetes here


def test_without_monitoring_servers_there_is_no_play():
    m, _ = _env()
    assert set(render(m, SERVICES)) == {RULES}


def test_the_prometheus_rule_carries_the_release_its_prometheus_selects():
    m, _ = _env()
    groups, _ = rule_set(m, SIGNALS)
    rule = prometheus_rule(m, groups)
    assert (rule["apiVersion"], rule["kind"]) == ("monitoring.coreos.com/v1", "PrometheusRule")
    assert rule["metadata"] == {"name": "ciam-alerts", "namespace": "monitoring",
                                "labels": {"release": "kube-prometheus-stack",
                                           "app.kubernetes.io/managed-by": "opsdir"}}
    assert rule["spec"]["groups"] == groups


def test_a_target_declaring_prometheus_with_nowhere_to_run_it_is_an_action():
    m, _ = _env()
    declared = m._replace(stack=(*m.stack, StackComponent("monitoring", "prometheus", None, None)))
    (action,) = check_placed(SimpleNamespace(d=m.d, src=m, dst=declared)).actions
    assert "records no server of role `monitoring`" in action[1]
    placed, _ = _env(MONITOR)
    placed = placed._replace(stack=(*placed.stack, StackComponent("monitoring", "prometheus", None, None)))
    assert not check_placed(SimpleNamespace(d=placed.d, src=placed, dst=placed)).actions
    assert not check_placed(SimpleNamespace(d=m.d, src=m, dst=m)).actions        # not declared


@pytest.mark.skipif(not (ROOT / "tools" / "bin" / "promtool").exists(), reason="no promtool (fetch-tools.sh)")
def test_promtool_accepts_the_rule_file(tmp_path):
    m, _ = _env()
    path = tmp_path / "ciam.rules.yml"
    path.write_text(render(m, SERVICES)[RULES])
    done = subprocess.run([str(ROOT / "tools" / "bin" / "promtool"), "check", "rules", str(path)],
                          capture_output=True, text=True)
    assert done.returncode == 0 and "SUCCESS: 2 rules found" in done.stdout, done.stdout + done.stderr


@pytest.mark.ansible
@pytest.mark.skipif(not (ROOT / "tools" / "ansible" / "venv" / "bin" / "ansible-playbook").exists(),
                    reason="no tools/ansible (opsdir/scripts/fetch-tools.sh)")
def test_the_play_passes_ansibles_own_checks(tmp_path):
    from opsdir_adapter_ansible.render import render as ansible
    m, _ = _env(MONITOR)
    for path, text in {**ansible(m, services()), **render(m, SERVICES)}.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(text)
    done = subprocess.run([str(ROOT / "opsdir" / "scripts" / "validate-ansible.sh"), str(tmp_path)],
                          capture_output=True, text=True)
    assert done.returncode == 0 and "prometheus-rules.yml (syntax)" in done.stdout, done.stdout + done.stderr

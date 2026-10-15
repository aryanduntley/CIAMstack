# opsdir-adapter-prometheus

opsdir monitoring add-on: the record's alert rules as Prometheus alerting rules (milestone 5.4, design 2297), placed on the environment's monitoring servers by Ansible and, where roles run on Kubernetes, as a prometheus-operator `PrometheusRule`.

**Applies to** environments whose stack declares it (`ciamStackRole: monitoring`, `ciamAdapter: prometheus`). On servers it works beside `opsdir-adapter-ansible`, whose inventory its play uses (the group of the servers with `ciamServerRole: monitoring`). On Kubernetes, a cluster running prometheus-operator (kube-prometheus-stack by default).

**Depends on** `opsdir` (the observability domain's alert rules and signals, `opsdir.domains.observability`; estate settings; render notes) and `opsdir-adapter-ansible` (Ansible names, the YAML writer). At run time: `promtool` on the monitoring servers (the play's check), Prometheus's systemd unit `prometheus`.

## Where the expressions come from

An alert rule (`ciamAlertRule`: `ciamSignal`, `ciamAlertRole`, and optionally `ciamTargetRole`, `ciamComparison`, `ciamThreshold`, `ciamEvaluationPeriod`, `ciamSeverity`, `ciamRunbookRef`) names a neutral signal on a server role. The product adapters rendering the environment declare which signals their servers expose as Prometheus metrics (`core.contract.Signal`, `Adapter.signals`), each backed by the product's own documentation. A product whose metric names change between releases declares one signal per release line (`Signal.versions`, a PEP 440 range), and the one whose range holds for the `ciamProductVersion`s the role's servers and workloads record is used (none recorded: the newest release's). Declared today:

| Product (adapter) | Signals |
|---|---|
| PingDS (`opsdir-adapter-pingds`) | `replication-delay` (s), `disk-free` (bytes), `heap-used` (bytes), `ldap-errors` (/s) |
| PingAM (`opsdir-adapter-pingam`) | `login-failures` (/s) |
| PingIDM (`opsdir-adapter-pingidm`) | `heap-used` (bytes): `idm_jvm_memory_usage_used{location="heap"}` on 8.x, `idm_jvm_memory_usage_heap_used` before 8 |
| PingFederate | none: it serves heartbeat statistics, not Prometheus metrics |

## What it renders

Per environment, nothing environment-neutral:

| File | When | Content |
|---|---|---|
| `prometheus/rules/ciam.rules.yml` | always | A header, the `# NOTE` comment of each rule not rendered, then `groups:` |
| `ansible/prometheus-rules.yml` | the environment has servers of role `monitoring` | One play on those hosts (`become`): the rules folder (`prometheus-rules-dir`, mode `0755`), then the rule file copied in as `ciam.rules.yml` (mode `0644`), checked by `promtool check rules` before it replaces the running file; Prometheus reloaded by a handler (`ansible.builtin.systemd_service` `prometheus`, `state: reloaded`) |
| `kubernetes/prometheus/prometheusrule.yaml` | the environment runs roles on Kubernetes and has rules to render | `PrometheusRule` `ciam-alerts` (`monitoring.coreos.com/v1`) in the `prometheus-rule-namespace` namespace, labels `release` (`prometheus-rule-release`) and `app.kubernetes.io/managed-by: opsdir`, holding the same groups |

| From the record | Alerting rule |
|---|---|
| The rule's name | `alert` |
| The signal's expression, `ciamComparison` (`gt`, `ge`, `lt`, `le`, `eq`, `ne`), `ciamThreshold` | `expr`: `(<expression>) <op> <threshold>`, the threshold converted to the signal's unit (`5000 ms` against seconds is `> 5`) |
| `ciamEvaluationPeriod` | `for` |
| `ciamSeverity`, the first `ciamOwner`, the rule, the environment's `<cloud>/<env>` | labels `severity`, `team`, `ciam_rule`, `environment` (those without a value left out) |
| The signal's description and the condition; the first runbook (`ciamRunbookRef`) | annotations `summary` (`<description>: <comparison> <threshold> on <role>`) and `runbook` (its `ciamDocUrl`, else `<name>: <ciamTitle>`) |
| `ciamAlertRole` | the group: one per delivering role, `ciam-<alert role>`. Alertmanager routes alerts on the labels; its routing stays the operators' own |

Rules that aren't rendered:

- **A rule on a role the environment doesn't run** (on servers, a compute group or Kubernetes): left out, silently: it isn't this environment's concern.
- **A rule whose signal no product rendering the environment declares for its role** (or that names no role): a render note (`core.notes`, flow 43; `Adapter.notes`), written as a `# NOTE` comment at the top of the rule file and listed in the render's NOTES.md. A plain note: a cloud alarm may realize the rule, and the planner's signal check asks for a metric when nothing in the target evaluates it.
- **A rule whose signal is declared but which records no comparison, or whose threshold can't be read in the signal's unit:** a render note, a plain note when an alarm binding (`ciamAlarmBinding` with `ciamRealizes` the rule) realizes it with a `ciamMetric`, else a blocker asking for the comparison and a threshold in the signal's unit.

Not rendered: Prometheus itself, its `rule_files` and scrape configuration, and Alertmanager's routes.

## Estate settings

| Setting | Default | What it sets |
|---|---|---|
| `prometheus-rules-dir` | `/etc/prometheus/rules` | The folder on the monitoring servers. Prometheus's `rule_files` must include `<folder>/*.yml` |
| `prometheus-rule-namespace` | `monitoring` | The namespace of the `PrometheusRule` (one the cluster's Prometheus reads rules from) |
| `prometheus-rule-release` | `kube-prometheus-stack` | The `release` label. kube-prometheus-stack's Prometheus selects rules by its Helm release unless `ruleSelectorNilUsesHelmValues` is false |

## Vocabulary it owns

The server role `monitoring` (`ciamServerRole`, `ciamTargetRole`): the servers Prometheus runs on. The store accepts a server of that role only while this adapter is installed.

It adds no required roles, importers, reference schemes, schema or secret patterns. Its formats: `prometheus/rules/*.yml`, `ansible/*.yml`, `kubernetes/prometheus/*.yaml`, all YAML.

## Planner checks

`check_placed`: a target that declares Prometheus but records no server of role `monitoring` and runs no role on Kubernetes is an action (area "Monitoring"): its rules would be rendered, and nothing would evaluate them.

## Known limits

- **Not yet run against a live Prometheus.** The rule file passes `promtool check rules` and the play ansible-core's syntax check and ansible-lint; loading them into a running Prometheus or prometheus-operator is part of the testing plan (milestone 7.2).
- Prometheus itself, its scrape configuration and Alertmanager's routes aren't rendered. The products' metrics endpoints must be scraped (PingDS `/metrics/prometheus/0.0.4` with a monitor account, PingAM's prometheus monitoring configuration, PingIDM `/openidm/metrics/prometheus`).
- The reload assumes the `prometheus` systemd unit reloads on `systemctl reload` (sends SIGHUP), as the distribution packages' units do.
- Firewall rules from the monitoring servers to the products' metrics ports aren't added: record them like any other rule.
- Cloud-managed Prometheus (Amazon Managed Service for Prometheus, Azure Monitor managed Prometheus, Google Cloud Managed Service for Prometheus) isn't rendered here (design 2297 D7).

## Tests

`tests/test_prometheus.py`: rules grouped by their channel and read in the signal's unit, labels and annotations; the rule file naming what it leaves out and the play writing it on the monitoring servers; no play without monitoring servers; the `PrometheusRule` with the release its Prometheus selects; the planner check with nowhere to run the rules; `promtool check rules` on the rule file (skipped without `tools/bin/promtool`, from `opsdir/scripts/fetch-tools.sh`); and (marker `ansible`, skipped without `tools/ansible`) the play through ansible-core and ansible-lint.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-prometheus/tests` (unit, with promtool when fetched), and with `-m ansible` for the play.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `prometheus`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

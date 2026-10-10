# opsdir-adapter-prometheus

opsdir monitoring add-on: the record's alert rules as Prometheus alerting rules (milestone 5.4, design 2297). It applies to environments whose stack declares it (`ciamStackRole: monitoring`, `ciamAdapter: prometheus`). On servers it works beside `opsdir-adapter-ansible`, whose inventory its play uses. On Kubernetes it renders a prometheus-operator `PrometheusRule`.

**Depends on** `opsdir`, where the observability domain holds the alert rules and the signals module, and on `opsdir-adapter-ansible`.

## Where the expressions come from

An alert rule names a neutral signal on a server role (`ciamSignal`, `ciamTargetRole`). The product adapters rendering the environment declare which signals their servers expose as Prometheus metrics (`core.contract.Signal`, `Adapter.signals`). Each declaration is backed by the product's own documentation:

| Product | Signals |
|---|---|
| PingDS | `replication-delay` (s), `disk-free` (bytes), `heap-used` (bytes), `ldap-errors` (/s) |
| PingAM | `login-failures` (/s) |
| PingIDM | `heap-used` (bytes) |
| PingFederate | none: it serves heartbeat statistics, not Prometheus metrics |

How each rule becomes an alerting rule:

- **Expression:** the signal's expression compared with the rule's threshold, converted to the signal's unit (`5000 ms` against seconds is `> 5`).
- **`for`:** the rule's `ciamEvaluationPeriod`.
- **Labels:** `severity`, `team` (the first owner), `ciam_rule` and `environment`.
- **Annotations:** a `summary`, and the first runbook's `ciamDocUrl` (else its name and title).
- **Groups:** one per delivering role (`ciam-<ciamAlertRole>`). Alertmanager routes alerts on these labels, and its routing stays the operators' own.

Rules that aren't rendered:

- **A rule on a role the environment doesn't run:** left out.
- **A rule whose signal no product here declares, or whose threshold can't be read in the signal's unit:** named in a `# NOTE` at the top of the rule file. The planner's signal check asks for a metric when nothing in the target evaluates a rule.

## What it renders

| File | When | Content |
|---|---|---|
| `prometheus/rules/ciam.rules.yml` | always | The rule groups, and the NOTEs |
| `ansible/prometheus-rules.yml` | the environment has servers of role `monitoring` | Play on those hosts: the rules folder, then the rule file copied in. The copy is checked by `promtool check rules` before it replaces the running file. Prometheus is then reloaded (systemd `reloaded`) |
| `kubernetes/prometheus/prometheusrule.yaml` | the environment runs roles on Kubernetes and has rules | `PrometheusRule` (`monitoring.coreos.com/v1`) holding the same groups |

## Estate settings

| Setting | Default | What it sets |
|---|---|---|
| `prometheus-rules-dir` | `/etc/prometheus/rules` | The folder on the monitoring servers. Prometheus's `rule_files` must include `<folder>/*.yml` |
| `prometheus-rule-namespace` | `monitoring` | The namespace of the `PrometheusRule` |
| `prometheus-rule-release` | `kube-prometheus-stack` | The `release` label. kube-prometheus-stack's Prometheus selects rules by its Helm release unless `ruleSelectorNilUsesHelmValues` is false |

## Vocabulary it owns

The server role `monitoring` (`ciamServerRole`, `ciamTargetRole`): the servers Prometheus runs on. The store accepts a server of that role only while this adapter is installed.

## Planner check

`check_placed`: a target that declares Prometheus but records no server of role `monitoring` and runs no role on Kubernetes is an action. Its rules would be rendered, and nothing would evaluate them.

## Known limits

- Prometheus itself, its scrape configuration and Alertmanager's routes aren't rendered. The products' metrics endpoints must be scraped (PingDS `/metrics/prometheus/0.0.4` with a monitor account, PingAM's prometheus monitoring configuration, PingIDM `/openidm/metrics/prometheus`).
- The reload assumes the `prometheus` systemd unit reloads on `systemctl reload` (sends SIGHUP), as the distribution packages' units do.
- Firewall rules from the monitoring servers to the products' metrics ports aren't added: record them like any other rule.
- Cloud-managed Prometheus (Amazon Managed Service for Prometheus, Azure Monitor managed Prometheus, Google Cloud Managed Service for Prometheus) isn't rendered here (design 2297 D7).

## Tests

`tests/test_prometheus.py` covers:

- Grouping and unit conversion, labels and annotations.
- Rules named rather than rendered.
- The play, and no play without monitoring servers.
- The `PrometheusRule`.
- The planner check.
- `promtool check rules` on the rule file (needs `tools/bin/promtool` from `opsdir/scripts/fetch-tools.sh`).
- The play through the real Ansible tools (marker `ansible`).

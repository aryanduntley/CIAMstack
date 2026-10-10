"""The estate settings the Prometheus add-on declares: where its rules land on the monitoring servers, and what makes a
cluster's Prometheus load its PrometheusRule (kube-prometheus-stack selects rules by its Helm release's label unless
told otherwise)."""
from opsdir.core.contract import Setting

RULES_DIR = Setting("prometheus-rules-dir", "string", "/etc/prometheus/rules",
                    "The folder on the monitoring servers the alerting rules are written to (Prometheus's rule_files "
                    "must include <folder>/*.yml)")
RULE_NAMESPACE = Setting("prometheus-rule-namespace", "string", "monitoring",
                         "The Kubernetes namespace the PrometheusRule is created in (one the cluster's Prometheus "
                         "reads rules from)")
RULE_RELEASE = Setting("prometheus-rule-release", "string", "kube-prometheus-stack",
                       "The release label the PrometheusRule carries: the Helm release of the cluster's "
                       "kube-prometheus-stack, whose Prometheus selects rules by it")
SETTINGS = (RULES_DIR, RULE_NAMESPACE, RULE_RELEASE)

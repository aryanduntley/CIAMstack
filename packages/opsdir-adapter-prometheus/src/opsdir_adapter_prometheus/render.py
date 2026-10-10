"""The Prometheus add-on's render for an environment. Pure.

prometheus/rules/ciam.rules.yml: the alerting rules (rules.rule_set), with a NOTE naming each rule not rendered and
why. Where the environment has servers of role monitoring: ansible/prometheus-rules.yml, the play writing that file
into the rules folder (estate setting prometheus-rules-dir) on them, checked by `promtool check rules` before it
replaces the running one, and reloading Prometheus. Where it runs roles on Kubernetes and has rules:
kubernetes/prometheus/prometheusrule.yaml, the same groups as a prometheus-operator PrometheusRule
(monitoring.coreos.com/v1) in the namespace and with the release label the estate settings give.
"""
from opsdir.core.environment import servers_with_role
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from opsdir.core.settings import setting_value
from opsdir.domains.compute.workloads import kubernetes_roles
from opsdir_adapter_ansible.names import ansible_name
from opsdir_adapter_ansible.output import WIDTH, yaml_text
from .rules import rule_set
from .settings import RULE_NAMESPACE, RULE_RELEASE, RULES_DIR

HOSTS = "monitoring"            # the server role Prometheus runs on (and the stack role the add-on fills)
RULES = "prometheus/rules/ciam.rules.yml"
PLAY = "ansible/prometheus-rules.yml"
OPERATOR = "kubernetes/prometheus/prometheusrule.yaml"
RULE_NAME = "ciam-alerts"


def _yaml(value):
    return dump(value, indent_sequences=True, width=WIDTH)


def rules_file(m, groups, skipped):
    """The rule file's text: header, a NOTE per rule not rendered, the groups."""
    notes = "".join(f"# NOTE: {why}: not rendered\n" for why in skipped)
    return header(m, "Prometheus alerting rules from the record's alert rules", YAML) + notes + \
        _yaml({"groups": groups})


def play(m):
    """The play (a list of one) writing the rule file on environment m's monitoring servers."""
    folder = setting_value(m.d, RULES_DIR)
    return [{"name": "Prometheus alerting rules (opsdir)", "hosts": ansible_name(HOSTS), "become": True,
             "tasks": [
                 {"name": "Rules folder", "ansible.builtin.file": {"path": folder, "state": "directory",
                                                                   "mode": "0755"}},
                 {"name": "Alerting rules, checked by promtool before they replace the running ones",
                  "ansible.builtin.copy": {"src": "{{ playbook_dir }}/../" + RULES,
                                           "dest": f"{folder}/ciam.rules.yml", "mode": "0644",
                                           "validate": "promtool check rules %s"},
                  "notify": "Reload Prometheus"}],
             "handlers": [{"name": "Reload Prometheus", "ansible.builtin.systemd_service":
                           {"name": "prometheus", "state": "reloaded"}}]}]


def prometheus_rule(m, groups):
    """The PrometheusRule object holding the groups."""
    return {"apiVersion": "monitoring.coreos.com/v1", "kind": "PrometheusRule",
            "metadata": {"name": RULE_NAME, "namespace": setting_value(m.d, RULE_NAMESPACE),
                         "labels": {"release": setting_value(m.d, RULE_RELEASE),
                                    "app.kubernetes.io/managed-by": "opsdir"}},
            "spec": {"groups": groups}}


def render(m, services):
    """{path: text} of environment m's Prometheus files."""
    groups, skipped = rule_set(m, services.signals(m))
    return {RULES: rules_file(m, groups, skipped),
            **({PLAY: yaml_text(m, "Writes the alerting rules on the monitoring servers", play(m))}
               if servers_with_role(m, HOSTS) else {}),
            **({OPERATOR: header(m, "Prometheus alerting rules for the cluster's prometheus-operator", YAML)
                + _yaml(prometheus_rule(m, groups))} if groups and kubernetes_roles(m) else {})}

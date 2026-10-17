"""Container output on Kubernetes to a Splunk index (milestone 109, task 575): the Splunk OpenTelemetry Collector
chart's values per cluster (the routed roles' namespaces only, logs only, the HEC token from an existing Secret, never
in the values), the actions to install it and fill the Secret, and blockers for what is missing."""
from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir_adapter_splunk.kubernetes import collector_notes, collector_values, cluster_shipments, render_collectors
from opsdir_adapter_splunk.render import splunk_shipments
from network_fixtures import ALPHA, entry, model

OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"
TREE = (OU.format(LOG_ROUTES, "log-routes"), OU.format(WORKLOADS, "workloads"),
        f"dn: cn=security,{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
        "cn: security\nciamLogKind: audit\nciamPublishedBy: web\nciamLogDestinationRole: siem\n",
        f"dn: {workload_dn('web')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: web\n"
        "ciamWorkloadKind: deployment\nciamTargetRole: web\nciamNamespace: ciam-web\nciamClusterRole: k8s\n"
        "ciamWorkloadRole: web-workload\n")


def _model(intake="https://hec.example.test:8088", credential="hec"):
    bindings = (entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                      ciamProviderRef="ciam_security", ciamRetentionDays="90",
                      **({"ciamIntakeUrl": intake} if intake else {}),
                      **({"ciamCredentialRole": credential} if credential else {})),
                entry(ALPHA, "hec", "ciamSecretRef", ciamBindingRole="hec", ciamRefUri="vault://secret/siem/hec"),
                entry(ALPHA, "web", "ciamWorkloadBinding", ciamBindingRole="web-workload",
                      ciamContainerImage="web=registry.example.test/web:1"),
                entry(ALPHA, "k8s", "ciamCluster", ciamBindingRole="k8s", ciamProviderRef="cluster-1"))
    _, alpha, _ = model(alpha=bindings, tree=TREE)
    found = splunk_shipments(alpha, services()._replace(
        logs=lambda m: (LogSource("web", "kubernetes", None, "json-lines", "audit"),)))
    return alpha, found


def test_a_cluster_gets_collector_values_for_its_routed_namespaces_with_the_token_from_a_secret():
    m, found = _model()
    ((cluster, xs),) = cluster_shipments(m, found)
    values = collector_values(m, cluster, xs)
    assert values["splunkPlatform"] == {"endpoint": "https://hec.example.test:8088/services/collector/event",
                                        "index": "ciam_security", "logsEnabled": True, "metricsEnabled": False,
                                        "tracesEnabled": False}
    assert values["secret"] == {"create": False, "name": "splunk-otel-collector-hec"}
    assert values["logsCollection"]["containers"]["extraOperators"] == [
        {"type": "filter", "expr": 'resource["k8s.namespace.name"] not in ["ciam-web"]'}]
    (path, text), = render_collectors(m, found).items()
    assert path == "kubernetes/splunk-otel-collector/k8s-values.yaml" and "token:" not in text
    action, _ = collector_notes(m, found)
    assert action.severity == "action" and "vault://secret/siem/hec" in action.text


def test_without_an_intake_or_credential_the_cluster_is_a_blocker():
    m, found = _model(intake=None, credential=None)
    assert render_collectors(m, found) == {}
    (blocker,) = collector_notes(m, found)
    assert blocker.severity == "blocker" and "an intake URL" in blocker.text and "a credential" in blocker.text

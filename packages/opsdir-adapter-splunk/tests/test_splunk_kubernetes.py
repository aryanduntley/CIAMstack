"""Container output on Kubernetes to a Splunk index (milestone 109, tasks 575 and 593): the Splunk OpenTelemetry
Collector chart's values per cluster (the routed roles' namespaces only, logs only, the HEC token from an existing
Secret, never in the values), the External Secrets objects filling that Secret from the index's credential reference
where an installed adapter delivers its scheme and the record gives its store, the actions to install it (and fill the
Secret by hand otherwise), and blockers for what is missing."""
import subprocess
from pathlib import Path

import pytest
import yaml

from opsdir.connectors.registry import services
from opsdir.core.contract import K8sIdentity, LogSource
from opsdir.domains.access.naming import PERMISSION_SETS, PRINCIPALS
from opsdir.domains.access.workloads import Pod, identity_pods
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir_adapter_aws.kubernetes import workload_identity as aws_workload_identity
from opsdir_adapter_splunk.kubernetes import (collector_notes, collector_values, collector_workload, cluster_shipments,
                                              reader_identity, render_collectors, token_delivery)
from opsdir_adapter_splunk.render import splunk_shipments
from network_fixtures import ALPHA, entry, model

OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"
TREE = (OU.format(LOG_ROUTES, "log-routes"), OU.format(WORKLOADS, "workloads"),
        f"dn: cn=security,{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
        "cn: security\nciamLogKind: audit\nciamPublishedBy: web\nciamLogDestinationRole: siem\n",
        f"dn: {workload_dn('web')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: web\n"
        "ciamWorkloadKind: deployment\nciamTargetRole: web\nciamNamespace: ciam-web\nciamClusterRole: k8s\n"
        "ciamWorkloadRole: web-workload\n")
VAULT = "vault://secret/siem/hec"
AWS_SM = "aws-sm://arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/hec-AbCdEf"
VALUES, SECRETS = "kubernetes/splunk-otel-collector/k8s-values.yaml", \
    "kubernetes/splunk-otel-collector/k8s-externalsecrets.yaml"
ROOT = Path(__file__).resolve().parents[3]


COLLECTOR_TREE = (
    OU.format(PRINCIPALS, "principals"), OU.format(PERMISSION_SETS, "permission-sets"),
    f"dn: {workload_dn('splunk-otel-collector')}\nobjectClass: top\nobjectClass: ciamWorkload\n"
    "cn: splunk-otel-collector\nciamWorkloadKind: daemonset\nciamTargetRole: splunk-otel-collector\n"
    "ciamNamespace: splunk-otel-collector\nciamServiceAccount: splunk-otel-collector-hec-reader\n"
    "ciamClusterRole: k8s\nciamIdentityRole: identity-collector\n",
    f"dn: cn=collector,{PERMISSION_SETS}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamPermissionSet\n"
    "cn: collector\nciamPermits: read-secret hec\n")
ROLE_ARN = "arn:aws:iam::111122223333:role/ciam-splunk-collector"


def _principal(holds=True):
    return (f"dn: cn=splunk-otel-collector,{PRINCIPALS}\nobjectClass: top\nobjectClass: ciamObject\n"
            "objectClass: ciamPrincipal\ncn: splunk-otel-collector\nciamPrincipalKind: workload\n"
            "ciamIdentityRole: identity-collector\nciamTargetRole: splunk-otel-collector\n"
            + (f"ciamHoldsSet: cn=collector,{PERMISSION_SETS}\n" if holds else ""))


def _collector(ref=AWS_SM, identity=True, holds=True, tree=COLLECTOR_TREE, **binding):
    """The model with the collector's workload (identity role identity-collector bound when identity), its principal
    and permit, and services giving AWS's workload identity (IRSA)."""
    extra = (entry(ALPHA, "identity-collector", "ciamIdentityBinding", ciamBindingRole="identity-collector",
                   **(binding or {"ciamProviderRef": ROLE_ARN})),) if identity else ()
    m, found = _model(ref=ref, store=False, extra=extra, tree=(*tree, _principal(holds)))
    return m, found, services()._replace(workload_identity=aws_workload_identity)


def _model(intake="https://hec.example.test:8088", credential="hec", ref=VAULT, store=True, extra=(), tree=()):
    bindings = (entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                      ciamProviderRef="ciam_security", ciamRetentionDays="90",
                      **({"ciamIntakeUrl": intake} if intake else {}),
                      **({"ciamCredentialRole": credential} if credential else {})),
                entry(ALPHA, "hec", "ciamSecretRef", ciamBindingRole="hec", ciamRefUri=ref),
                entry(ALPHA, "web", "ciamWorkloadBinding", ciamBindingRole="web-workload",
                      ciamContainerImage="web=registry.example.test/web:1"),
                entry(ALPHA, "k8s", "ciamCluster", ciamBindingRole="k8s", ciamProviderRef="cluster-1"),
                *((entry(ALPHA, "vault", "ciamSecretStore", ciamBindingRole="secret-store-vault", ciamRefScheme="vault",
                         ciamStoreEndpoint="https://vault.example.test:8200", ciamStoreAuthRole="splunk"),)
                  if store else ()), *extra)
    _, alpha, _ = model(alpha=bindings, tree=(*TREE, *tree))
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
    rendered = render_collectors(m, found, services())
    assert set(rendered) == {VALUES, SECRETS} and "token:" not in rendered[VALUES]


def test_the_token_secret_is_an_external_secret_from_the_index_credential_through_its_stores_provider():
    m, found = _model()
    docs = list(yaml.safe_load_all(render_collectors(m, found, services())[SECRETS]))
    assert [(d["kind"], d["metadata"]["name"]) for d in docs] == [
        ("Namespace", "splunk-otel-collector"), ("ServiceAccount", "splunk-otel-collector-hec-reader"),
        ("SecretStore", "splunk-otel-collector-hec"), ("ExternalSecret", "splunk-otel-collector-hec")]
    store, secret = docs[2], docs[3]
    assert store["spec"]["provider"]["vault"]["server"] == "https://vault.example.test:8200"
    assert store["spec"]["provider"]["vault"]["auth"]["kubernetes"]["serviceAccountRef"] == {
        "name": "splunk-otel-collector-hec-reader"}
    assert secret["metadata"]["namespace"] == "splunk-otel-collector"
    assert secret["spec"]["target"] == {"name": "splunk-otel-collector-hec", "creationPolicy": "Owner"}
    assert secret["spec"]["data"] == [{"secretKey": "splunk_platform_hec_token",
                                       "remoteRef": {"key": "siem/hec", "property": "value"}}]
    action, _ = collector_notes(m, found, services())
    assert action.severity == "action" and VAULT in action.text and "k8s-externalsecrets.yaml" in action.text
    assert any("splunk-otel-collector-hec-reader" in s for s in action.how)
    assert any("--namespace splunk-otel-collector" in s for s in action.how)


def test_an_aws_secrets_manager_token_is_read_from_the_json_key_firehose_reads_too():
    m, found = _model(ref=AWS_SM, store=False)
    ((cluster, xs),) = cluster_shipments(m, found)
    provider, remote_ref, why = token_delivery(m, services(), xs[0].destination, cluster)
    assert why is None and provider["aws"]["service"] == "SecretsManager"
    assert remote_ref == {"key": AWS_SM.split("://", 1)[1], "property": "hec_token"}
    action, _ = collector_notes(m, found, services())
    assert '{"hec_token": ...}' in action.text


def test_without_a_complete_store_or_a_delivering_adapter_the_secret_is_left_to_a_person():
    for ref, store in ((VAULT, False), ("cyberark-cp://Safe/hec", False), ("file:///etc/hec", True)):
        m, found = _model(ref=ref, store=store)
        assert set(render_collectors(m, found, services())) == {VALUES}, ref
        action, _ = collector_notes(m, found, services())
        assert action.severity == "action" and "the render doesn't deliver it" in action.text, ref
        assert any(s.startswith("Fill the Secret from the reference") for s in action.how), ref


def test_without_an_intake_or_credential_the_cluster_is_a_blocker():
    m, found = _model(intake=None, credential=None)
    assert render_collectors(m, found, services()) == {}
    (blocker,) = collector_notes(m, found, services())
    assert blocker.severity == "blocker" and "an intake URL" in blocker.text and "a credential" in blocker.text


def test_a_recorded_collector_workload_gives_the_reader_the_clouds_workload_identity():
    m, found, svc = _collector()
    ((cluster, _),) = cluster_shipments(m, found)
    assert identity_pods(m, "identity-collector") == (
        Pod("splunk-otel-collector", "splunk-otel-collector-hec-reader", cluster),)
    docs = list(yaml.safe_load_all(render_collectors(m, found, svc)[SECRETS]))
    assert docs[1]["metadata"] == {"name": "splunk-otel-collector-hec-reader", "namespace": "splunk-otel-collector",
                                   "annotations": {"eks.amazonaws.com/role-arn": ROLE_ARN}}
    assert docs[2]["spec"]["provider"]["aws"]["auth"] == {
        "jwt": {"serviceAccountRef": {"name": "splunk-otel-collector-hec-reader"}}}
    action, _ = collector_notes(m, found, svc)
    assert "carries identity role identity-collector's cloud workload identity" in action.text
    assert not any("identity" in s for s in action.how)


def test_an_identity_role_without_the_credentials_permit_is_told_to_get_it():
    m, found, svc = _collector(holds=False)
    action, _ = collector_notes(m, found, svc)
    (grant,) = [s for s in action.how if s.startswith("Let identity role identity-collector read")]
    assert "read-secret hec" in grant


def test_without_an_identity_the_reader_has_no_annotations_and_the_action_says_why():
    for kw, why in (({"identity": False}, "identity role identity-collector, which this environment doesn't bind"),
                    ({"ciamProviderRef": "ciam-splunk-collector"}, "identity-collector-role-arn")):
        m, found, svc = _collector(**kw)
        docs = list(yaml.safe_load_all(render_collectors(m, found, svc)[SECRETS]))
        assert "annotations" not in docs[1]["metadata"], kw
        action, _ = collector_notes(m, found, svc)
        assert why in action.text and any(s.startswith("Give service account") for s in action.how), kw
        assert not any(s.startswith("Or record the collector") for s in action.how), kw
    m, found, _ = _collector()
    ((cluster, _),) = cluster_shipments(m, found)
    assert reader_identity(m, services()._replace(workload_identity=lambda m, b: None), cluster)[2] == \
        "no installed adapter gives this environment's cloud workload identity"


def test_without_a_collector_workload_the_action_proposes_the_entries_recording_it():
    m, found, svc = _collector(tree=COLLECTOR_TREE[:2])
    ((cluster, _),) = cluster_shipments(m, found)
    assert collector_workload(m, cluster) is None
    action, _ = collector_notes(m, found, svc)
    assert "no workload records it (namespace splunk-otel-collector" in action.text
    record, principal = [s for s in action.how if s.startswith(("Or record", "With it"))]
    for what in (workload_dn("splunk-otel-collector"), "ciamWorkloadKind daemonset", "ciamClusterRole k8s",
                 "ciamServiceAccount splunk-otel-collector-hec-reader", "no ciamWorkloadRole"):
        assert what in record, what
    assert "read-secret hec" in principal


def test_azure_and_google_identities_annotate_the_reader_as_their_providers_read_it():
    for identity, annotations in (
            (K8sIdentity((("azure.workload.identity/client-id", "0000-1111"),),
                         (("azure.workload.identity/use", "true"),)),
             {"azure.workload.identity/client-id": "0000-1111"}),
            (K8sIdentity((("iam.gke.io/gcp-service-account", "c@p.iam.gserviceaccount.com"),), ()),
             {"iam.gke.io/gcp-service-account": "c@p.iam.gserviceaccount.com"})):
        m, found, svc = _collector()
        svc = svc._replace(workload_identity=lambda m, b: identity)
        docs = list(yaml.safe_load_all(render_collectors(m, found, svc)[SECRETS]))
        assert docs[1]["metadata"]["annotations"] == annotations


@pytest.mark.skipif(not (ROOT / "tools" / "bin" / "kubeconform").exists(), reason="no tools (fetch-tools.sh)")
def test_the_external_secrets_objects_are_valid_kubernetes(tmp_path):
    for ref, store in ((VAULT, True), (AWS_SM, False)):
        m, found = _model(ref=ref, store=store)
        path = tmp_path / ref.split(":", 1)[0] / SECRETS
        path.parent.mkdir(parents=True)
        path.write_text(render_collectors(m, found, services())[SECRETS])
    m, found, svc = _collector()
    path = tmp_path / "identity" / SECRETS
    path.parent.mkdir(parents=True)
    path.write_text(render_collectors(m, found, svc)[SECRETS])
    done = subprocess.run([str(ROOT / "opsdir" / "scripts" / "validate-kubernetes.sh"), str(tmp_path)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr

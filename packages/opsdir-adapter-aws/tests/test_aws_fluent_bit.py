"""Container logs on EKS to CloudWatch: per cluster a Fluent Bit DaemonSet picking a role's pods by their label,
giving each line its kind as the role's LogSource says (match rules in order, then the source's kind), and sending
each route's kinds to its log group, as an IAM role (IRSA) allowed only those writes; what can't ship is named."""
import yaml

from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir_adapter_aws.fluent_bit import IMAGE, fluent_bit_notes, render_fluent_bit
from opsdir_adapter_aws.terraform import render
from network_fixtures import ALPHA, entry, model

AM = LogSource("am", "kubernetes", None, "mixed", "debug",
               (("eventName", "AM-ACCESS-", "access"), ("eventName", "", "audit")))
CLUSTER = "arn:aws:eks:region-1:111122223333:cluster/ciam-eks"
def load_documents(text):
    return [x for x in yaml.safe_load_all(text) if x is not None]


OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"


def _route(cn, kinds, dest):
    return (f"dn: cn={cn},{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
            f"cn: {cn}\n" + "".join(f"ciamLogKind: {k}\n" for k in kinds)
            + f"ciamPublishedBy: am\nciamLogDestinationRole: {dest}\n")


TREE = (OU.format(WORKLOADS, "workloads"),
        f"dn: {workload_dn('am')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: am\nciamWorkloadKind: deployment\n"
        "ciamTargetRole: am\nciamNamespace: ciam\nciamClusterRole: k8s\nciamWorkloadRole: am-workload\n",
        OU.format(LOG_ROUTES, "log-routes"),
        _route("audit-logs", ("audit", "admin"), "audit-logs"),
        _route("access-logs", ("access", "debug"), "ops-logs"),
        _route("to-siem", ("audit",), "siem"))
BINDINGS = (entry(ALPHA, "am", "ciamWorkloadBinding", ciamBindingRole="am-workload",
                  ciamContainerImage="openam=registry.example.test/am:7.5.1"),
            entry(ALPHA, "eks", "ciamCluster", ciamBindingRole="k8s", ciamProviderRef=CLUSTER),
            entry(ALPHA, "audit", "ciamLogDestination", ciamBindingRole="audit-logs", ciamDestinationKind="log-group",
                  ciamProviderRef="arn:aws:logs:region-1:111122223333:log-group:/ciam/audit"),
            entry(ALPHA, "ops", "ciamLogDestination", ciamBindingRole="ops-logs", ciamDestinationKind="log-group",
                  ciamProviderRef="arn:aws:logs:region-2:111122223333:log-group:/ciam/ops:*"),
            entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef="splunk://ciam"))


def _services():
    return services()._replace(logs=lambda m: (AM,))


def _alpha():
    _, alpha, _ = model(alpha=BINDINGS, tree=TREE)
    return alpha


def test_lines_are_picked_by_role_classified_in_order_and_sent_per_route():
    blocks, files = render_fluent_bit(_alpha(), _services())
    conf = load_documents(files["kubernetes/fluent-bit/ciam-eks/configmap.yaml"])[0]["data"]["fluent-bit.conf"]
    rules = [line.split(None, 1)[1] for line in conf.splitlines() if line.strip().startswith("Rule")]
    assert rules == [
        "$kubernetes['labels']['opsdir.io/role'] ^am$ ciam.am false",
        "$log ^ ciam.am.main false",                                           # no container-specific source of am
        "$log_processed['eventName'] ^AM\\-ACCESS\\- ciam.am.main.access false",  # first match wins: one filter each
        "$log_processed['eventName'] ^ ciam.am.main.audit false",
        "$log ^ ciam.am.main.debug false"]                                     # the rest: the source's kind
    outputs = conf.split("[OUTPUT]")[1:]
    assert len(outputs) == 2                                                    # the SIEM route isn't a log group
    audit, access = sorted(outputs, key=lambda o: "/ciam/ops" in o)
    assert "Match_Regex       ^ciam\\.am\\.main\\.(audit)$" in audit and "log_group_name    /ciam/audit" in audit
    assert "region            region-1" in audit and "auto_create_group false" in audit
    assert "Match_Regex       ^ciam\\.am\\.main\\.(access|debug)$" in access and "region            region-2" in access
    assert "log_stream_prefix ciam-eks." in access and "endpoint" not in access
    hcl = "\n".join(blocks)
    assert 'values   = ["system:serviceaccount:ciam-logging:fluent-bit"]' in hcl
    assert all(f'"arn:aws:logs:{arn}"' in hcl for arn in (
        "region-1:111122223333:log-group:/ciam/audit:*", "region-1:111122223333:log-group:/ciam/audit",
        "region-2:111122223333:log-group:/ciam/ops:*"))                       # each group and its streams
    assert '"logs:PutLogEvents"' in hcl and "CloudWatchAgentServerPolicy" not in hcl


def test_the_kustomization_and_the_daemonset():
    _, files = render_fluent_bit(_alpha(), _services())
    base = "kubernetes/fluent-bit/ciam-eks"
    assert load_documents(files[f"{base}/kustomization.yaml"])[0]["resources"] == [
        "namespace.yaml", "rbac.yaml", "configmap.yaml", "daemonset.yaml"]
    (ds,) = load_documents(files[f"{base}/daemonset.yaml"])
    pod = ds["spec"]["template"]["spec"]
    assert pod["containers"][0]["image"] == IMAGE and pod["serviceAccountName"] == "fluent-bit"
    assert {"name": "varlog", "mountPath": "/var/log", "readOnly": True} in pod["containers"][0]["volumeMounts"]
    account = load_documents(files[f"{base}/rbac.yaml"])[0]
    assert account["metadata"]["annotations"] == {"eks.amazonaws.com/role-arn": "UNBOUND:fluent-bit-role-arn"}


def test_whats_not_shipped_is_named_and_the_render_carries_it_all():
    alpha = _alpha()
    assert fluent_bit_notes(alpha, _services()) == (
        "# NOTE: log route to-siem: role am's container output not shipped: its destination siem isn't a CloudWatch "
        "log group (kind log-group, a log group ARN)",)
    out = render(alpha, _services())
    assert out["terraform/main.tf"].count('data "aws_eks_cluster" "ciam_eks"') == 1
    assert 'resource "aws_iam_role" "fluent_bit_ciam_eks"' in out["terraform/main.tf"]
    assert "kubernetes/fluent-bit/ciam-eks/daemonset.yaml" in out


def test_a_roles_lines_go_by_container_to_its_sidecars_sources_first():
    tail = LogSource("am", "kubernetes", None, "text", "audit", container="audit-tail")
    idle = LogSource("am", "kubernetes", None, "text", "replication", container="admin-tail")   # no route wants it
    _, files = render_fluent_bit(_alpha(), services()._replace(logs=lambda m: (AM, tail, idle)))
    conf = load_documents(files["kubernetes/fluent-bit/ciam-eks/configmap.yaml"])[0]["data"]["fluent-bit.conf"]
    rules = [line.split(None, 1)[1] for line in conf.splitlines() if line.strip().startswith("Rule")]
    assert rules[1:4] == ["$kubernetes['container_name'] ^audit\\-tail$ ciam.am.audit-tail false",
                          "$kubernetes['container_name'] ^admin\\-tail$ ciam.am.admin-tail false",   # never main's
                          "$log ^ ciam.am.main false"]
    assert "$log ^ ciam.am.audit-tail.audit false" in rules
    assert not any("ciam.am.admin-tail.replication" in r for r in rules)         # nothing ships it: dropped
    assert "Match_Regex       ^ciam\\.am\\.audit\\-tail\\.(audit)$" in conf

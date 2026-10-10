"""Product logs from containers on EKS to CloudWatch Logs (core observability: log routes; what each route ships:
domains/observability/sources): per cluster, a Fluent Bit DaemonSet (AWS for Fluent Bit) reading every container's
output on each node, and the IAM role its service account assumes (IRSA) to write to the routes' log groups. Pure.

kubernetes/fluent-bit/<cluster>/, a kustomization of:
  namespace.yaml        namespace ciam-logging
  rbac.yaml             service account fluent-bit (annotated with its IAM role), and the cluster role the kubernetes
                        filter reads pods and namespaces with
  configmap.yaml        fluent-bit.conf: tail /var/log/containers/*.log (cri and docker lines), the kubernetes filter
                        (JSON lines lifted under log_processed), then three steps by tag:
                          1. a role's pods by their label opsdir.io/role (the deployment kits set it) -> ciam.<role>;
                             other pods' lines go nowhere
                          2. each line's source: by its container (a kit's log sidecar) among the role's sources,
                             the rest the role's main source -> ciam.<role>.<container | main>; then its kind, as
                             that source says: its match rules in order (one rewrite_tag filter each, the first that
                             matches retags the line), then the source's kind -> ciam.<role>.<source>.<kind>
                          3. one cloudwatch_logs output per route and role, matching the kinds the route wants, to
                             the log group its destination is (streams prefixed with the cluster's name; groups are
                             Terraform's: never created here)
  daemonset.yaml        the DaemonSet (Linux nodes, every taint tolerated), /var/log read-only, its tail state on the
                        node
Terraform: the role (trusting the cluster's OIDC provider for ciam-logging/fluent-bit) with logs:CreateLogStream,
PutLogEvents and DescribeLogStreams on the routes' log groups.

Named in main.tf instead (# NOTE): a route whose destination isn't a log group here, a role that runs on Kubernetes
here in no cluster the environment binds. With FIPS endpoints the outputs send to CloudWatch Logs' FIPS endpoint.
Sources (research 2344): docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-logs-FluentBit
.html, docs.fluentbit.io/manual/data-pipeline/filters/rewrite-tag, .../outputs/cloudwatch, .../filters/kubernetes.
"""
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import documents, dump
from opsdir.core.manifest import header
from opsdir.domains.compute.workloads import role_clusters
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.sources import kinds_of, shipments
from opsdir_format_terraform.hcl import block, jsonencoded, ref, tf_name
from .access import resources
from .account import account_id, partition
from .identities import eks_cluster_name, irsa_statement
from .log_agent import log_group

IMAGE = "public.ecr.aws/aws-observability/aws-for-fluent-bit:3.4.17"    # 2026-09-17: Fluent Bit 5.0.9
NAMESPACE, ACCOUNT = "ciam-logging", "fluent-bit"
ROLE_LABEL = "opsdir.io/role"
WRITES = ("logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams")


def _shipped(x):
    return x.on == "kubernetes" and log_group(x.destination) is not None


def cluster_shipments(m, services):
    """((cluster binding, (Shipment, ...)), ...): environment m's container shipments to log groups, per cluster their
    role runs in here."""
    found = tuple(x for x in shipments(m, log_routes(m.d), services.logs(m)) if _shipped(x))
    clusters = {c.dn: c for x in found for c in role_clusters(m, x.role)}
    return tuple((c, tuple(x for x in found if c.dn in {k.dn for k in role_clusters(m, x.role)}))
                 for c in clusters.values())


def _literal(text):
    """A regular expression (Onigmo) matching text literally, without spaces (rule fields are space separated)."""
    return re.escape(text).replace("\\ ", "\\x20")


def _part(name):
    """A name as one part of a tag (tags split at dots)."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", name)


def _tag(role):
    return f"ciam.{_part(role)}"


def _section(name, pairs):
    width = max(len(k) for k, _ in pairs)
    return f"[{name}]\n" + "".join(f"    {k.ljust(width)} {v}\n" for k, v in pairs)


def _rewrite(match, rule):
    return _section("FILTER", (("Name", "rewrite_tag"), ("Match", match), ("Rule", rule)))


MAIN = "main"                       # the tag of a role's lines no container-specific source names


def _source_tag(source):
    """The tag of a role's lines from one of its sources: ciam.<role>.<container> or ciam.<role>.main."""
    return f"{_tag(source.server_role)}.{_part(source.container) if source.container else MAIN}"


def _containers(role, sources):
    """The rewrite_tag filters sending a role's lines to the source of their container (its container-specific
    sources, one filter each), the rest to its main source."""
    tag = _tag(role)
    return (*(_rewrite(tag, f"$kubernetes['container_name'] ^{_literal(s.container)}$ {_source_tag(s)} false")
              for s in sources if s.container),
            _rewrite(tag, f"$log ^ {tag}.{MAIN} false"))


def _kinds(source):
    """The rewrite_tag filters giving a source's lines their kind: its match rules in order, then its kind."""
    tag = _source_tag(source)
    return (*(_rewrite(tag, f"$log_processed['{field}'] ^{_literal(prefix)} {tag}.{kind} false")
              for field, prefix, kind in source.match),
            _rewrite(tag, f"$log ^ {tag}.{source.kind} false"))


def _output(m, cluster, x):
    arn = one(x.destination, "ciamProviderRef")
    region = arn.split(":")[3]
    wanted = [k for k in kinds_of(x.source) if k in values(x.route, "ciamLogKind")]
    return _section("OUTPUT", (
        ("Name", "cloudwatch_logs"),
        ("Match_Regex", f"^{re.escape(_source_tag(x.source))}\\.({'|'.join(wanted)})$"),
        ("region", region), ("log_group_name", log_group(x.destination)),
        ("log_stream_prefix", f"{eks_cluster_name(cluster)}."), ("auto_create_group", "false"),
        *((("endpoint", f"logs-fips.{region}.amazonaws.com"),) if fips_endpoints(m) else ())))


def config_text(m, cluster, found, sources):
    """fluent-bit.conf for a cluster's Shipments, given the LogSources declared (a shipped role's lines are split by
    container among all of its sources there, so lines of a container nothing ships are never taken for another's)."""
    roles = tuple(dict.fromkeys(x.role for x in found))
    own = {r: tuple(s for s in sources if s.server_role == r and s.on == "kubernetes") for r in roles}
    shipped = tuple(dict.fromkeys(x.source for x in found))
    return "\n".join((
        _section("SERVICE", (("Flush", "5"), ("Log_Level", "info"))),
        _section("INPUT", (("Name", "tail"), ("Tag", "kube.*"), ("Path", "/var/log/containers/*.log"),
                           ("multiline.parser", "docker, cri"), ("DB", "/var/fluent-bit/state/ciam-tail.db"),
                           ("Mem_Buf_Limit", "50MB"), ("Skip_Long_Lines", "On"), ("Refresh_Interval", "10"))),
        _section("FILTER", (("Name", "kubernetes"), ("Match", "kube.*"),
                            ("Kube_URL", "https://kubernetes.default.svc:443"),
                            ("Kube_Tag_Prefix", "kube.var.log.containers."), ("Merge_Log", "On"),
                            ("Merge_Log_Key", "log_processed"), ("Keep_Log", "On"), ("Labels", "On"),
                            ("Annotations", "Off"), ("K8S-Logging.Parser", "Off"), ("K8S-Logging.Exclude", "Off"))),
        _section("FILTER", (("Name", "rewrite_tag"), ("Match", "kube.*"),
                            *(("Rule", f"$kubernetes['labels']['{ROLE_LABEL}'] ^{_literal(r)}$ {_tag(r)} false")
                              for r in roles))),
        *(f for r in roles for f in _containers(r, own[r])),
        *(f for s in shipped for f in _kinds(s)),
        *dict.fromkeys(_output(m, cluster, x) for x in found)))


def role_name(m, cluster):
    """The name of the IAM role a cluster's Fluent Bit assumes."""
    return f"ciam-{rdn_value(m.env)}-fluent-bit-{eks_cluster_name(cluster)}"[:64]


def _role_arn(m, cluster):
    account = account_id(m)
    return f"arn:{partition(m)}:iam::{account}:role/{role_name(m, cluster)}" if account \
        else f"{UNBOUND}fluent-bit-role-arn"


def _objects(m, cluster, found, sources):
    labels = {"app.kubernetes.io/name": "fluent-bit"}
    meta = {"name": ACCOUNT, "namespace": NAMESPACE}
    return {
        "namespace.yaml": ("The namespace", [{"apiVersion": "v1", "kind": "Namespace",
                                               "metadata": {"name": NAMESPACE}}]),
        "rbac.yaml": ("Fluent Bit's service account (its IAM role) and what it reads of the cluster", [
            {"apiVersion": "v1", "kind": "ServiceAccount",
             "metadata": {**meta, "annotations": {"eks.amazonaws.com/role-arn": _role_arn(m, cluster)}}},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
             "metadata": {"name": "ciam-fluent-bit"},
             "rules": [{"apiGroups": [""], "resources": ["namespaces", "pods"], "verbs": ["get", "list", "watch"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
             "metadata": {"name": "ciam-fluent-bit"},
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "ciam-fluent-bit"},
             "subjects": [{"kind": "ServiceAccount", **meta}]}]),
        "configmap.yaml": ("Fluent Bit's configuration: each route's container logs to its log group", [
            {"apiVersion": "v1", "kind": "ConfigMap",
             "metadata": {"name": "fluent-bit-config", "namespace": NAMESPACE},
             "data": {"fluent-bit.conf": config_text(m, cluster, found, sources)}}]),
        "daemonset.yaml": ("Fluent Bit on every Linux node", [
            {"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": {**meta, "labels": labels},
             "spec": {"selector": {"matchLabels": labels}, "template": {
                 "metadata": {"labels": labels},
                 "spec": {"serviceAccountName": ACCOUNT, "terminationGracePeriodSeconds": 10,
                          "nodeSelector": {"kubernetes.io/os": "linux"}, "tolerations": [{"operator": "Exists"}],
                          "containers": [{
                              "name": "fluent-bit", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                              "resources": {"requests": {"cpu": "100m", "memory": "100Mi"},
                                            "limits": {"memory": "200Mi"}},
                              "volumeMounts": [{"name": "varlog", "mountPath": "/var/log", "readOnly": True},
                                               {"name": "state", "mountPath": "/var/fluent-bit/state"},
                                               {"name": "config", "mountPath": "/fluent-bit/etc/"}]}],
                          "volumes": [{"name": "varlog", "hostPath": {"path": "/var/log"}},
                                      {"name": "state", "hostPath": {"path": "/var/fluent-bit/state",
                                                                     "type": "DirectoryOrCreate"}},
                                      {"name": "config", "configMap": {"name": "fluent-bit-config"}}]}}}}])}


def manifests(m, cluster, found, sources):
    """{path: text}: a cluster's kubernetes/fluent-bit/<cluster>/ folder, given the LogSources declared."""
    base = f"kubernetes/fluent-bit/{eks_cluster_name(cluster)}"
    objects = _objects(m, cluster, found, sources)
    kustomization = {"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization",
                     "resources": list(objects)}
    return {**{f"{base}/{f}": header(m, what, YAML) + documents(docs) for f, (what, docs) in objects.items()},
            f"{base}/kustomization.yaml": header(m, "Fluent Bit shipping container logs", YAML) + dump(kustomization)}


def role_blocks(m, cluster, found):
    """HCL: the IAM role a cluster's Fluent Bit assumes (IRSA) and its writes to the routes' log groups."""
    n = tf_name(f"fluent_bit_{eks_cluster_name(cluster)}")
    groups = tuple({x.destination.dn: x.destination for x in found}.values())
    return (block("data", ["aws_iam_policy_document", f"{n}_trust"],
                  [irsa_statement(cluster, [f"system:serviceaccount:{NAMESPACE}:{ACCOUNT}"])]),
            block("resource", ["aws_iam_role", n], [
                ("name", role_name(m, cluster)),
                ("assume_role_policy", ref(f"data.aws_iam_policy_document.{n}_trust.json")),
                ("tags", {"Role": "fluent-bit", "Cluster": eks_cluster_name(cluster), "ManagedBy": "opsdir"})]),
            block("resource", ["aws_iam_role_policy", n], [
                ("name", "ship-container-logs"), ("role", ref(f"aws_iam_role.{n}.id")),
                ("policy", jsonencoded({"Version": "2012-10-17", "Statement": [
                    {"Sid": "WriteRouteLogGroups", "Effect": "Allow", "Action": list(WRITES),
                     "Resource": [r for b in groups for r in resources(b)]}]}))]))


def fluent_bit_clusters(m, services):
    """The clusters (bindings) environment m runs Fluent Bit in."""
    return tuple(c for c, _ in cluster_shipments(m, services))


def render_fluent_bit(m, services):
    """(HCL blocks, {path: text}) of environment m's Fluent Bit: per cluster its IAM role and its manifests."""
    found, sources = cluster_shipments(m, services), services.logs(m)
    return (tuple(b for c, xs in found for b in role_blocks(m, c, xs)),
            {p: t for c, xs in found for p, t in manifests(m, c, xs, sources).items()})


def fluent_bit_notes(m, services):
    """HCL comments naming the container logs environment m's routes can't ship to CloudWatch."""
    found = tuple(x for x in shipments(m, log_routes(m.d), services.logs(m)) if x.on == "kubernetes")
    return tuple(dict.fromkeys(
        f"# NOTE: log route {rdn_value(x.route)}: role {x.role}'s container output " + (
            f"not shipped: its destination {rdn_value(x.destination)} isn't a CloudWatch log group (kind log-group, a "
            "log group ARN)" if log_group(x.destination) is None else
            "not shipped: the role runs on Kubernetes here in no cluster the environment binds")
        for x in found if x.destination is not None and (log_group(x.destination) is None
                                                          or not role_clusters(m, x.role))))

"""Kubernetes manifests read as workloads: a StatefulSet's role, cluster, workload role, service account and the cloud
identity it carries, pod security (with its namespace's level), the network policies and ingress hosts that reach it,
the Secrets it reads by name (never their values); manifests under <cloud>/<env>/ also give that environment's
workload binding (images, replicas, resources, storage), others the intent only; roles from labels or roles.json; a
re-import changes nothing and keeps what the record adds."""
import json

from opsdir.connectors.importing import preview_import
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.automation.naming import job_dn
from opsdir.domains.compute.naming import workload_dn
from opsdir.domains.compute.workloads import workload_binding
from opsdir_adapter_kubernetes.adapter import ADAPTER
from opsdir_adapter_kubernetes.workloads import entry_names, environment_at, objects, pod_security, secret_names
import mini_estate
from support import REGISTRY, build_directory

DS = """apiVersion: v1
kind: Namespace
metadata: {name: identity, labels: {pod-security.kubernetes.io/enforce: restricted}}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: ds, namespace: identity, annotations: {eks.amazonaws.com/role-arn: "arn:aws:iam::1:role/ds"}}
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: ds-idrepo
  namespace: identity
  labels: {app.kubernetes.io/name: ds, app.kubernetes.io/component: ds}
  annotations: {opsdir.io/cluster-role: k8s}
spec:
  replicas: 3
  template:
    metadata: {labels: {app: ds-idrepo}}
    spec:
      serviceAccountName: ds
      securityContext: {runAsNonRoot: true}
      containers:
      - name: ds
        image: registry.example.test/ds:7.5.0
        securityContext: {readOnlyRootFilesystem: true}
        resources: {requests: {cpu: 500m, memory: 2Gi}, limits: {memory: 4Gi}}
        env:
        - {name: ADMIN_PASSWORD, valueFrom: {secretKeyRef: {name: ds-passwords, key: admin}}}
        envFrom: [{secretRef: {name: ds-env}}]
      volumes: [{name: keys, secret: {secretName: ds-keystore}}]
  volumeClaimTemplates:
  - metadata: {name: data}
    spec: {storageClassName: fast, resources: {requests: {storage: 100Gi}}}
---
apiVersion: v1
kind: Secret
metadata: {name: ds-passwords, namespace: identity}
data: {admin: bm90LXJlYWQ=}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: ds-ldap, namespace: identity}
spec: {podSelector: {matchLabels: {app: ds-idrepo}}, policyTypes: [Ingress]}
---
apiVersion: v1
kind: Service
metadata: {name: ds, namespace: identity}
spec: {selector: {app: ds-idrepo}, ports: [{port: 1636}]}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: ds-admin, namespace: identity}
spec:
  rules:
  - host: ds-admin.example.test
    http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: ds, port: {number: 8443}}}}]}
"""
AM = json.dumps({"apiVersion": "v1", "kind": "List", "items": [
    {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "am", "namespace": "identity"},
     "spec": {"replicas": 2, "template": {"spec": {"containers": [
         {"name": "am", "image": "registry.example.test/am:7.5.0", "securityContext": {"privileged": True}}]}}}},
    {"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": {"name": "log-shipper", "namespace": "ops"},
     "spec": {"template": {"spec": {"containers": [{"name": "fluent-bit", "image": "fluent/fluent-bit:3.0"}]}}}},
    {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": "ds-backup", "namespace": "identity",
                                                              "annotations": {"opsdir.io/cluster-role": "k8s"}},
     "spec": {"schedule": "0 2 * * *", "jobTemplate": {"spec": {"template": {"spec": {
         "serviceAccountName": "backup", "containers": [{
             "name": "backup", "image": "registry.example.test/ds-backup:1.2", "command": ["/opt/backup.sh"],
             "args": ["--to", "s3://backups"], "envFrom": [{"secretRef": {"name": "backup-creds"}}]}]}}}}}}]})
FILES = {"alpha/prod/identity/ds.yaml": DS, "identity/am.json": AM, "roles.json": json.dumps({"am": "am"}),
         "notes.txt": "key: [unclosed"}
OWNER = tuple(parse(f"dn: {workload_dn('ds-idrepo')}\nchangetype: modify\nadd: ciamOwner\n"
                    "ciamOwner: cn=ops,ou=owners,dc=ciam-ops\n-\n"))
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n\n"
          "dn: cn=ops,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n")


def records():
    return tuple(parse(mini_estate.LDIF + "\n" + OWNERS))


def imported(changes=(), files=None):
    base = build_directory(REGISTRY, records(), changes)
    import_changes, notices = preview_import(base, "kubernetes/workloads", files or FILES, (ADAPTER,))
    return build_directory(REGISTRY, records(), (*changes, *import_changes)), import_changes, notices


def test_a_statefulset_is_a_workload_with_what_reaches_it():
    d, _, _ = imported()
    w = get(d, workload_dn("ds-idrepo"))
    assert (one(w, "ciamWorkloadKind"), one(w, "ciamTargetRole"), one(w, "ciamClusterRole"), one(w, "ciamNamespace"),
            one(w, "ciamWorkloadRole"), one(w, "ciamServiceAccount"), one(w, "ciamIdentityRole"),
            one(w, "ciamRepoPath")) == \
        ("statefulset", "ds", "k8s", "identity", "ds-idrepo-workload", "ds", "ds-identity",
         "alpha/prod/identity/ds.yaml")
    assert values(w, "ciamPodSecurity") == ("runAsNonRoot", "readOnlyRootFilesystem", "level=restricted")
    assert values(w, "ciamNetworkPolicy") == ("ds-ldap: Ingress",)
    assert values(w, "ciamIngressHost") == ("ds-admin.example.test",)
    assert values(w, "ciamSecretName") == ("ds-env", "ds-keystore", "ds-passwords")


def test_manifests_under_an_environment_give_its_workload_binding():
    from opsdir.core.environment import env_model
    d, _, notices = imported()
    b = workload_binding(env_model(d, "alpha/prod"), get(d, workload_dn("ds-idrepo")))
    assert b is not None and b.dn == "cn=ds-idrepo,ou=bindings,env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
    assert (one(b, "ciamBindingRole"), values(b, "ciamContainerImage"), one(b, "ciamWorkloadReplicas"),
            one(b, "ciamCpuRequest"), one(b, "ciamCpuLimit"), one(b, "ciamMemoryRequest"), one(b, "ciamMemoryLimit"),
            one(b, "ciamStorageSize"), one(b, "ciamStorageClass")) == \
        ("ds-idrepo-workload", ("ds=registry.example.test/ds:7.5.0",), "3", "500m", None, "2Gi", "4Gi", "100Gi",
         "fast")
    assert workload_binding(env_model(d, "alpha/prod"), get(d, workload_dn("am"))) is None
    assert "1 manifest file(s) not under <cloud>/<env>/ of an environment the record holds (identity/am.json): " \
           "workloads only, no environment's images, replicas, resources or storage" in notices


def test_an_environment_folder_counts_only_when_the_record_holds_it():
    d, _, _ = imported()
    assert environment_at(d, "alpha/prod/x.yaml") == "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
    assert environment_at(d, "gamma/prod/x.yaml") is None and environment_at(d, "alpha/x.yaml") is None


def test_roles_from_the_role_map_and_what_has_none_is_named():
    d, _, notices = imported()
    am = get(d, workload_dn("am"))
    assert (one(am, "ciamWorkloadKind"), one(am, "ciamTargetRole"), one(am, "ciamClusterRole"),
            values(am, "ciamPodSecurity"), one(am, "ciamIdentityRole")) == ("deployment", "am", "cluster",
                                                                            ("privileged", "level=restricted"), None)
    assert get(d, workload_dn("log-shipper")) is None
    assert "identity/am.json: DaemonSet log-shipper: no role (label opsdir.io/role or app.kubernetes.io/component, " \
           "or roles.json); not imported" in notices
    assert "1 Secret object(s) in the manifests: never read (their values stay in the cluster)" in notices
    assert "not YAML or JSON, not read: notes.txt" in notices


def test_a_cronjob_is_a_job_the_cluster_realizes():
    d, _, _ = imported()
    j = get(d, job_dn("k8s-ds-backup"))
    assert (one(j, "ciamJobKind"), one(j, "ciamSchedule"), one(j, "ciamCommand"), one(j, "ciamRuntime"),
            one(j, "ciamRunsAs"), one(j, "ciamJobRole"), values(j, "ciamSecretName")) == \
        ("cron", "0 2 * * *", "/opt/backup.sh --to s3://backups", "registry.example.test/ds-backup:1.2", "backup",
         "k8s", ("backup-creds",))


def test_secret_values_never_reach_the_record():
    d, changes, _ = imported()
    assert "bm90LXJlYWQ=" not in repr(changes) and "not-read" not in repr(changes)


def test_a_reimport_changes_nothing_and_keeps_the_owner():
    _, first, _ = imported()
    d, changes, _ = imported((*first, *OWNER))
    assert not changes and one(get(d, workload_dn("ds-idrepo")), "ciamOwner") == "cn=ops,ou=owners,dc=ciam-ops"


def test_names_across_namespaces_and_the_helpers():
    found = [(p, o) for p, o in objects({"a.yaml": "kind: Deployment\nmetadata: {name: web, namespace: a}\n---\n"
                                                   "kind: Deployment\nmetadata: {name: web, namespace: b}\n"}) if o]
    assert entry_names(found) == ["a-web", "b-web"]
    pod = {"spec": {"template": {"spec": {"hostNetwork": True, "volumes": [
        {"projected": {"sources": [{"secret": {"name": "tls"}}]}}], "containers": [{"name": "x"}]}}}}
    assert pod_security(pod, {}) == ("hostNetwork",) and secret_names(pod) == ("tls",)


def test_a_namespace_collected_live_reads_as_its_saved_manifests():
    """`opsdir collect` with a k8s://<context>/<namespace>/workloads source: what kubectl prints for the namespace,
    trimmed, imports as the same objects saved by hand do (except where each was read from: ciamRepoPath)."""
    from opsdir.connectors.collecting import collect, collectors
    from opsdir.core.environment import env_model
    served = [o for _, o in objects(FILES) if o and (o.get("metadata") or {}).get("namespace") == "identity"
              and o["kind"] not in ("Namespace", "Secret")]
    namespace = next(o for _, o in objects(FILES) if o and o["kind"] == "Namespace")
    leaky = json.loads(json.dumps(served))
    leaky[0].setdefault("metadata", {})["managedFields"] = [{"manager": "kubectl"}]
    for o in leaky:
        if o["kind"] == "StatefulSet":
            o["spec"]["template"]["spec"]["containers"][0]["env"].append({"name": "JAVA_OPTS", "value": "-Dpw=hunter2"})
    source = ("dn: ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: settings\n\n"
              "dn: cn=collect-from-kubernetes,ou=settings,dc=ciam-ops\n"
              "objectClass: top\nobjectClass: ciamEstateSetting\n"
              "cn: collect-from-kubernetes\nciamEstateValue: TRUE\n\n"
              "dn: cn=k8s-identity,ou=bindings,env=prod,cloud=alpha,ou=environments,dc=ciam-ops\nobjectClass: top\n"
              "objectClass: ciamCollectionSource\ncn: k8s-identity\nciamBindingRole: collect-k8s\n"
              "ciamImporter: kubernetes/workloads\nciamSourceRef: k8s://prod-east/identity/workloads\n")
    d = build_directory(REGISTRY, (*records(), *parse(source)))
    m = env_model(d, "alpha/prod")
    (collector,) = [c for c in collectors(ADAPTER, m) if c.importer == "workloads"]
    answers = {"get": json.dumps({"kind": "List", "items": leaky}), "namespace": json.dumps(namespace)}
    c = collect("kubernetes/workloads", collector, d, m,
                lambda call: (answers["namespace" if "namespace" in call.argv else "get"], None))
    assert c.problems == () and sorted(c.files) == ["prod-east/identity/namespace.json",
                                                    "prod-east/identity/objects.json"]
    assert "hunter2" not in "".join(c.files.values()) and "managedFields" not in "".join(c.files.values())
    saved = {"identity/live.json": json.dumps({"kind": "List", "items": [namespace, *served]})}
    plain = lambda changes: sorted((r.dn, sorted((a, v) for a, v in r.attrs.items() if a != "ciamRepoPath"))
                                   for r in changes if r.changetype == "add")
    collected, _ = preview_import(d, "kubernetes/workloads", c.files, (ADAPTER,))
    by_hand, _ = preview_import(d, "kubernetes/workloads", saved, (ADAPTER,))
    assert plain(collected) == plain(by_hand) and any(r.dn == workload_dn("ds-idrepo") for r in collected)


GATEWAYS = """apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge-gw
  namespace: edge
  annotations: {opsdir.io/cluster-role: k8s, gateway.istio.io/name-override: edge-gw}
spec:
  gatewayClassName: istio
  infrastructure:
    annotations: {service.beta.kubernetes.io/azure-load-balancer-ipv4: 10.1.9.10}
  listeners: [{name: http, protocol: HTTP, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: other-gw, namespace: edge}
spec: {gatewayClassName: nginx, listeners: [{name: http, protocol: HTTP, port: 80}]}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: login, namespace: ciam}
spec: {hostnames: [login.example.test]}
"""


def test_gateways_under_an_environment_are_its_cluster_gateways():
    d, _, notices = imported(files={**FILES, "alpha/prod/edge/gateways.yaml": GATEWAYS,
                                    "edge/stray.yaml": GATEWAYS.split("---")[1]})
    gw = get(d, "cn=edge-gw,ou=bindings,env=prod,cloud=alpha,ou=environments,dc=ciam-ops")
    assert (one(gw, "ciamClusterRole"), one(gw, "ciamNamespace"), one(gw, "ciamGatewayImplementation"),
            one(gw, "ciamFrontendIp"), one(gw, "ciamBindingRole")) == ("k8s", "edge", "istio", "10.1.9.10",
                                                                       "edge-gw-gateway")
    other = get(d, "cn=other-gw,ou=bindings,env=prod,cloud=alpha,ou=environments,dc=ciam-ops")
    assert other is not None and one(other, "ciamGatewayImplementation") is None
    assert any("GatewayClass 'nginx' isn't one opsdir renders (envoy, istio)" in n for n in notices)
    assert "1 HTTPRoute(s): not read (a deployment kit declares its routes)" in notices
    assert any(n.startswith("edge/stray.yaml: Gateway other-gw: not under <cloud>/<env>/") for n in notices)

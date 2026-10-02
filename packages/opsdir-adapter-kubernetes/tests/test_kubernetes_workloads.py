"""Kubernetes manifests read as workloads: a StatefulSet's role, cluster, replicas, images, storage, service account
and the cloud identity it carries, pod security (with its namespace's level), the network policies and ingress hosts
that reach it, the Secrets it reads by name (never their values); roles from labels or roles.json; a re-import
changes nothing and keeps what the record adds."""
import json

from opsdir.connectors.importing import preview_import
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.automation.naming import job_dn
from opsdir.domains.compute.naming import workload_dn
from opsdir_adapter_kubernetes.adapter import ADAPTER
from opsdir_adapter_kubernetes.workloads import entry_names, objects, pod_security, secret_names
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
FILES = {"identity/ds.yaml": DS, "identity/am.json": AM, "roles.json": json.dumps({"am": "am"}),
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
            one(w, "ciamReplicaCount"), one(w, "ciamStorageSize"), one(w, "ciamStorageClass"),
            one(w, "ciamServiceAccount"), one(w, "ciamIdentityRole"), one(w, "ciamRepoPath")) == \
        ("statefulset", "ds", "k8s", "identity", "3", "100Gi", "fast", "ds", "ds-identity", "identity/ds.yaml")
    assert values(w, "ciamContainerImage") == ("registry.example.test/ds:7.5.0",)
    assert values(w, "ciamPodSecurity") == ("runAsNonRoot", "readOnlyRootFilesystem", "level=restricted")
    assert values(w, "ciamNetworkPolicy") == ("ds-ldap: Ingress",)
    assert values(w, "ciamIngressHost") == ("ds-admin.example.test",)
    assert values(w, "ciamSecretName") == ("ds-env", "ds-keystore", "ds-passwords")


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

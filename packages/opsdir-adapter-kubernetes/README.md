# opsdir-adapter-kubernetes

opsdir adapter for Kubernetes: Kubernetes secrets as a secret store any environment can reference (`k8s-secret://`), and what clusters run, read from their manifests: workloads (the core `compute` domain: server roles run as containers) and CronJobs (the core `automation` domain's jobs).

**Applies to** no environment as a renderer (`applies` is always false: kind `secret-store`). Its reference scheme resolves wherever a binding uses it, and its importer works whether or not an environment declares it.

**Depends on** `opsdir` (the compute and automation domains) and `pyyaml`.

## What it renders

Nothing. Kubernetes overlays and Helm values (ForgeOps) are milestone 5.2.

## Secret references

A binding's `ciamRefUri` of the form `k8s-secret://<namespace>/<secret>/<key>` names one key of a Kubernetes secret. `opsdir` resolves it at run time with `kubectl get secret -n <namespace> <secret> -o jsonpath='{.data.<key>}' | base64 -d` (dots in a key are escaped for JSONPath). The value never reaches the database or a rendered file.

## Reading workloads from manifests

```bash
kubectl get statefulsets,deployments,daemonsets,cronjobs,services,ingresses,networkpolicies,serviceaccounts,namespaces \
  -A -o yaml > manifests/cluster.yaml        # or rendered Helm/Kustomize output: helm template …, kustomize build …
opsdir import --dry-run kubernetes/workloads manifests/
opsdir import --change CHG-… kubernetes/workloads manifests/
```

Any YAML or JSON file is read, multi-document YAML and `List` output included. Every StatefulSet, Deployment and DaemonSet is one workload (`ciamWorkload`, `cn=<name>,ou=workloads`): intent, the same in every environment.

| From | Recorded |
|---|---|
| label or annotation `opsdir.io/role`, else label `app.kubernetes.io/component`, else `app.kubernetes.io/name`, else `roles.json` (`{workload name: role}`) | `ciamTargetRole`: the server role it realizes. Without one the workload is named, not imported |
| annotation `opsdir.io/cluster-role` | `ciamClusterRole`: the binding role of the cluster it runs in (each environment binds it with a `ciamCluster`), else `cluster` |
| `metadata.namespace`, `spec.replicas` (not for a DaemonSet) | `ciamNamespace`, `ciamReplicaCount` |
| the pod template's containers | `ciamContainerImage` |
| its first volume claim template | `ciamStorageSize`, `ciamStorageClass` |
| `serviceAccountName` | `ciamServiceAccount` |
| its ServiceAccount's cloud identity annotation (`eks.amazonaws.com/role-arn`, `azure.workload.identity/client-id`, `iam.gke.io/gcp-service-account`) | `ciamIdentityRole`: the binding role each environment gives it (annotation `opsdir.io/identity-role` on the workload or account, else `<role>-identity`); the identity itself is the environment's binding (milestone 4.7) |
| security contexts; the namespace's `pod-security.kubernetes.io/enforce` label | `ciamPodSecurity`: `runAsNonRoot`, `readOnlyRootFilesystem` (every container), `privileged`, `hostNetwork`, `hostPID`, `level=<level>` |
| NetworkPolicies in its namespace whose pod selector selects it | `ciamNetworkPolicy`: `name: policy types` |
| Ingress rules whose backend is a Service selecting it | `ciamIngressHost` |
| env `secretKeyRef`, `envFrom` `secretRef`, secret and projected volumes | `ciamSecretName`: the Secrets' names, never their values |
| the file | `ciamRepoPath` |

**CronJobs** are jobs (`ciamJob`, `cn=k8s-<name>,ou=jobs`): kind `cron`, the schedule, the command and arguments of the first container (not recorded when they hold secret material: named), its image (`ciamRuntime`), service account (`ciamRunsAs`), the Secrets it reads by name, and the cluster role that realizes it (`ciamJobRole`, from `opsdir.io/cluster-role`, else `cluster`). The automation domain's planner check then asks the target to bind that cluster.

**Names.** A workload is named by its metadata name, `namespace-name` when two namespaces use the name. A re-import finds it by name and changes nothing; what the record adds (owners, criticality) is kept.

**Secrets.** Secret objects in the manifests are never read; they are counted in the notices. Only the names of the Secrets a workload reads are recorded.

**Collected live** (`opsdir collect --env CLOUD/ENV`, with the estate setting `collect-from-kubernetes` on): a collection source per namespace, `ciamImporter: kubernetes/workloads` and `ciamSourceRef: k8s://<kubectl context>/<namespace>/workloads`, read with your own kubectl context: `kubectl get statefulsets,deployments,daemonsets,cronjobs,services,ingresses,networkpolicies,serviceaccounts -n <namespace> -o json` and the namespace itself (its pod-security label). Secrets are never listed; literal env values, `managedFields` and the last-applied annotation are dropped before the export. A live namespace has no `roles.json`, so label the workloads (`opsdir.io/role` or `app.kubernetes.io/component`). The context name must be a plain name (rename an EKS ARN context with `kubectl config rename-context`). Least privilege: a Role with `get`, `list` on those eight resources in the namespace, and a ClusterRole with `get` on `namespaces`.

**Notices:** workloads without a role, names that can't be a record name, Secret objects (counted), files that aren't YAML or JSON, manifests with no workloads.

The planner (core `compute` domain) then blocks a move whose target has no cluster for a workload and no servers of its role, and a workload identity role nobody binds; a privileged workload is an action. Clusters themselves (`ciamCluster`: version, add-ons, node pools) are read by the cloud adapters (EKS, AKS).

## References, vocabulary and schema

The `k8s-secret` reference scheme. No schema of its own: workloads and clusters are the core `compute` domain's. Adapter kind `secret-store`.

## Known limits

- Not run against a live cluster yet; manifests as the Kubernetes API documents them (apps/v1, networking.k8s.io/v1).
- Not read yet: one-off Jobs, operators' custom resources (the DS operator's `DirectoryService`, ForgeOps secret agent, external-secrets `ExternalSecret`), resource requests and limits, pod disruption budgets, horizontal autoscalers, NetworkPolicy rule details (only the policy and its types), Gateway API routes.
- An Ingress backend is matched to a workload through a Service's selector in the same namespace; `ExternalName` services and cross-namespace routing aren't followed.

## Tests

`tests/test_kubernetes.py`: registration, never rendering, resolving a key through the registry, JSONPath escaping. `tests/test_kubernetes_workloads.py`: a StatefulSet with its role, cluster, storage, identity, pod security (and namespace level), network policy, ingress host and secret names; roles from `roles.json`, a workload without one named; Secret values never reaching the record; a re-import changing nothing and keeping an owner; a CronJob as a job the cluster realizes; names across namespaces and the helpers; a namespace collected live (trimmed) importing as its saved manifests do.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `kubernetes`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

# opsdir-adapter-kubernetes

opsdir adapter for Kubernetes: what every workload an environment runs on Kubernetes needs around it (namespaces, service accounts with their cloud identities, network policies, secret delivery), Kubernetes secrets as a secret store any environment can reference (`k8s-secret://`), and what clusters run, read from their manifests: workloads (the core `compute` domain: server roles run as containers) and CronJobs (the core `automation` domain's jobs).

**Applies to** environments that run workloads on Kubernetes (a workload binding for at least one workload); kind `platform`, so an environment that declares a stack renders it only when the stack names it (`opsdir check` names it otherwise). Its reference scheme resolves wherever a binding uses it, and its importer works whether or not an environment declares it.

**Depends on** `opsdir` (the compute and automation domains) and `pyyaml`.

## What it renders

Per environment, one folder per namespace of the workloads it runs on Kubernetes, `kubernetes/<namespace>/`, a kustomization (`kustomization.yaml`) of:

| File | What |
|---|---|
| `namespace.yaml` | the Namespace, labelled `pod-security.kubernetes.io/enforce` with the most permissive level its workloads record (`level=` in `ciamPodSecurity`) |
| `serviceaccounts.yaml` | a ServiceAccount per account its workloads run as (`ciamServiceAccount`, else the workload's name), annotated with the cloud identity of the workload's `ciamIdentityRole`: the provider adapter's workload identity (AWS IRSA, AKS workload identity, GKE Workload Identity Federation) |
| `networkpolicies.yaml` | a default deny of ingress, and a policy per workload (pods labelled `opsdir.io/role: <role>`) admitting what its pods listen on: the container ports its deployment kit declares (listeners `on="kubernetes"`), else its products' listeners. Client and admin ports from anywhere; its peers and other server roles from pods with their role label when they run on Kubernetes in the environment, from their servers' subnets otherwise |
| `externalsecrets.yaml` | target `external-secrets`: a SecretStore per secret store, scheme and service account, and an ExternalSecret per Secret (`external-secrets.io/v1`) |
| `secretproviderclasses.yaml` | target `csi`: a SecretProviderClass per workload and secret store (`secrets-store.csi.x-k8s.io/v1`), syncing the Secrets the workload reads (`secretObjects`) |
| `secrets-required.yaml` | not a Kubernetes object, so not in the kustomization: every Secret key the workloads read (`ciamWorkloadSecret: <secret>/<key> <- <role>`), the role and reference that fill it, what delivers it, and which workloads read it |

The deployment kit (`opsdir-adapter-forgeops`, `opsdir-adapter-ping-devops`, plain manifests) renders the workloads themselves and must label each pod `opsdir.io/role: <role>`, run it as the service account above, add the pod labels its cloud's workload identity needs (AKS: `azure.workload.identity/use: "true"`) and, with target `csi`, mount the provider class. Neither kit's rendered pods mount one, so with them the Secrets come by `external-secrets`. ForgeOps' charts take no extra volumes; the ping-devops chart could mount one, but its values don't yet. The kits read what they set from a workload's binding through `kits.py`: images, replicas, resources, storage and pod labels. Each kit declares its pods' container ports as listeners (`on="kubernetes"`); they replace the product's ports (PingAM's 8443 on its servers) in the role's policy, and the firewall checks leave them out.

**Render targets** (`opsdir render --target kubernetes=external-secrets` or `=csi`, only when asked): how the Secrets get their values. Without one, `secrets-required.yaml` says what the operator creates. How a reference is read is the adapter's that owns its scheme (`Adapter.secret_delivery`): `vault://` (hashicorp-vault), `aws-sm://` (aws), `azkv://` (azure), `gcp-sm://` (gcp). A `k8s-secret://` reference to the Secret itself needs nothing; any other scheme is named for the operator. What the record doesn't say is written `UNBOUND:<what>` (a Vault address with no `ciamSecretStore`, an Azure client id with no `ciamIdentityClientId`).

Checked by `opsdir/scripts/validate-kubernetes.sh` (kustomize build + kubeconform -strict with the External Secrets and CSI schemas).

## The in-cluster gateway behind the cloud's front

A role an environment runs only on Kubernetes is reached through its cluster's in-cluster gateway when the record has one (`ciamClusterGateway`, the core edge domain). The cloud adapter renders the front before it (load balancer, WAF, TLS certificate, DNS record) from the service name's policies; `gateway.py` renders what is behind it, Gateway API standard channel (v1.6.1) plus the implementation's own objects:

- `kubernetes/<gateway namespace>/gateway.yaml`: the Gateway, with an HTTP listener (80) for service names whose TLS the front terminates and an HTTPS one (443) presenting the gateway's internal certificate for those the front re-encrypts (the Secret its binding's `ciamWorkloadSecret` keys `tls.crt` and `tls.key` name, delivered like a workload's); routes allowed from the fronted roles' namespaces only. The cloud's plug (`Services.gateway_plug`) gives the gateway Service's annotations and type and any objects it needs (a target group binding on AWS).
- `kubernetes/<role namespace>/routes.yaml`: an HTTPRoute per fronted service name (host = its `ciamFqdn`) from the routes its deployment kit declares (`Adapter.routes`: ForgeOps, ping-devops), prefix rewrites as `URLRewrite ReplacePrefixMatch`; a BackendTLSPolicy for a Service that speaks TLS (PingFederate), checked against ConfigMap `<gateway>-backend-ca`, rendered beside it: `ca.crt` holds the PEMs recorded (`ciamCertificatePem`, public material) for the CAs the gateway trusts (`ciamTrustsCertificate`; core `edge.gateways.backend_ca`), or `UNBOUND:<ca>-pem` while one isn't recorded (the planner's action); and cookie stickiness (`route`) when the traffic policy asks for it.

Which implementation runs a gateway is data: the binding's `ciamGatewayImplementation`, else the estate setting `kubernetes-gateway-implementation` (this adapter declares it; `opsdir report settings`). Rows (`gateway.IMPLEMENTATIONS`), each pinned to the release its objects were checked against:

| Implementation | Default | Service name, type, annotations | Trusted X-Forwarded-For | Stickiness |
|---|---|---|---|---|
| `istio` (gateway only, no mesh; 1.31.1) | yes | Gateway annotations `gateway.istio.io/name-override`, `networking.istio.io/service-type`; `spec.infrastructure.annotations` (copied to the Service and pods) | `proxy.istio.io/config` `numTrustedProxies: 1` | DestinationRule `httpCookie` per backend Service |
| `envoy-gateway` (v1.9.2) | | EnvoyProxy `envoyService` (name, type, annotations) the Gateway names; GatewayClass `envoy` rendered | ClientTrafficPolicy `numTrustedHops: 1` | BackendTrafficPolicy consistent-hash cookie on the HTTPRoute |

The platform team installs the implementation (Istio: the `base` and `istiod` charts, images from the registry it chooses, e.g. Iron Bank or a FIPS distribution, through `global.hub`/`global.tag`; Envoy Gateway: `gateway-helm`) and the Gateway API v1.6.1 standard CRDs. Rendered objects are checked offline with kubeconform against the pinned CRDs catalog.

## Secret references

A binding's `ciamRefUri` of the form `k8s-secret://<namespace>/<secret>/<key>` names one key of a Kubernetes secret. `opsdir` resolves it at run time with `kubectl get secret -n <namespace> <secret> -o jsonpath='{.data.<key>}' | base64 -d` (dots in a key are escaped for JSONPath). The value never reaches the database or a rendered file.

Configuration management (`opsdir-adapter-ansible`) reads such a reference at run time with the `kubernetes.core.k8s` lookup (kind Secret, the key's data base64-decoded; `ansible_lookup`), with the controller's kubeconfig.

## Reading workloads from manifests

```bash
kubectl get statefulsets,deployments,daemonsets,cronjobs,services,ingresses,networkpolicies,serviceaccounts,namespaces \
  -A -o yaml > manifests/cluster.yaml        # or rendered Helm/Kustomize output: helm template …, kustomize build …
opsdir import --dry-run kubernetes/workloads manifests/
opsdir import --change CHG-… kubernetes/workloads manifests/
```

Any YAML or JSON file is read, multi-document YAML and `List` output included. Every StatefulSet, Deployment and DaemonSet is one workload (`ciamWorkload`, `cn=<name>,ou=workloads`): intent, the same in every environment. Manifests under `<cloud>/<env>/` of an environment the record holds (`manifests/aws/prod/cluster.yaml`) also give that environment's **workload binding** (`ciamWorkloadBinding`, `cn=<name>,ou=bindings,<environment>`): how it runs the workload on Kubernetes. Manifests anywhere else give the intent only (named in the notices).

| From | Recorded |
|---|---|
| label or annotation `opsdir.io/role`, else label `app.kubernetes.io/component`, else `app.kubernetes.io/name`, else `roles.json` (`{workload name: role}`) | `ciamTargetRole`: the server role it realizes. Without one the workload is named, not imported |
| annotation `opsdir.io/cluster-role` | `ciamClusterRole`: the binding role of the cluster it runs in (each environment binds it with a `ciamCluster`), else `cluster` |
| `metadata.namespace` | `ciamNamespace` |
| annotation `opsdir.io/workload-role` | `ciamWorkloadRole`: the binding role of its workload binding, else `<name>-workload` |
| `serviceAccountName` | `ciamServiceAccount` |
| its ServiceAccount's cloud identity annotation (`eks.amazonaws.com/role-arn`, `azure.workload.identity/client-id`, `iam.gke.io/gcp-service-account`) | `ciamIdentityRole`: the binding role each environment gives it (annotation `opsdir.io/identity-role` on the workload or account, else `<role>-identity`); the identity itself is the environment's binding (milestone 4.7) |
| security contexts; the namespace's `pod-security.kubernetes.io/enforce` label | `ciamPodSecurity`: `runAsNonRoot`, `readOnlyRootFilesystem` (every container), `privileged`, `hostNetwork`, `hostPID`, `level=<level>` |
| NetworkPolicies in its namespace whose pod selector selects it | `ciamNetworkPolicy`: `name: policy types` |
| Ingress rules whose backend is a Service selecting it | `ciamIngressHost` |
| env `secretKeyRef`, `envFrom` `secretRef`, secret and projected volumes | `ciamSecretName`: the Secrets' names, never their values |
| the file | `ciamRepoPath` |

The workload binding (manifests under `<cloud>/<env>/`):

| From | Recorded |
|---|---|
| the workload role | `ciamBindingRole` |
| the pod template's containers | `ciamContainerImage`: `container=image`, one per container |
| `spec.replicas` (not for a DaemonSet) | `ciamWorkloadReplicas` |
| the first container's `resources` | `ciamCpuRequest`, `ciamCpuLimit`, `ciamMemoryRequest`, `ciamMemoryLimit` |
| its first volume claim template | `ciamStorageSize`, `ciamStorageClass` |

The Secret keys a workload reads and the secret roles that fill them (`ciamWorkloadSecret: <secret>/<key> <- <role>`) aren't in a manifest: operators record them (the renderers of milestone 5.2 deliver them).

**CronJobs** are jobs (`ciamJob`, `cn=k8s-<name>,ou=jobs`): kind `cron`, the schedule, the command and arguments of the first container (not recorded when they hold secret material: named), its image (`ciamRuntime`), service account (`ciamRunsAs`), the Secrets it reads by name, and the cluster role that realizes it (`ciamJobRole`, from `opsdir.io/cluster-role`, else `cluster`). The automation domain's planner check then asks the target to bind that cluster.

**Names.** A workload is named by its metadata name, `namespace-name` when two namespaces use the name. A re-import finds it by name and changes nothing; what the record adds (owners, criticality) is kept.

**Secrets.** Secret objects in the manifests are never read; they are counted in the notices. Only the names of the Secrets a workload reads are recorded.

**Collected live** (`opsdir collect --env CLOUD/ENV`, with the estate setting `collect-from-kubernetes` on): a collection source per namespace, `ciamImporter: kubernetes/workloads` and `ciamSourceRef: k8s://<kubectl context>/<namespace>/workloads` (add `?prefix=<cloud>/<env>/` to record that environment's workload bindings), read with your own kubectl context: `kubectl get statefulsets,deployments,daemonsets,cronjobs,services,ingresses,networkpolicies,serviceaccounts -n <namespace> -o json` and the namespace itself (its pod-security label). Secrets are never listed; literal env values, `managedFields` and the last-applied annotation are dropped before the export. A live namespace has no `roles.json`, so label the workloads (`opsdir.io/role` or `app.kubernetes.io/component`). The context name must be a plain name (rename an EKS ARN context with `kubectl config rename-context`). Least privilege: a Role with `get`, `list` on those eight resources in the namespace, and a ClusterRole with `get` on `namespaces`.

**Notices:** workloads without a role, names that can't be a record name, Secret objects (counted), manifest files not under an environment's folder (intent only), files that aren't YAML or JSON, manifests with no workloads.

The planner (core `compute` domain) then blocks a move whose target neither runs a workload on Kubernetes (its workload binding) nor has servers of its role, a target workload binding without its cluster, and identity or secret roles nobody binds; a role moving between servers and Kubernetes (what its host baseline carries must move into the image, or back) and a privileged workload are actions. Workload bindings are local to their environment, so the core role check doesn't ask the target to bind them. Clusters themselves (`ciamCluster`: version, add-ons, node pools) are read by the cloud adapters (EKS, AKS).

**Gateways** (`gateway_import.py`): a Gateway API Gateway in manifests under `<cloud>/<env>/` is that environment's cluster gateway binding (`ciamClusterGateway`), named like the Gateway: the implementation whose GatewayClass it names (`istio`, `envoy` -> `envoy-gateway`; another class is named in a notice), its namespace, the cluster role (`opsdir.io/cluster-role`, else `cluster`), the binding role (`opsdir.io/gateway-role`, else `<name>-gateway`), and the private address its Service takes when its infrastructure annotations give Azure's (`azure-load-balancer-ipv4`). The rendered Gateway carries both opsdir annotations, so a render reads back as the same binding. What the record adds (its CA, Secret keys, owners) is kept.

## References, vocabulary and schema

The `k8s-secret` reference scheme; the vocabulary of `ciamGatewayImplementation` (`istio`, `envoy-gateway`) and the estate setting `kubernetes-gateway-implementation`. No schema of its own (the cluster gateway binding is the core edge domain's): workloads, workload bindings and clusters are the core `compute` domain's, secret stores (`ciamSecretStore`) the `pki` domain's. Adapter kind `platform`; render targets `external-secrets`, `csi`.

## Known limits

- Not run against a live cluster yet; manifests as the Kubernetes API documents them (apps/v1, networking.k8s.io/v1).
- Not read yet: one-off Jobs, operators' custom resources (the DS operator's `DirectoryService`, ForgeOps secret agent, external-secrets `ExternalSecret`), sidecars' resource requests and limits (only the first container's), pod disruption budgets, horizontal autoscalers, NetworkPolicy rule details (only the policy and its types), Gateway API routes.
- An Ingress backend is matched to a workload through a Service's selector in the same namespace; `ExternalName` services and cross-namespace routing aren't followed.

- HTTPRoutes aren't read back (a deployment kit declares its routes); Gateways are (below).

## Tests

`tests/test_kubernetes.py`: registration (kind, render targets), resolving a key through the registry, JSONPath escaping. `tests/test_kubernetes_render.py`: applies only where workloads run on Kubernetes; the namespace folder and kustomization; service accounts with the provider's identity; network policies from listeners (pods by label, servers by subnet; a kit's container ports replacing the product's); the secrets required and what delivers them; External Secrets and CSI when asked; names; the whole render valid for kustomize and kubeconform (marker `kubernetes`). `tests/test_kubernetes_workloads.py`: a StatefulSet with its role, cluster, workload role, identity, pod security (and namespace level), network policy, ingress host and secret names; roles from `roles.json`, a workload without one named; Secret values never reaching the record; manifests under an environment's folder giving its workload binding (images, replicas, resources, storage) and others the intent only; an environment folder counting only when the record holds it; a re-import changing nothing and keeping an owner; a CronJob as a job the cluster realizes; names across namespaces and the helpers; a namespace collected live (trimmed) importing as its saved manifests do.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `kubernetes`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

# opsdir-adapter-kubernetes

opsdir adapter for Kubernetes: what every workload an environment runs on Kubernetes needs around it (namespaces, service accounts with their cloud identities, network policies, Secret delivery), the in-cluster gateway behind a cloud's front, Kubernetes secrets as a secret store any environment can reference (`k8s-secret://`), and what clusters run, read from their manifests: workloads (the core `compute` domain: server roles run as containers), CronJobs (the core `automation` domain's jobs) and Gateways (the core `edge` domain's cluster gateways). It also holds what the deployment kits share (`kits.py`, `names.py`).

**Applies to** environments that run workloads on Kubernetes (a workload binding for at least one workload). Kind `platform`: an environment that declares a stack renders it only when the stack names it (`kubernetes`); one that declares none renders it when it has such a binding. Its reference scheme resolves wherever a binding uses it, and its importer works whether or not an environment declares it.

**Depends on** `opsdir` (the compute, automation, edge, network and pki domains) and `pyyaml`. How a reference is delivered into a Secret, a cloud identity's annotations and the gateway Service's cloud wiring come from the adapters that own them (opsdir-adapter-aws, -azure, -gcp, -hashicorp-vault); the workloads themselves from a deployment kit (opsdir-adapter-forgeops, opsdir-adapter-ping-devops) or plain manifests. The `kubernetes` tests and `opsdir/scripts/validate-kubernetes.sh` need kustomize and kubeconform (`opsdir/scripts/fetch-tools.sh`); `opsdir/scripts/validate-csi-sync.sh` needs a local kind cluster.

## What it renders

Per environment, one folder per namespace of the workloads it runs on Kubernetes (and of its cluster gateways), `kubernetes/<namespace>/`, a kustomization (`kustomization.yaml`) of:

| File | From the record | Rendered as |
|---|---|---|
| `namespace.yaml` | the namespace's workloads' `ciamPodSecurity` `level=` | the Namespace, labelled `pod-security.kubernetes.io/enforce` with the most permissive level they record (privileged, baseline, restricted) |
| `serviceaccounts.yaml` | each workload's `ciamServiceAccount` (else its name) and `ciamIdentityRole` | a ServiceAccount per account the workloads (and cluster gateways) run as, annotated with the cloud identity the environment binds to that role: the provider adapter's workload identity (AWS IRSA, AKS workload identity, GKE Workload Identity Federation) |
| `networkpolicies.yaml` | the workloads' `ciamTargetRole`, the listeners of the environment's adapters | a default deny of ingress, and a policy per workload (`<workload>-ingress`, pods labelled `opsdir.io/role: <role>`) admitting what its pods listen on: the container ports its deployment kit declares (listeners `on="kubernetes"`), else its products' listeners. Client and admin ports from anywhere; its peers and other server roles from pods with their role label when they run on Kubernetes in the environment, from their servers' subnets otherwise. Each is labelled `app.kubernetes.io/managed-by: opsdir`, so the workloads importer knows it as this adapter's own |
| `externalsecrets.yaml` | target `external-secrets`: the Secret keys the workloads read and the references their roles' bindings hold | a SecretStore per secret store, scheme and service account, and an ExternalSecret per Secret and store (`external-secrets.io/v1`, refresh 1h; the first owns the Secret, the others merge into it) |
| `secretproviderclasses.yaml` | target `csi`: the same | a SecretProviderClass per workload and secret store (`secrets-store.csi.x-k8s.io/v1`), syncing the Secrets the workload reads (`secretObjects`, objects aliased `<secret>-<key>`) |
| `secretsync.yaml` | target `csi`: the workloads no deployment kit mounts, and the cluster gateways | a sync pod per service account (below) |
| `gateway.yaml`, `routes.yaml` | a cluster gateway (below) | the Gateway API objects behind the cloud's front |
| `secrets-required.yaml` | every Secret key the workloads read (`ciamWorkloadSecret: <secret>/<key> <- <role>`) | not a Kubernetes object, so not in the kustomization: each key, the role and reference that fill it (`UNBOUND:<role>` when the environment binds none), what delivers it, and which workloads read it |

The deployment kit (opsdir-adapter-forgeops, opsdir-adapter-ping-devops, plain manifests) renders the workloads themselves and must label each pod `opsdir.io/role: <role>`, run it as the service account above and add the pod labels its cloud's workload identity needs (AKS: `azure.workload.identity/use: "true"`). The kits read what they set from a workload's binding through `kits.py`: images (`ciamContainerImage`; `chart_image` and `split_image` turn a reference with a digest into a chart's or Kustomize's terms), replicas, resources, storage, pod labels, and the marks that make what they deploy read back as the record (below). Each kit declares its pods' container ports as listeners (`on="kubernetes"`); they replace the product's ports (PingAM's 8443 on its servers) in the role's policy, and the firewall checks leave them out.

### Secret delivery (render targets `external-secrets`, `csi`)

`opsdir render --target kubernetes=external-secrets` or `=csi`, only when asked: how the Secrets get their values. Without one, `secrets-required.yaml` says what the operator creates. How a reference is read is the adapter's that owns its scheme (`Adapter.secret_delivery`): `vault://` (hashicorp-vault), `aws-sm://` (aws), `azkv://` (azure), `gcp-sm://` (gcp). A `k8s-secret://` reference to the Secret itself needs nothing; any other scheme is named for the operator. What the record doesn't say is written `UNBOUND:<what>` (a Vault address with no `ciamSecretStore`, an Azure client id with no `ciamIdentityClientId`).

**Secrets synced by the CSI driver.** The driver creates a synced Secret only while a pod mounts its class, and deletes it with the last such pod. A deployment kit that can mount a workload's SecretProviderClasses in its pods says so (`Adapter.mounts_secrets`): opsdir-adapter-ping-devops does, mounting what `mounted_classes` names for this render (empty unless the render's `kubernetes` targets include `csi`: `Services.render_targets`) at `/run/secrets/<class>` (`class_mount`). ForgeOps' pods can't, and cluster gateways are no kit's: their Secrets are kept by sync pods. A sync pod (`sync_deployment`) is a Deployment of `registry.k8s.io/pause:3.10.2` per service account, running as that account with no token mounted, labelled `opsdir.io/secret-sync: <account>` and with its cloud identity's pod labels, restricted (non-root 65535, no privilege escalation, no capabilities, RuntimeDefault seccomp, read-only root), 1m CPU and 4Mi requested, 16Mi limit, mounting each of its classes read-only at `/run/secrets/<class>`, so the Secrets the workloads read by `secretKeyRef` stay there.

The CSI driver must be installed with `syncSecret.enabled=true` (and `enableSecretRotation=true` for rotated values; environment variables need a pod restart to see them). `opsdir/scripts/validate-csi-sync.sh` deploys the sync pods this adapter renders on a throwaway kind cluster with the CSI driver, a real provider (HashiCorp Vault and its CSI provider, its Kubernetes auth bound to the sync pod's service account) and a namespace enforcing restricted pod security, and checks: a product pod created first waits for its Secret and starts once it exists; the sync pod is admitted; the Secret holds the store's value; its service account holds no RBAC; a pod of another account is refused; a changed value reaches the Secret; deleting the sync pod deletes the Secret (running pods keep their values, a restart then waits for a sync pod again).

**Render notes** under `csi` (`notes`, also comments at the top of the files):
- what no local cluster can show, that the environment's own cloud's CSI provider reads its stores as each sync pod's workload identity: an action in the plan (with the checks to run in a non-production cluster of that cloud) until the environment records `ciamConfigurationMet: csi-provider-identity` under an approved change;
- a Secret whose keys come from several secret stores is synced by one class per store, which the CSI driver documents nothing for: fill it from one store, or deliver it with `external-secrets` (which merges them).

Checked by `opsdir/scripts/validate-kubernetes.sh` (kustomize build + kubeconform -strict against Kubernetes 1.36.0's schemas and the CRDs catalog pinned there, External Secrets and CSI included).

### The in-cluster gateway behind the cloud's front

A role an environment runs only on Kubernetes is reached through its cluster's in-cluster gateway when the record has one (`ciamClusterGateway`, the core edge domain, which also says which service names it fronts). The cloud adapter renders the front before it (load balancer, WAF, TLS certificate, DNS record) from the service name's policies; `gateway.py` renders what is behind it, Gateway API standard channel (v1.6.1) plus the implementation's own objects:

- `kubernetes/<gateway namespace>/gateway.yaml` (the binding's `ciamNamespace`, else the first fronted role's): the Gateway (named like the binding), with an HTTP listener (80) for service names whose TLS the front terminates and an HTTPS one (443) presenting the gateway's internal certificate for those the front re-encrypts (the Secret whose keys `tls.crt` and `tls.key` the binding's `ciamWorkloadSecret` names, delivered like a workload's; else `UNBOUND:gateway-tls-secret`); routes allowed from the fronted roles' namespaces only. The Gateway carries `opsdir.io/cluster-role` and `opsdir.io/gateway-role`, so it reads back as the same binding. The cloud's plug (`Services.gateway_plug`) gives the gateway Service's annotations and type and any objects it needs (a target group binding on AWS). A gateway that fronts nothing with declared routes renders nothing.
- `kubernetes/<role namespace>/routes.yaml`: an HTTPRoute per fronted service name (host = its `ciamFqdn`) from the routes its deployment kit declares (`Adapter.routes`: ForgeOps, ping-devops), prefix rewrites as `URLRewrite ReplacePrefixMatch`; a BackendTLSPolicy for a Service that speaks TLS (PingFederate), checked against ConfigMap `<gateway>-backend-ca`, rendered beside it: `ca.crt` holds the PEMs recorded (`ciamCertificatePem`, public material) for the CAs the gateway trusts (`ciamTrustsCertificate`; core `edge.gateways.backend_ca`), or `UNBOUND:<ca>-pem` while one isn't recorded (the planner's action); and cookie stickiness (cookie `route`, the policy's lifetime) when the service name's traffic policy asks for it.

Which implementation runs a gateway is data: the binding's `ciamGatewayImplementation`, else the estate setting `kubernetes-gateway-implementation` (this adapter declares it, default `istio`; `opsdir report settings`). A value no row renders renders nothing. Rows (`gateway.IMPLEMENTATIONS`), each pinned to the release its objects were checked against:

| Implementation | Default | Service name, type, annotations | Trusted X-Forwarded-For | Stickiness |
|---|---|---|---|---|
| `istio` (gateway only, no mesh; 1.31.1), GatewayClass `istio` (Istio's own) | yes | Gateway annotations `gateway.istio.io/name-override`, `networking.istio.io/service-type`; `spec.infrastructure.annotations` (copied to the Service and pods) | `proxy.istio.io/config` `numTrustedProxies: 1` | DestinationRule `httpCookie` per backend Service |
| `envoy-gateway` (v1.9.2), GatewayClass `envoy` rendered | | EnvoyProxy `envoyService` (name, type, annotations) the Gateway names | ClientTrafficPolicy `numTrustedHops: 1` | BackendTrafficPolicy consistent-hash cookie on the HTTPRoute |

The platform team installs the implementation (Istio: the `base` and `istiod` charts, images from the registry it chooses, e.g. Iron Bank or a FIPS distribution, through `global.hub`/`global.tag`; Envoy Gateway: `gateway-helm`) and the Gateway API v1.6.1 standard CRDs. Rendered objects are checked offline with kubeconform against the pinned CRDs catalog.

## What it reads back

### Workloads from manifests (`kubernetes/workloads`)

```bash
kubectl get statefulsets,deployments,daemonsets,cronjobs,services,ingresses,networkpolicies,serviceaccounts,namespaces \
  -A -o yaml > manifests/cluster.yaml        # or rendered Helm/Kustomize output: helm template …, kustomize build …
opsdir import --dry-run kubernetes/workloads manifests/
opsdir import --change CHG-… kubernetes/workloads manifests/
```

Any YAML or JSON file is read, multi-document YAML and `List` output included. Every StatefulSet, Deployment and DaemonSet is one workload (`ciamWorkload`, `cn=<name>,ou=workloads`): intent, the same in every environment. Manifests under `<cloud>/<env>/` of an environment the record holds (`manifests/aws/prod/cluster.yaml`) also give that environment's **workload binding** (`ciamWorkloadBinding`, `cn=<name>,ou=bindings,<environment>`): how it runs the workload on Kubernetes. Manifests anywhere else give the intent only (named in the notices). Objects labelled `app.kubernetes.io/managed-by: opsdir` (this adapter's sync pods) are no workloads.

**Marks** (`names.py`) are annotations on the workload object, else on its pod template (a deployment kit's chart may allow only one; ForgeOps' takes pod annotations only). The kits set them so what they deploy reads back as the record's workloads.

| From | Recorded |
|---|---|
| label `opsdir.io/role` on the object, else that mark, else the pod template's label; else label `app.kubernetes.io/component`, else `app.kubernetes.io/name`, else `roles.json` beside the manifests (`{workload name: role}`) | `ciamTargetRole`: the server role it realizes. Without one the workload is named, not imported |
| the object's kind | `ciamWorkloadKind`: `statefulset`, `deployment`, `daemonset` |
| mark `opsdir.io/cluster-role` | `ciamClusterRole`: the binding role of the cluster it runs in (each environment binds it with a `ciamCluster`), else `cluster` |
| `metadata.namespace` | `ciamNamespace` (else `default`) |
| mark `opsdir.io/workload-role` | `ciamWorkloadRole`: the binding role of its workload binding, else `<name>-workload` |
| `serviceAccountName` | `ciamServiceAccount` |
| its ServiceAccount's cloud identity annotation (`eks.amazonaws.com/role-arn`, `azure.workload.identity/client-id`, `iam.gke.io/gcp-service-account`) | `ciamIdentityRole`: the binding role each environment gives it (mark `opsdir.io/identity-role` on the workload, annotation on the account, else `<role>-identity`); the identity itself is the environment's binding |
| security contexts; the namespace's `pod-security.kubernetes.io/enforce` label | `ciamPodSecurity`: `runAsNonRoot`, `readOnlyRootFilesystem` (every container), `privileged`, `hostNetwork`, `hostPID`, `level=<level>` |
| NetworkPolicies in its namespace whose pod selector selects it, but those labelled `app.kubernetes.io/managed-by: opsdir` (this adapter's own, derived from the record's listeners) | `ciamNetworkPolicy`: `name: policy types` |
| Ingress rules' hosts, and HTTPRoutes' hostnames (a cluster gateway's routes), whose backend is a Service in its namespace selecting it | `ciamIngressHost` |
| env `secretKeyRef`, `envFrom` `secretRef`, secret and projected volumes (containers and init containers) | `ciamSecretName`: the Secrets' names, never their values |
| the file | `ciamRepoPath` |

The workload binding (manifests under `<cloud>/<env>/`):

| From | Recorded |
|---|---|
| the workload role | `ciamBindingRole` |
| the pod template's containers, then its companions' | `ciamContainerImage`: `container=image`, one per container; not those the mark `opsdir.io/derived-containers` names (comma-separated: a kit's log sidecars, derived from the record's log routes); then those the mark `opsdir.io/container-names` names (`<record container>=<pod container>`, comma-separated: a kit's configuration image in an init container, ForgeOps' `idm-custom=custom-vol-init`), under the record's name |
| `spec.replicas` (not for a DaemonSet) | `ciamWorkloadReplicas` |
| the first container's `resources` | `ciamCpuRequest`, `ciamCpuLimit`, `ciamMemoryRequest`, `ciamMemoryLimit` |
| its first volume claim template | `ciamStorageSize`, `ciamStorageClass` |

The Secret keys a workload reads and the secret roles that fill them (`ciamWorkloadSecret: <secret>/<key> <- <role>`) aren't in a manifest: operators record them, and the renderers deliver them.

**Names.** A workload is named by its mark `opsdir.io/workload` (the record's name, when a kit names the object otherwise: ping-devops' `<release>-pingfederate-admin`), else its metadata name, `namespace-name` when two namespaces use the name. A re-import finds it by name and changes nothing (values read in another order included); what the record adds (owners, criticality) is kept.

**Companions.** A StatefulSet, Deployment, DaemonSet or Job marked `opsdir.io/image-of: <workload>/<container>` is part of that workload, as a kit runs it with it (ForgeOps' UIs and amster with AM): no workload of its own; the named container's image (its containers' or init containers') goes into that workload's binding in the same environment as `<container>=<image>`. A mark naming no such workload, or no container with an image, is a notice.

**CronJobs** are jobs (`ciamJob`, `cn=k8s-<name>,ou=jobs`): kind `cron`, the schedule, the command and arguments of the first container (not recorded when they hold secret material: a notice names it), its image (`ciamRuntime`), service account (`ciamRunsAs`), the Secrets it reads by name, and the cluster role that realizes it (`ciamJobRole`, from `opsdir.io/cluster-role`, else `cluster`). The automation domain's planner check then asks the target to bind that cluster.

**Gateways** (`gateway_import.py`): a Gateway API Gateway in manifests under `<cloud>/<env>/` is that environment's cluster gateway binding (`ciamClusterGateway`), named like the Gateway: the implementation whose GatewayClass it names (`istio`, `envoy` -> `envoy-gateway`; another class is named in a notice and no implementation is recorded), its namespace, the cluster role (`opsdir.io/cluster-role`, else `cluster`), the binding role (`opsdir.io/gateway-role`, else `<name>-gateway`), and the private address its Service takes when its infrastructure annotations give Azure's (`service.beta.kubernetes.io/azure-load-balancer-ipv4`: `ciamFrontendIp`). An implementation the record leaves to the estate setting stays left to it while the Gateway runs what the setting names; a gateway new to the record records what it runs. What the record adds (its CA, Secret keys, owners) is kept. A Gateway not under an environment's folder is a notice. HTTPRoutes aren't read as routes (a deployment kit declares its routes); their hostnames are the ingress hosts of the workloads their Services select.

**Secrets.** Secret objects in the manifests are never read; they are counted in the notices. Only the names of the Secrets a workload reads are recorded.

**Notices:** workloads without a role, names that can't be a record name, Secret objects (counted), manifest files not under an environment's folder (intent only), companions whose mark names nothing, Gateways not under an environment's folder or of a class opsdir doesn't render, CronJob commands holding secret material, files that aren't YAML or JSON, manifests with no workloads.

**Round trip** (`reads_back`): the rendered `kubernetes/` files read back by `kubernetes/workloads` under `<cloud>/<env>/` change nothing (the Gateway reads back as its binding; the namespace's own objects carry no workloads). Deployed, the kits' workloads read back as the record through `examples/showcase/tests/kubernetes/test_kubernetes_round_trip.py` (helm template under each kit's own release name, kustomize build): with the marks, nothing is left over.

### Collected live (`opsdir collect`)

With the estate setting `collect-from-kubernetes` on (off until an approved change turns it on), a collection source per namespace: `ciamImporter: kubernetes/workloads` and `ciamSourceRef: k8s://<kubectl context>/<namespace>/workloads` (add `?prefix=<cloud>/<env>/` to record that environment's workload bindings), read with your own kubectl context (core `governance.config_sources`): `kubectl get statefulsets,deployments,daemonsets,cronjobs,services,ingresses,networkpolicies,serviceaccounts -n <namespace> -o json` and `kubectl get namespace <namespace> -o json` (its pod-security label), saved as `<prefix><context>/<namespace>/objects.json` and `namespace.json`. Secrets are never listed; literal env values, `managedFields` and the last-applied annotation are dropped before the export. A live namespace has no `roles.json`, so label the workloads (`opsdir.io/role` or `app.kubernetes.io/component`). The context name must be a plain name (rename an EKS ARN context with `kubectl config rename-context`). Least privilege: a Role with `get`, `list` on those eight resources in the namespace, and a ClusterRole with `get` on `namespaces`.

### What the planner does with it

This adapter has no planner check of its own. The core `compute` domain blocks a move whose target neither runs a workload on Kubernetes (its workload binding) nor has servers of its role, a target workload binding without its cluster, and identity or secret roles nobody binds; a role moving between servers and Kubernetes (what its host baseline carries must move into the image, or back) and a privileged workload are actions. Workload bindings are local to their environment, so the core role check doesn't ask the target to bind them. Clusters themselves (`ciamCluster`: version, add-ons, node pools) are read by the cloud adapters (EKS, AKS, GKE).

## References, vocabulary and settings it owns

| Scheme | Form | Resolved |
|---|---|---|
| `k8s-secret` | `k8s-secret://<namespace>/<secret>/<key>`: one key of a Kubernetes Secret | at run time: `kubectl get secret -n '<namespace>' '<secret>' -o jsonpath='{.data.<key>}' \| base64 -d` (dots in a key escaped for JSONPath). The value never reaches the database or a rendered file |

Configuration management (`opsdir-adapter-ansible`) reads such a reference at run time with the `kubernetes.core.k8s` lookup (kind Secret, the key's data base64-decoded; `ansible_lookup`), with the controller's kubeconfig.

Vocabulary: `ciamGatewayImplementation` (`istio`, `envoy-gateway`). Estate setting: `kubernetes-gateway-implementation` (string, default `istio`). No schema of its own: workloads, workload bindings and clusters are the core `compute` domain's, cluster gateways the `edge` domain's, secret stores (`ciamSecretStore`) the `pki` domain's. No required roles, secret patterns or planner checks. Render targets `external-secrets`, `csi`.

## Known limits

- **Not run against a live cluster.** Manifests as the Kubernetes API documents them (apps/v1, networking.k8s.io/v1); the render is checked offline with kustomize and kubeconform, the CSI sync pods on a local kind cluster only. A deployed run is part of the testing plan (milestone 7.2).
- **Not read yet:** one-off Jobs (only as companions), operators' custom resources (the DS operator's `DirectoryService`, ForgeOps secret agent, external-secrets `ExternalSecret`), sidecars' resource requests and limits (only the first container's), pod disruption budgets, horizontal autoscalers, NetworkPolicy rule details (only the policy and its types), HTTPRoutes as routes (only their hostnames).
- An Ingress or HTTPRoute backend is matched to a workload through a Service's selector in the same namespace; `ExternalName` services and cross-namespace routing aren't followed.
- A Secret filled from several stores under `csi` has no documented driver behaviour (a render note says so); the sync pods' cloud identity is unproven until the environment records `csi-provider-identity`.
- Two gateway implementations are rendered (Istio, Envoy Gateway).

## Tests

- `tests/test_kubernetes.py`: registration through the entry point, resolving a key through the registry, JSONPath escaping.
- `tests/test_kubernetes_render.py`: applies only where workloads run on Kubernetes; the namespace folder and kustomization; service accounts with the provider's identity; network policies from listeners (pods by label, servers by subnet; a kit's container ports replacing the product's); the secrets required and what delivers them; External Secrets and CSI when asked; sync pods for the workloads no kit mounts, none for a kit that mounts, the identity action until the environment records it, a Secret from two stores named; names; the whole render valid for kustomize and kubeconform (marker `kubernetes`).
- `tests/test_kubernetes_workloads.py`: a StatefulSet with its role, cluster, workload role, identity, pod security (and namespace level), network policy, ingress host and secret names; manifests under an environment's folder giving its workload binding and others the intent only; an environment folder counting only when the record holds it; roles from `roles.json`, a workload without one named; a CronJob as a job the cluster realizes; Secret values never reaching the record; a re-import changing nothing and keeping an owner; names across namespaces and the helpers; a namespace collected live (trimmed) importing as its saved manifests do; Gateways as the environment's cluster gateways, one left to the estate setting staying so; an HTTPRoute's hostnames reaching the workload its Service selects; opsdir's own network policies not recorded again; a kit's marks on pod templates naming the workload, folding its companions and dropping derived containers.
- `tests/test_kubernetes_gateway.py`: no gateway, no objects; an Istio gateway behind the cloud's front by default; routes, backend TLS and stickiness in the role's namespace; the backend CA bundle from the PEMs recorded; Envoy Gateway by the binding or the estate setting; a rendered gateway reading back as the same binding; the gateway render valid for kustomize and kubeconform (marker `kubernetes`).

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-kubernetes/tests` (unit tests); `-m kubernetes` for the tool-checked ones (`opsdir/scripts/fetch-tools.sh` first).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `kubernetes`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

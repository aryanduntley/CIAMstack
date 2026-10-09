# opsdir-adapter-forgeops

opsdir adapter for ForgeOps, Ping Identity's deployment kit for PingAM, PingIDM, PingDS and PingGateway on Kubernetes. For the workloads an environment runs with it, it renders Helm values for ForgeOps' charts and a Kustomize overlay in ForgeOps' own layout. Both come from the record's workloads and their workload bindings, for one pinned ForgeOps release: **2026.3.1** (commit `8c79cbbac7ca72e579e7ab8391284785acad3690`, `release.py`).

**Applies to** environments that run, on Kubernetes (a workload binding), a workload whose role ForgeOps deploys:
- `am`, `idm` and `ig` by role;
- `ds` by the workload's name, `ds-idrepo` or `ds-cts`. These are ForgeOps' own names, which the kubernetes importer gives workloads read from ForgeOps manifests.

The adapter is kind `platform`, so an environment that declares a stack renders it only when the stack names it.

**Depends on** `opsdir` and `opsdir-adapter-kubernetes`. That adapter renders what surrounds the workloads: the namespace, service accounts with their cloud identities, network policies and Secret delivery. Render both.

## What it renders

Per namespace of those workloads. Each component comes with the ones it needs:
- amster with AM;
- ds-set-passwords with an in-cluster DS;
- keystore-create with AM or IDM;
- the platform UIs (admin, end-user, login) with AM and IDM both.

Components the environment doesn't run are disabled or left out.

| Target | Files | Use |
|---|---|---|
| `helm` | `forgeops/helm/<namespace>/identity-platform-values.yaml`, `ping-gateway-values.yaml` | `helm upgrade --install <chart> <ForgeOps 2026.3.1 checkout>/charts/<chart> --namespace <namespace> -f <file>` |
| `kustomize` | `forgeops/kustomize/overlay/<namespace>/`: its kustomization, `base/` (platform-config) and one folder per component over `../../../base/<component>` | copy the folder into the checkout's `kustomize/overlay/`, then `kustomize build` |

Both targets are on by default, as `forgeops env` writes both. Pick one with `opsdir render --target forgeops=helm` or `=kustomize`.

### From the record

- **Images** come from the workload bindings' `ciamContainerImage` (`container=image`).
  - The image is matched by the component's container names: `openam`/`am`, `amster`, `openidm`/`idm`, `ds`, `ig`, `admin-ui`, `end-user-ui`, `login-ui`. Failing that, a component's own workload's only image is used.
  - keystore-create's Java image is AM's (IDM's without AM).
  - ForgeOps' public images are for development and testing only, so an image the record doesn't name is written `UNBOUND:forgeops-<component>-image`.
  - Helm takes a digest as repository `<name>@sha256`, tag `<hex>`, which the chart's `<repository>:<tag>` turns back into the reference. Kustomize takes it as `digest`.
  - The tooling images the bases name (`am-custom`, `idm-custom`: busybox; `kubectl`) are set to the chart's defaults at the release.
- **Replicas, CPU and memory** come from the binding (`ciamWorkloadReplicas`, `ciamCpuRequest`/`Limit`, `ciamMemoryRequest`/`Limit`), as do **DS storage** (`ciamStorageSize`, `ciamStorageClass`). What the record doesn't hold stays the chart's or base's default.
- **Pod labels**: `opsdir.io/role: <role>`, which the kubernetes adapter's network policies select, plus the pod labels the cloud's workload identity needs (AKS: `azure.workload.identity/use`).
  - Kustomize puts them on pod templates only, never selectors.
  - The chart puts its pod labels in its selectors, so a release first installed without them can't be upgraded to them in place.
  - Components without a workload of their own carry the role they come with, so the namespace's default deny of ingress lets in what reaches them: the UIs `am` (served through the ingress as AM is), ds-set-passwords `ds` (it reaches DS as its peers do). amster and keystore-create only call out and carry none.
- **Service account**: the workloads' (`ciamServiceAccount`, else the workload's name), which the kubernetes adapter creates (`create: false`).
  - The identity-platform chart runs every pod as one account, so the Helm values use the first workload's.
  - The overlay sets each workload's.
- **Ingress hosts** come from the workloads' `ciamIngressHost`: AM's and IDM's for the platform, IG's for the gateway. Otherwise they are written `UNBOUND:forgeops-ingress-host` / `UNBOUND:ig-ingress-host`.
- **DS on servers**: when a DS store doesn't run in the cluster, what reaches it is pointed at the environment's `ds-ldaps-service` (`fqdn:port`):
  - AM's CTS and user stores: in Helm `platform.external_ds`; in Kustomize, platform-config `AM_STORES_*_SERVERS`;
  - IDM's repository and user store (ds-idrepo): the variables IDM reads its boot properties `openidm.repo.host`/`port` and `userstore.host`/`port` from, `OPENIDM_REPO_HOST`, `OPENIDM_REPO_PORT`, `USERSTORE_HOST`, `USERSTORE_PORT` (Helm `idm.env`; Kustomize, a patch of the `openidm` container), the first of its servers;
  - with no DS in the cluster, ForgeOps' self-signed DS certificates are off (Helm `platform.ds_certs.enabled: false`), and AM and IDM trust the CA in `ds-ssl-keypair` `ca.crt`, which the record delivers: the CA that signed the DS servers' certificates.

### Secrets

The chart and the bases run in ForgeOps' secret-generator layout with no generator. Helm sets `disable_secret_agent_config`, and `secrets_enabled` with `base_generate` and no `secrets`, which is how ForgeOps generates its Kustomize bases. So ForgeOps writes none of the Secrets the record delivers, and every pod reads the same Secret names under both targets.

ForgeOps makes these itself:
- the AM/IDM keystore (the keystore-create job, `keystore_create.force`);
- under Helm, amster's SSH key pair (the ssh-keygen job) and, with DS in the cluster, the DS certificates (cert-manager).

Everything else comes from the record (`ciamWorkloadSecret`, delivered by the kubernetes adapter's `external-secrets` target) or from the operator. Its `csi` target doesn't suit ForgeOps: a SecretProviderClass syncs its Secrets only while a pod mounts it, and ForgeOps' pods don't (the identity-platform chart takes no extra volumes). Those Secrets, by name and key (`release.py`, `KIT_SECRETS`):
- `am-env-secrets`
- `ds-env-secrets`
- `amster-env-secrets`
- `idm-env-secrets`
- `ds-passwords`
- `keystore-create`
- under Kustomize also `amster`, `ds-ssl-keypair` and `ds-master-keypair`
- with DS on servers only, `ds-ssl-keypair` `ca.crt` (the servers' CA), under both targets

## Routes behind a cluster gateway

ForgeOps' own Ingresses use the `nginx` class and nginx annotations, a controller the Kubernetes project has retired. When the record has a cluster gateway (`ciamClusterGateway`, the core edge domain) in front of the roles a chart serves, that chart's Ingresses are off: Helm `platform.ingress.enabled: false` (identity-platform for AM and IDM, ping-gateway for IG), and the Kustomize overlay deletes them (`$patch: delete`). Their paths are declared as routes (`release.ROUTES`, `routes.py`), which opsdir-adapter-kubernetes renders as Gateway API HTTPRoutes:

| Component | Path | Service:port | Hosts |
|---|---|---|---|
| am | `/am` | am:80 | AM's service names |
| login-ui, admin-ui, end-user-ui | `/am/XUI`, `/platform`, `/enduser` | their own :8080 | AM's |
| idm | `/openidm`, `/upload`, `/export`, `/admin`, `/openicf` | idm:80 | IDM's and AM's (the platform UIs call both on one host) |
| ig | `/ig`, `/igadmin` (prefix replaced by `/`, as the release's `rewrite-target /$2` does) | ig:80, ig:8085 | IG's |

## Listeners

The release's pods' container ports (`release.py`, `POD_PORTS`), declared as listeners `on="kubernetes"` for each role the environment runs with ForgeOps: AM, IDM and IG HTTP on 8080 (behind the ingress); DS LDAP 1389 and LDAPS 1636 (from AM, IDM and its peers), administration 4444, replication 8989. The kubernetes adapter's network policies admit these to the role's pods instead of the products' own ports on servers (PingAM's 8443), and the firewall checks leave them out.

## Planner check

`check_forgeops` adds actions on the target environment:
- every Secret key ForgeOps' pods read that no workload in the namespace records and ForgeOps doesn't make;
- ForgeOps workloads of one namespace that name different service accounts (one per Helm release);
- a ds workload ForgeOps can't place (not named `ds-idrepo` or `ds-cts`);
- one DS store in the cluster and the other on servers while AM or IDM runs there. This layout isn't supported: ForgeOps then makes the DS certificates, so AM's and IDM's truststore holds only ForgeOps' CA and not the CA that signed the DS servers' certificates. Run both stores in the cluster or both on servers;
- a component running a ForgeOps public image.

## The ForgeOps source

`scripts/fetch-forgeops.sh` downloads the pinned release into `tools/forgeops/2026.3.1/` (gitignored). It uses GitHub's archive of the commit, checked against the SHA-256 pinned in `release.py`. The tests marked `kubernetes` use it with the tools from `opsdir/scripts/fetch-tools.sh`. They render the values and the overlay, then run `helm template` on both charts and `kustomize build` against the release's bases, and check everything with kubeconform (`opsdir/scripts/validate-kubernetes.sh`).

Tests: `tests/test_forgeops.py`.

Not done here:
- AM/IDM keystore content from the record's keys; the keystore-create job generates it.
- Product configuration packaged as ForgeOps config profiles (milestone 5.9).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `forgeops`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

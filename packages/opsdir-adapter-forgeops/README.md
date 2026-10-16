# opsdir-adapter-forgeops

opsdir adapter for ForgeOps, Ping Identity's deployment kit for PingAM, PingIDM, PingDS and PingGateway on Kubernetes. For the workloads an environment runs with it, it renders Helm values for ForgeOps' charts and a Kustomize overlay in ForgeOps' own layout and, on request, the products' configuration as ForgeOps config profiles. All of it comes from the record's workloads and their workload bindings, for one pinned ForgeOps release: **2026.3.2** (commit `3b61b9e0a18b65c4e370dc2512f133296990b363`, both charts at version 1.0.0; `release.py`).

**Applies to** environments that run, on Kubernetes (a workload binding), a workload whose `ciamTargetRole` ForgeOps deploys:
- `am`, `idm` and `ig` by role;
- `ds` by the workload's name, `ds-idrepo` or `ds-cts`. These are ForgeOps' own names, the ones its StatefulSets carry, so the kubernetes importer gives them to workloads read from ForgeOps manifests.

The adapter is kind `platform`. An environment that declares a stack renders it only when the stack names it (`forgeops`); one that declares none renders it when it runs such a workload.

**Depends on** `opsdir` and `opsdir-adapter-kubernetes`. The products it deploys are named by product (PingAM, PingIDM, PingGateway, PingDS: `release.PRODUCT_COMPONENTS`, `COMPANION_PRODUCTS`, `CHART_PRODUCTS`, `KEYSTORE_PRODUCTS`), and their roles (server roles, AM's and IDM's keystore, DS's service name) come from their installed adapters' declarations (`Adapter.roles`, `opsdir.core.environment.roles_for`), never from an import: install those adapters too. That adapter renders what surrounds the workloads: the namespace, service accounts with their cloud identities, network policies, Secret delivery and the HTTPRoutes of a cluster gateway; this one uses its helpers for placements, images, replicas, resources, storage, pod labels, marks and listeners (`kits.py`). Render both. Deploying the output needs a ForgeOps 2026.3.2 checkout, and Helm or Kustomize; the `kubernetes` tests also need helm, kustomize and kubeconform (`opsdir/scripts/fetch-tools.sh`).

## What it renders

Per namespace of those workloads (`components.py`, `placements`). Each component comes with the ones it needs:
- amster with AM;
- ds-set-passwords with an in-cluster DS store;
- keystore-create with AM or IDM;
- the platform UIs (admin-ui, end-user-ui, login-ui) with AM and IDM both;
- idm-admin-ui (IDM's legacy administration UI as a pod of its own, new in ForgeOps 2026.3.2; PingIDM 8.1 no longer bundles it) only when the record's IDM version is 8.1 or later and a workload binding names an `idm-admin-ui` image (the chart's default: off).

Components the environment doesn't run are disabled (`enabled: false` in the values) or left out of the overlay.

| Target | Files | Use |
|---|---|---|
| `helm` | `forgeops/helm/<namespace>/identity-platform-values.yaml` (AM, amster, IDM, DS, the UIs, the jobs), `ping-gateway-values.yaml` (IG); a file only for a chart with a component on | `helm upgrade --install <chart> <ForgeOps 2026.3.2 checkout>/charts/<chart> --namespace <namespace> -f <file>` (each file's header says so) |
| `kustomize` | `forgeops/kustomize/overlay/<namespace>/`: its `kustomization.yaml` (namespace, the tooling images), `base/` (a patch of `platform-config`) and one folder per component over `../../../base/<component>` | copy the folder into the checkout's `kustomize/overlay/`, then `kustomize build`. ForgeOps deprecates Kustomize deployments from 2026.3.2 (removal expected a year later): prefer `helm`. idm-admin-ui is the chart's only, not in the bases: the kustomization's header names it as not rendered. With the record's keystore (below) keystore-create is left out |
| `config-profiles` (on request) | `forgeops/config-profiles/<namespace>/<component>/` and a `README.md` per namespace | below |

`helm` and `kustomize` are on by default, as `forgeops env` writes both. Pick with `opsdir render --target forgeops=helm`, `=kustomize`, or add `config-profiles`.

Helm merges the values over the chart's own and the overlay patches the bases, so what the record doesn't hold stays the chart's or base's default; images are the exception (below).

### From the record

| From the record | Rendered as |
|---|---|
| the workload bindings' `ciamContainerImage` (`container=image`), by the component's container names: `openam`/`am`, `amster`, `openidm`/`idm`, `ds-idrepo`/`ds-cts`/`ds`, `ig`, `admin-ui`, `end-user-ui`, `login-ui`, `idm-admin-ui` (its own workload's binding first); else its own workload's only image | Helm `<component>.image` `{repository, tag}` (a digest as repository `<name>@sha256`, tag `<hex>`, which the chart's `<repository>:<tag>` turns back into the reference); Kustomize `images` (`newName`, `newTag`, `digest`). keystore-create's Java image (`initImage`) is AM's (IDM's without AM); ds-set-passwords runs ds-idrepo's |
| no image named | `UNBOUND:forgeops-<component>-image`: ForgeOps' public images (`us-docker.pkg.dev/forgeops-public/`) are for development and testing only, so none is used by default |
| the tooling images the bases name (`am-custom`, `idm-custom`, `kubectl`) | the chart's defaults at the release (`busybox:musl`, `…/images/kubectl:1.36.1`) in the overlay's `images` |
| `ciamWorkloadReplicas`, `ciamCpuRequest`/`Limit`, `ciamMemoryRequest`/`Limit` | `replicaCount` and `resources` (not on jobs); in the overlay a patch of the workload object |
| DS `ciamStorageSize`, `ciamStorageClass` | Helm `volumeClaimSpec`; Kustomize a JSON patch of `/spec/volumeClaimTemplates/0/spec` |
| the workload's role, its identity binding | pod labels `opsdir.io/role: <role>` (what the kubernetes adapter's network policies select) and those the cloud's workload identity needs (AKS: `azure.workload.identity/use`); Kustomize puts them on pod templates only (`includeSelectors: false`) |
| the workload's cluster role, workload role, identity role and name | marks so the deployment reads back as the record (opsdir-adapter-kubernetes): `podAnnotations` in Helm, a patch of the workload object's annotations in the overlay. The charts take no workload annotations and pod labels are in their selectors, so the marks are pod annotations: adding them rolls the pods once |
| a companion's image (amster and the UIs, which have no workload of their own, `release.COMPANION_IMAGES`) | `opsdir.io/image-of: <workload>/<container>`: the workload whose binding keeps their image, so the importer folds it back there. keystore-create and ds-set-passwords borrow an image and carry none |
| a component without a workload | the role it comes with as `opsdir.io/role`, so the namespace's default deny of ingress lets in what reaches it: the UIs `am`, idm-admin-ui `idm`, ds-set-passwords `ds`. amster and keystore-create only call out and carry none |
| `ciamServiceAccount` (else the workload's name) | Helm `serviceAccount: {create: false, name}`: the chart runs every pod as one account, so the first placed workload's; the overlay sets each workload's `serviceAccountName`. The kubernetes adapter creates them |
| `ciamIngressHost` of AM and IDM; of IG | Helm `platform.ingress.hosts`; overlay: each Ingress's host and TLS host, and `platform-config` `FQDN`/`AM_SERVER_FQDN`. None recorded: `UNBOUND:forgeops-ingress-host` / `UNBOUND:ig-ingress-host` |
| a DS store not in the cluster: the environment's `ds-ldaps-service` (`fqdn:port`, its `ciamPort`, else 1636; none: `UNBOUND:ds-ldaps-service`) | AM's CTS and user stores: Helm `platform.external_ds` (`cts_hosts`, `idrepo_hosts`), Kustomize `platform-config` `AM_STORES_CTS_SERVERS`/`AM_STORES_USER_SERVERS`. IDM's repository and user store (ds-idrepo), the first of its servers: `OPENIDM_REPO_HOST`, `OPENIDM_REPO_PORT`, `USERSTORE_HOST`, `USERSTORE_PORT` (the variables IDM reads `openidm.repo.host`/`port` and `userstore.host`/`port` from; Helm `idm.env`, Kustomize a patch of the `openidm` container). A store in the cluster is addressed as `<store>-<i>.<store>:1636` per replica |
| no DS store in the cluster | Helm `platform.ds_certs.enabled: false` (no self-signed DS certificates): AM and IDM trust the CA in `ds-ssl-keypair` `ca.crt`, which the record delivers: the CA that signed the DS servers' certificates |

### Secrets

The chart and the bases run in ForgeOps' secret-generator layout with no generator. Helm sets `disable_secret_agent_config`, and `secrets_enabled` with `base_generate` and no `secrets`, which is how ForgeOps generates its Kustomize bases. So ForgeOps writes none of the Secrets the record delivers, and every pod reads the same Secret names under both targets.

ForgeOps makes these itself:
- the AM/IDM keystore (`keystore`; the keystore-create job, `keystore_create.force`), unless the record delivers it (below);
- under Helm, amster's SSH key pair (`amster`, the ssh-keygen job, `ssh_keygen.enabled` with AM) and, with DS in the cluster, the DS certificates (`ds-ssl-keypair`, `ds-master-keypair`: cert-manager, `platform.ds_certs`).

Everything else comes from the record (`ciamWorkloadSecret`, delivered by the kubernetes adapter) or from the operator. Those Secrets, by name and key (`release.py`, `KIT_SECRETS`):

| Secret | Keys | Read by |
|---|---|---|
| `am-env-secrets` | `AM_AUTHENTICATION_SHARED_SECRET`, `AM_ENCRYPTION_KEY`, `AM_OIDC_CLIENT_SUBJECT_IDENTIFIER_HASH_SALT`, `AM_PASSWORDS_AMADMIN_CLEAR`, `AM_SELFSERVICE_LEGACY_CONFIRMATION_EMAIL_LINK_SIGNING_KEY`, `AM_SESSION_STATELESS_ENCRYPTION_KEY`, `AM_SESSION_STATELESS_SIGNING_KEY` | am |
| `ds-env-secrets` | `AM_STORES_APPLICATION_PASSWORD`, `AM_STORES_CTS_PASSWORD`, `AM_STORES_USER_PASSWORD` | am, ds-set-passwords |
| `amster-env-secrets` | `IDM_PROVISIONING_CLIENT_SECRET`, `IDM_RS_CLIENT_SECRET` | amster, idm |
| `idm-env-secrets` | `OPENIDM_ADMIN_PASSWORD` | idm |
| `ds-passwords` | `dirmanager.pw`, `monitor.pw` | idm, ds-idrepo, ds-cts, ds-set-passwords, keystore-create |
| `keystore-create` | `KEYSTORE_PASSWORD` | am, idm, keystore-create |
| `amster` (Kustomize only: Helm makes it) | `ssh-privatekey`, `ssh-publickey` | am, amster |
| `ds-ssl-keypair`, `ds-master-keypair` (Kustomize with DS in the cluster: Helm makes them) | `ca.crt`, `tls.crt`, `tls.key` | am, idm, the DS stores |
| `ds-ssl-keypair` with DS on servers only, under both targets | `ca.crt` (the servers' CA) | am, idm |

With the kubernetes adapter's `external-secrets` target (Ping's recommendation for ForgeOps: External Secrets Operator or Vault) nothing more is needed. With its `csi` target, a SecretProviderClass syncs its Secrets only while a pod mounts it, and ForgeOps' pods can't (the identity-platform chart hard-codes its pods' volumes, ping-gateway's has none, and no release adds a hook): this adapter declares no `mounts_secrets`, so the kubernetes adapter renders a sync pod per service account (`kubernetes/<namespace>/secretsync.yaml`) that mounts the classes and keeps the Secrets, under Helm and Kustomize alike. That pattern is validated on a local cluster (`opsdir/scripts/validate-csi-sync.sh`); in the environment's own cloud it stays an action in the plan until the environment records `ciamConfigurationMet: csi-provider-identity` (the kubernetes adapter's README).

### The keystore from the record

By default the release's keystore-create job generates AM's and IDM's keystore (the `keystore` Secret). To run the record's keystore instead, map it on a workload in the namespace: `ciamWorkloadSecret: keystore/keystore.jceks <- <role>`, for example the `am-keystore` role the pingam adapter requires. The kubernetes adapter then delivers it from the record's reference, and nothing generates one. The Helm values set `keystore_create.force: false`, which turns the job off while AM and IDM still mount `keystore` and `keystore-create`. The Kustomize overlay leaves the `keystore-create` component out. The keystore must hold the aliases the job would make (the chart's `keystore_create.config.keytoolAliases`), with `KEYSTORE_PASSWORD` in `keystore-create`. Apply the kubernetes adapter's Secrets before the release, so the pods find them.

### Config profiles (target `config-profiles`, on request)

`opsdir render <env> --target forgeops=helm,kustomize,config-profiles` also renders the products' configuration the way ForgeOps builds it into images (`profiles.py`). Each product adapter declares which of its files are its product's own instance files. The render hands those trees to this adapter, which writes one build context per component under `forgeops/config-profiles/<namespace>/<component>/`, in the release's `docker/<component>/` layout: `config-profiles/opsdir/` and the `Dockerfile` that builds it. A component gets one only when it is on and its product has files. Your CI builds and pushes each; the values and the overlay then run them.

| Component | Profile | Image |
|---|---|---|
| `idm` | PingIDM's `conf/` (and captured `resolver/`) | a busybox configuration image with the profile under `/config/`; the chart's `idm_custom` init container copies it over IDM's configuration on first start. The record names it as the container `idm-custom` on IDM's workload binding (`ciamContainerImage idm-custom=<ref>`), else `UNBOUND:forgeops-idm-custom-image`: Helm `idm_custom.image`, the overlay's `idm-custom` image. IDM's pods then carry `opsdir.io/container-names: idm-custom=custom-vol-init`, so the init container's image reads back under that name |
| `amster` | PingAM's Amster entities (`config/global/`, `config/realms/<realm>/...`) | the amster image rebuilt `FROM ${BASE_IMAGE}` with the profile under `/opt/amster`; the amster job imports `/opt/amster/config` |
| `ig` | PingGateway's `config/config.json`, `admin.json` and `config/routes/` | the PingGateway image rebuilt `FROM ${BASE_IMAGE}` with the profile under `${IG_INSTANCE_DIR}` (the chart's `ig_custom` image isn't wired into its templates) |

The derived images' Dockerfile header names the image the release runs, to pass as `--build-arg BASE_IMAGE`. AM's own file-based configuration stays its image's: the record's AM configuration is Amster's.

**DS** has no config profile: ForgeOps builds one DS image (for `ds-idrepo` and `ds-cts`) from its `docker/ds/` folder, which takes custom schema (`config/schema/*.ldif`) and LDAP entries per backend (`ldif-ext/<backend>/*.ldif`). From PingDS's profile (its `ldap/schema.ldif` and `ldap/dit.ldif`), a namespace where ForgeOps runs DS gets `forgeops/config-profiles/<namespace>/ds/` (`ds_profile.py`), when the record gives it schema or entries:

| File | Holds |
|---|---|
| `config/schema/90-opsdir.ldif` | the record's schema definitions as one `cn=schema` entry, DS's schema-file form (as ForgeOps' sample `config/schema/99-ext.ldif`); named to load after DS's own files and before `99-user.ldif`, where DS writes schema changes made over LDAP. Definitions PingDS ships are already left out of `ldap/schema.ldif` (`opsdir-base-ds`) |
| `ldif-ext/<backend>/opsdir.ldif` | the record's tree entries below the base DN of the ForgeOps backend serving them: `am-config` (`ou=am-config`), `identities` (`ou=identities`), `tokens` (`ou=tokens`), `idm-repo` (`dc=openidm,dc=forgerock,dc=io`). The base entry itself is the setup profile's |
| `append-ldif-ext.sh` | the build step appending each `ldif-ext/<backend>/opsdir.ldif` to the `base-entries.ldif` template that backend's setup profile imports, as the release's `ds-setup.sh` does, with two differences, both tried on ForgeOps' public DS image (PingDS 8.1.2): the template is the profile folder's highest version holding one, chosen in the image (`ds-setup.sh` names `IDM/repo/7.3`, which the 8.1 idm-repo profile no longer reads: its entries are never imported), and an entry whose DN the template already creates (such as `ou=people,ou=identities`) is left out (a duplicate fails the profile's import, so the pod's setup). `release.DS_BACKENDS`: each backend's profile folder and what its templates' `&{...}` parameter stands for |
| `Dockerfile` | `FROM ${BASE_IMAGE}`, the DS image built from ForgeOps' `docker/ds` (its header names the one the release runs): the schema into `/opt/opendj/custom-schema/`, then `append-ldif-ext.sh` |

Build and push it as the image the record names for `ds-idrepo` and `ds-cts`; or copy `config/schema/` and `ldif-ext/` into a ForgeOps checkout's `docker/ds/` and run `forgeops build ds`. A pod loads both only when it sets up an empty volume: on a running deployment, apply the PingDS render's `ldap/schema.ldif` and `ldap/dit.ldif` online.

What ForgeOps' DS can't take from the record reaches its owners as render notes (`ds_profile.ds_notes`, area `ForgeOps`, severity action, in `NOTES.md`/`NOTES.json`, and as comments in the namespace's DS `Dockerfile` when it is rendered), wherever ForgeOps runs DS, whatever the target:
- each record backend whose base DN is under none of ForgeOps' four: its entries are in no image (create the backend on the pods once they run and add its entries online, or give it a base DN ForgeOps serves);
- the record's DS configuration and ACIs (indexes, password policies, connection handlers, log publishers, replication, ACIs: the PingDS render's `ds/dsconfig.batch` and `ds/acis.ldif`), to apply online once the pods run: the identity-platform chart mounts its own setup scripts over the image's (`ds-runtime-scripts`, `ds-idrepo-runtime-scripts`, `ds-cts-runtime-scripts`), so no image can carry them. It names each record backend at a ForgeOps base DN under another name (the batch's index lines name the record's: ForgeOps' are `cfgStore`, `amIdentityStore`, `amCts`, `idmRepo`).

No profile holds a secret. Where a product renders a secret reference, the profile holds `&{opsdir.<role>}` (the role's dashes as dots). IDM, PingGateway and Amster fill that token from the environment variable `OPSDIR_<ROLE>`. You map the variable on the workload like any other Secret key: `ciamWorkloadSecret: <secret>/OPSDIR_<ROLE> <- <role>`. The values (`<component>.env`) and the overlay (a patch of the main container) then add it to the AM, IDM and PingGateway containers as `secretKeyRef`. The amster job reads `amster-env-secrets` whole, so amster's variables go in that Secret. Each namespace's `README.md` lists every token, its variable and role, and whether the record maps it.

### Routes behind a cluster gateway

ForgeOps' own Ingresses use the `nginx` class and nginx annotations, a controller the Kubernetes project has retired. When the record has a cluster gateway (`ciamClusterGateway`, the core edge domain) in front of a role a chart serves (identity-platform: `am`, `idm`; ping-gateway: `ig`), that chart's Ingresses are off: Helm `platform.ingress.enabled: false`, and the Kustomize overlay deletes them (`$patch: delete`). Their paths are declared as routes (`release.ROUTES`, `routes.py`), which opsdir-adapter-kubernetes renders as Gateway API HTTPRoutes:

| Component | Path | Service:port | Hosts |
|---|---|---|---|
| am | `/am` | am:80 | AM's service names |
| login-ui, admin-ui, end-user-ui | `/am/XUI`, `/platform`, `/enduser` | their own :8080 | AM's |
| idm | `/openidm`, `/upload`, `/export`, `/admin`, `/openicf` | idm:80 | IDM's and AM's (the platform UIs call both on one host) |
| idm-admin-ui (when on) | `/admin` (taken from idm), `/api` | idm-admin-ui:8080 | IDM's and AM's |
| ig | `/ig`, `/igadmin` (prefix replaced by `/`, as the release's `rewrite-target /$2` does) | ig:80, ig:8085 | IG's |

### Listeners

The release's pods' container ports (`release.py`, `POD_PORTS`), declared as listeners `on="kubernetes"` for each role the environment runs with ForgeOps: AM, IDM and IG HTTP on 8080 (behind the ingress, from clients); DS LDAP 1389 and LDAPS 1636 (from AM, IDM and its peers), administration 4444, replication 8989 (peers). The kubernetes adapter's network policies admit these to the role's pods instead of the products' own ports on servers (PingAM's 8443), and the firewall checks leave them out.

### Logs

The pods' container output (JSON lines among text lines), declared as log sources `on="kubernetes"` (`logs.py`), which log routes (`ciamLogKind`) pick lines from:

| Role | Lines no rule classifies | JSON lines, by field | Audit events need |
|---|---|---|---|
| am | `debug` (AM writes its debug log there) | `eventName` starting `AM-ACCESS`: access; any other `eventName`: audit | AM's JSONStdout audit event handler (audit logging service) |
| idm | `error` | `eventName`: audit | `openidm.audit.handler.stdout.enabled=true` (JsonStdoutAuditEventHandler) |
| ig | `error` | `topic: access`: access; `source: audit`: audit | a JsonStdoutAuditEventHandler in the routes' audit service |

DS isn't declared: its documentation states no default for container output.

## Reading it back

This adapter has no importer of its own. The rendered (or `helm template` / `kustomize build`) manifests read back through opsdir-adapter-kubernetes's importer: the marks put the workloads back under their records, `opsdir.io/image-of` folds the companions' images into the binding that keeps them, and `opsdir.io/container-names` names IDM's configuration image.

## Planner check

`check_forgeops` (area `ForgeOps`, `checks.py`) adds actions on the target environment, owned by the environment's responsible team:
- every Secret key ForgeOps' pods read that no workload in the namespace records and ForgeOps doesn't make under both targets (the action names what makes it under one target, and asks for `ciamWorkloadSecret <secret>/<key> <- <role>`);
- ForgeOps workloads of one namespace that name different service accounts (the identity-platform chart runs one per release: the values use the first, the overlay sets each);
- a ds workload ForgeOps can't place (not named `ds-idrepo` or `ds-cts`): it isn't deployed;
- one DS store in the cluster and the other on servers while AM or IDM runs there. This layout isn't supported: ForgeOps then makes the DS certificates, so AM's and IDM's truststore holds only ForgeOps' CA and not the CA that signed the DS servers' certificates. Run both stores in the cluster or both on servers;
- a component running a ForgeOps public image;
- a config profile's secret variable (`OPSDIR_<ROLE>`) the record doesn't deliver to its component, when the target renders config profiles;
- the keystore-create job generating the keystore while the environment binds `am-keystore` or `idm-keystore` and no workload maps `keystore/keystore.jceks`.

With none of these it says so (every Secret recorded or made, its own images). It adds no required roles, vocabulary, schema, reference schemes or secret patterns; the product adapters (pingam, pingidm, pingds, pinggateway) say which roles must be bound.

## The ForgeOps source

`scripts/fetch-forgeops.sh` downloads the pinned release into `tools/forgeops/2026.3.2/` at the repository root (gitignored). It uses GitHub's archive of the commit, checked against the SHA-256 pinned in `release.py` (a test keeps the script's pins equal to `release.py`'s). Idempotent. The tests marked `kubernetes` use it with the tools from `opsdir/scripts/fetch-tools.sh`.

## Known limits

- **Not run against a live cluster.** The values and the overlay are built with `helm template` and `kustomize build` against the pinned release and checked by kubeconform; deploying them is part of the testing plan (milestone 7.2). The CSI sync pods are validated on a local cluster only (above).
- **One release.** Everything is read from ForgeOps 2026.3.2's charts and bases; another release needs `release.py` updated. Kustomize deployments are deprecated by ForgeOps from that release.
- **One service account per Helm release**, and pod labels in the chart's selectors: a release first installed without the `opsdir.io/role` label can't be upgraded to it in place.
- **DS split between the cluster and servers** isn't supported (the planner names it).
- **DS image inputs tried locally, not in a cluster** (milestone 7.2). A build of the rendered `ds/` folder on ForgeOps' public DS image (`:latest`, PingDS 8.1.2) ran ForgeOps' own `ds-idrepo` and `ds-cts` setup scripts offline: the schema file loaded and every backend imported the record's entries (a duplicate of a template entry left out). Not tried: a pod's first start in a cluster (the chart's mounted scripts and entrypoint), other PingDS versions. Found there: a custom schema definition with a shipped definition's OID and name only warns (DS keeps its own), but one with a shipped definition's name and another OID stops DS's tools and server from starting; ForgeOps 2026.3.2's own `ds-setup.sh` appends `ldif-ext/idm-repo/` to a template PingDS 8.1's idm-repo profile no longer reads.
- **DS custom schema and entries apply at first setup only** (an empty volume), as ForgeOps documents; the record's DS configuration and ACIs are applied online (render notes), since the chart replaces the image's setup scripts.
- **AM's file-based configuration** isn't profiled: the record's AM configuration goes through Amster.
- idm-admin-ui isn't rendered by the Kustomize target (not in the bases).
- **Product roles come from the installed product adapters**: a product whose adapter isn't installed has no server roles here, so ForgeOps places none of its workloads (and DS on servers is `UNBOUND:PingDS-service` without the PingDS adapter). The container ports, routes and log sources (`POD_PORTS`, `ROUTES`, `logs.py`) still name the products' server roles (`am`, `idm`, `ig`, `ds`).

## Tests

`tests/test_forgeops.py`: it renders only where ForgeOps runs workloads; components come with the ones they serve; images from the record, never ForgeOps' public ones (`UNBOUND` otherwise; digests); the identity-platform and ping-gateway values (service account, Secrets layout, ingress hosts, DS on servers, marks); DS storage from the record; the Kustomize overlay in ForgeOps' layout; the pods' ports and the companions' role labels; the planner's actions (unrecorded Secrets, a DS split, a second service account, an unmapped profile variable); routes and Ingresses off behind a cluster gateway; the fetch script's pins; idm-admin-ui on for IDM 8.1 with its image; config profiles with secrets as tokens, the values and overlay running their images and delivering their variables; the keystore generated unless the record delivers it; DS image inputs (the schema as one `cn=schema` entry, tree entries by the backend whose base DN holds them, the Dockerfile from the record's DS image) and the render notes for an unserved backend and the DS configuration to apply online; no SecretProviderClass mounted, so CSI Secrets come through sync pods. Tests marked `kubernetes` (skipped without `tools/bin/kubeconform` and the fetched release) build the render with `helm template` and `kustomize build` and check it with kubeconform: DS on servers, DS in the cluster, behind a gateway, with config profiles, with the record's keystore.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-forgeops/tests` (unit tests); add `-m kubernetes` after `scripts/fetch-forgeops.sh` and `opsdir/scripts/fetch-tools.sh` for the builds.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `forgeops`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

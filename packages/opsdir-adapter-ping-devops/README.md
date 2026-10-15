# opsdir-adapter-ping-devops

opsdir adapter for **ping-devops**, Ping Identity's Helm chart for its DevOps images. It renders the chart's values for the PingFederate admin console and engines an environment runs on Kubernetes and, on request, PingFederate's configuration as a Ping server profile, from the record's workloads and their workload bindings, for one pinned chart release: **0.16.0** (`release.py`; chart default image tag `2609`). ForgeOps (`opsdir-adapter-forgeops`) deploys PingAM, PingIDM, PingDS and PingGateway; this chart's other products (PingDirectory, PingAccess, ...) aren't rendered.

**Applies to** environments that run, on Kubernetes (a workload binding), a workload whose `ciamTargetRole` is `pf-admin` (the chart's `pingfederate-admin`) or `pf-engine` (`pingfederate-engine`). The chart runs one of each per release, so per namespace the first workload of each role is placed (`products.py`, `placements`); a further one is named by the planner, not deployed. The adapter is kind `platform`: an environment that declares a stack renders it only when the stack names it (`ping-devops`); one that declares none renders it when it runs such a workload.

**Depends on** `opsdir`, `opsdir-adapter-kubernetes` and `opsdir-adapter-pingfederate` (whose `pf-cluster-discovery` binding the values and the check read, and whose log file declarations the sidecars follow). The kubernetes adapter renders what surrounds the workloads: the namespace, service accounts with their cloud identities, network policies (from this adapter's listeners, below), Secret delivery and the HTTPRoutes of a cluster gateway. Render both. Installing the values needs Helm and Ping's chart repository (`https://helm.pingidentity.com/`); the `kubernetes` tests need helm and kubeconform (`opsdir/scripts/fetch-tools.sh`) and the fetched chart.

## What it renders

Per namespace, `ping-devops/helm/<namespace>/ping-devops-values.yaml`, installed with the command in its header:

```
helm upgrade --install pingfederate ping-devops --repo https://helm.pingidentity.com/ --version 0.16.0 \
  --namespace <namespace> -f ping-devops-values.yaml
```

**Prerequisite:** the organization has accepted Ping Identity's terms for PingFederate, once, through its agreement with Ping (an administrator's act, outside opsdir and outside any deployment). PingFederate's image starts only with `PING_IDENTITY_ACCEPT_EULA=YES`, so the values set it (`global.envs`) for every product. That setting is the image's startup requirement, not a record of the acceptance.

Helm merges the values over the chart's own, so what the record doesn't hold stays the chart's default. That includes the engines' wait for the admin console (an init container running the chart's `pingidentity/pingtoolkit:2609`) and PingFederate's other clustering settings (`OPERATIONAL_MODE`, `DNS_RECORD_TYPE` A). The chart's other products stay off.

Per product (the one without a workload is `enabled: false`):

| From the record | Rendered as |
|---|---|
| the workload bindings' `ciamContainerImage` (`container=image`), by the container names `pingfederate-admin` / `pingfederate-engine`, then `pingfederate` (so engines can take the admin binding's image; its own workload's binding first); else the workload's only image | `image.repositoryFqn`, `image.tag` (the record's registry as is); a digest as repositoryFqn `<name>[:<tag>]@sha256`, tag `<hex>`, which the chart's `<repositoryFqn>:<tag>` turns back into the reference |
| no image named | `UNBOUND:ping-devops-<product>-image` |
| `ciamWorkloadReplicas`, `ciamCpuRequest`/`Limit`, `ciamMemoryRequest`/`Limit` | `container.replicaCount`, `container.resources` |
| `ciamServiceAccount` (else the workload's name) | `rbac.serviceAccountName`. The kubernetes adapter makes it; the chart makes none |
| the workload's role, its identity binding | `workload.labels`: `opsdir.io/role: <role>` (what the network policies select) plus the pod labels the cloud's workload identity needs. The chart puts them on pod templates only; its selectors are its own |
| the workload's cluster role, workload role, identity role and name | `workload.annotations` (pod annotations) with the marks `opsdir.io/cluster-role`, `workload-role`, `identity-role` and `workload` (the chart names the workload `<release>-pingfederate-admin`; the mark gives the record's name), and `opsdir.io/derived-containers` naming the log sidecars, so the deployment reads back as the record |
| each Secret key the workload reads (`ciamWorkloadSecret <secret>/<key> <- <role>`) | `container.env`: the environment variable of its name (`secretKeyRef`). The exception is `pingfederate.lic`, mounted as the license file at `/opt/in/instance/server/default/conf/pingfederate.lic` (`secretVolumes`), as in the chart's own example |
| `ciamStorageSize` / `ciamStorageClass` | the product runs as a StatefulSet (`workload.type`) with a persistent volume `out-dir` for `/opt/out`. A release first installed as a Deployment can't be changed to a StatefulSet in place |
| `ciamIngressHost` | `ingress` for those hosts (path `/`, the chart's `https` service), TLS from the chart's default TLS secret; none when the workload records none |
| a cluster gateway (`ciamClusterGateway`) in front of the role | no Ingress: the role's whole host goes to the chart's Service (`pingfederate-pingfederate-admin:9999`, `pingfederate-pingfederate-engine:9031`, both TLS) as a route (`routes.py`) that opsdir-adapter-kubernetes renders as an HTTPRoute, re-encrypted to the pods |
| a `ciamProfileRepo` on the workload binding | `envs`: `SERVER_PROFILE_URL`, `SERVER_PROFILE_PATH`, `SERVER_PROFILE_BRANCH` (server profile, below) |
| the environment's `pf-cluster-discovery` binding when it is `DNS_PING` (opsdir-adapter-pingfederate's `pingfedClusterDiscovery`, `ciamFqdn`) | `global.envs.DNS_QUERY_LOCATION`: its DNS name. The chart's own value is its cluster service, `pingfederate-pingfederate-cluster.<namespace>.svc.cluster.local` (headless, publishing unready pods), so the binding to record is that name; the planner check below offers it |

### Secrets

The chart writes no Secret; they come from the kubernetes adapter (`external-secrets` or `csi`) or the operator. Under the kubernetes adapter's `csi` target (its SecretProviderClasses, one per secret store a workload reads from), each product mounts its classes, so the CSI driver keeps the Secrets synced: the adapter declares `mounts_secrets` for the workloads it deploys, and no sync pod is rendered for them.
- One class goes through the chart's own block: `secretProviderClass` `enabled: true`, `create: false` (the class is the kubernetes adapter's), `name`, `mountPath: /run/secrets/<class>`; it reaches the utility sidecar too.
- Several classes go in as the product's own `volumes` (CSI, read-only) and `volumeMounts` at `/run/secrets/<class>`, beside the log sidecars' mounts.

Checked with `helm template` and kubeconform (the tests marked `kubernetes`).

### Log sidecars

One sidecar per PingFederate log file the environment's log routes pick (`log_sidecars.py`, user decision 2348; core `observability`: `ciamLogRoute` kinds from `pf-admin` / `pf-engine`), so each file's lines are its own container's output and the clouds' collectors tell them apart by container name. The image streams only `server.log` and `init.log` (`TAIL_LOG_FILES`) on its main container, with nothing marking which file a line is from.
- The files and their kinds are opsdir-adapter-pingfederate's declarations (`pingfederate/log/<file>`), declared here on kubernetes as container `pf-log-<file>` (`logs.py`): for example `pf-log-audit` (audit), `pf-log-runtime-request` (access), `pf-log-transaction` (transaction), `pf-log-admin` (admin). The main container's output is the server log's (text, `error`).
- Each sidecar (top-level `sidecars`, the product's `includeSidecars`, as the pinned chart's `pinglib/_workload.tpl` reads them) runs the product's own image: `tail -n +1 -F /pf-out/instance/log/<file>`, with `out-dir` mounted read-only at `/pf-out`, 10m CPU and 16Mi requested, 64Mi limit, no privilege escalation, every capability dropped.
- A StatefulSet shares its `out-dir` volume (`/opt/out`). A Deployment's `/opt/out` is the container's own, so the values add `out-dir` as an `emptyDir` (top-level `volumes`, `includeVolumes`) mounted at `/opt/out` on the main container. It is mounted at `/opt/out`, never at `/opt/out/instance/log`: the image's start hooks take an existing server root for a restart, and the kubelet would create it for that mount.
- Only the files a route picks get a sidecar; with no log routes the values have none.

### Server profile (target `server-profile`, on request)

`opsdir render <env> --target pingfederate=admin-api,terraform,bulk-config --target ping-devops=server-profile` renders PingFederate's configuration as a Ping server profile under `ping-devops/server-profile/<namespace>/pingfederate/` (`profiles.py`). The `pingfederate` adapter's bulk-config target gives `instance/bulk-config/data.json`, which the image imports when the admin console starts and then replicates to the engines. The captured files keep their instance paths, for example `instance/bin/run.properties`. Nothing is written when the record holds nothing for PingFederate.

No profile holds a secret. Where PingFederate's configuration needs one, the profile holds `${OPSDIR_<ROLE>}` and the file is named `<file>.subst`, so the image fills it from the environment at start. A key pair's `fileData` is the PKCS#12 file, base64-encoded. You map the variable on the workload like any other Secret key: `ciamWorkloadSecret: <secret>/OPSDIR_<ROLE> <- <role>`. The values already deliver every key the workload records.

Where the profile comes from is up to the record:
- When the workload binding names a repository (`ciamProfileRepo: <git URL>[#<path>][@<branch>]`), the values set `SERVER_PROFILE_URL`, `_PATH` and `_BRANCH`, and the containers fetch it. Commit the `pingfederate/` folder there. A private repository's credentials are Secret keys the workload records (`SERVER_PROFILE_GIT_USER`, `SERVER_PROFILE_GIT_PASSWORD`).
- Otherwise the `Dockerfile` beside the profile rebuilds the record's image with it in `/opt/in` (`COPY --chown=ping:identity`). Build with `--build-arg BASE_IMAGE=<the PingFederate image to start from>` and push it as the image the record names (the Dockerfile's header names it).

A `README.md` per namespace lists each product's way, each variable, its role and whether the record maps it. The planner names the unmapped ones.

### Listeners

The chart's PingFederate pods' container ports (`release.py`, `POD_PORTS`), declared as listeners `on="kubernetes"`: the admin console's 9999 (operators, and the engines' wait for it), the engines' runtime 9031 (clients), and the cluster ports 7600 and 7700 (JGroups bind and failure detection) between the admin console and the engines. The kubernetes adapter's network policies admit them to the pods; the firewall checks leave them out.

## Reading it back

This adapter has no importer of its own. The rendered values, run through `helm template`, read back through opsdir-adapter-kubernetes's importer: the marks put the workloads back under their records' names, and `opsdir.io/derived-containers` tells it the log sidecars are derived from the record, not workloads of their own.

## Planner check

`check_ping_devops` (area `PingFederate on Kubernetes`, `checks.py`) adds actions on the target environment, owned by the environment's responsible team:
- a placed PingFederate workload with no license recorded: neither the key `pingfederate.lic` nor both `PING_IDENTITY_DEVOPS_USER` and `PING_IDENTITY_DEVOPS_KEY` (a license from Ping's license server);
- an admin console with no `PING_IDENTITY_PASSWORD` recorded (the image's default administrator password is published);
- an admin console recording more than one replica (a PingFederate cluster has one admin console node);
- engines in a namespace with no admin console (the chart clusters engines with their release's admin console);
- a workload of a role beyond the first in its namespace (not deployed: scale the first or give it its own namespace);
- a cluster discovery that isn't `DNS_PING` through the chart's cluster service (no binding, another protocol, another DNS name). Its fix binds it (`pingfedClusterDiscovery`, `DNS_PING`, `ciamFqdn` the service's name), replacing a binding of another class under the same name; nodes still running the old discovery don't find the new ones, so the cluster moves as a whole. The core's binding check may also offer to bind the role the way the source does (an S3 bucket, for instance); on Kubernetes, take this fix instead;
- a server profile's `OPSDIR_<ROLE>` variable the record doesn't deliver, when the target renders the server profile.

With none of these it says the licenses, admin password and cluster discovery are recorded. It adds no required roles, vocabulary, schema, reference schemes or secret patterns; opsdir-adapter-pingfederate says which roles PingFederate needs.

## The chart

`scripts/fetch-ping-devops.sh` downloads the pinned chart into `tools/ping-devops/0.16.0/` at the repository root (gitignored). The archive comes from Ping's GitHub release and is checked against the SHA-256 that Ping's chart repository index lists for it, pinned in `release.py` (a test keeps the script's pins equal). Idempotent.

## Known limits

- **Not run against a live cluster.** The values are checked with `helm template` and kubeconform against the pinned chart; deploying them is part of the testing plan (milestone 7.2).
- **One chart release** (0.16.0) and **one admin console and one engine workload per namespace** (the chart's one release per product).
- **PingFederate only**: the chart's other products aren't rendered.
- PingFederate's configuration as Admin API payloads or Terraform, applied to the running admin console, is the `pingfederate` adapter's (the server profile above carries its bulk import document).
- Storage switches a product to a StatefulSet, which an installed Deployment release can't take in place.

## Tests

`tests/test_ping_devops.py`: it renders only where PingFederate runs on Kubernetes; the admin values from the record (image, replicas, resources, service account, labels, marks, Secrets as variables and the license as a file, storage, ingress); the engine sharing the admin image and scaling; an unnamed image `UNBOUND` and a missing product off; the pods' ports; the planner's actions (license, admin password, replicas, engines alone, extra workloads, an unmapped profile variable); the nodes finding each other through the chart's cluster service and the fix that binds it; routes and the Ingress off behind a cluster gateway; the fetch script's pins; each log file a route picks as its own sidecar's output; the server profile with secrets substituted and built into the image, or fetched from a repository; CSI classes mounted through the chart's block or as the products' own volumes, and no sync pod for them. Tests marked `kubernetes` (skipped without the tools and the fetched chart) template the values with the chart and check them with kubeconform: the values, the sidecars beside PingFederate, the classes mounted in the pods.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-ping-devops/tests` (unit tests); add `-m kubernetes` after `scripts/fetch-ping-devops.sh` and `opsdir/scripts/fetch-tools.sh`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `ping-devops`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

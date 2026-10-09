# opsdir-adapter-ping-devops

opsdir adapter for **ping-devops**, Ping Identity's Helm chart for its DevOps images. It renders the chart's values for the PingFederate admin console and engines an environment runs on Kubernetes, from the record's workloads and their workload bindings, for one pinned chart release: **0.16.0** (`release.py`; chart default image tag `2609`). ForgeOps (`opsdir-adapter-forgeops`) deploys PingAM, PingIDM, PingDS and PingGateway; this chart's other products (PingDirectory, PingAccess, ...) aren't rendered.

**Applies to** environments that run, on Kubernetes (a workload binding), a workload of role `pf-admin` (the chart's `pingfederate-admin`) or `pf-engine` (`pingfederate-engine`). The chart runs one of each per release, so per namespace the first workload of each role is placed. The adapter is kind `platform`, so an environment that declares a stack renders it only when the stack names it.

**Depends on** `opsdir` and `opsdir-adapter-kubernetes`. That adapter renders what surrounds the workloads: the namespace, service accounts with their cloud identities, network policies (from this adapter's listeners, below) and Secret delivery. Render both.

## What it renders

`ping-devops/helm/<namespace>/ping-devops-values.yaml`, installed with the command in its header:

```
helm upgrade --install pingfederate ping-devops --repo https://helm.pingidentity.com/ --version 0.16.0 \
  --namespace <namespace> -f ping-devops-values.yaml
```

**Prerequisite:** the organization has accepted Ping Identity's terms for PingFederate, once, through its agreement with Ping (an administrator's act, outside opsdir and outside any deployment). PingFederate's image starts only with `PING_IDENTITY_ACCEPT_EULA=YES`, so the values set it (`global.envs`) for every product. That setting is the image's startup requirement, not a record of the acceptance.

Per product (the one without a workload is `enabled: false`), from the record:
- **Image** (`repositoryFqn`, `tag`) from the workload bindings' `ciamContainerImage` (`container=image`):
  - matched by the container names `pingfederate-admin` / `pingfederate-engine`, then `pingfederate`, so engines can take the admin binding's image;
  - failing that, the workload's only image; else `UNBOUND:ping-devops-<product>-image`;
  - a digest is written as repositoryFqn `<name>[:<tag>]@sha256`, tag `<hex>`, which the chart's `<repositoryFqn>:<tag>` turns back into the reference.
- **Replicas, CPU and memory** (`container.replicaCount`, `container.resources`) from the binding.
- **Service account**: `rbac.serviceAccountName`, the workload's (`ciamServiceAccount`, else its name). The kubernetes adapter makes it; the chart makes none.
- **Pod labels** (`workload.labels`): `opsdir.io/role: <role>`, which the network policies select, plus the pod labels the cloud's workload identity needs. The chart puts them on pod templates only; its selectors are its own.
- **Secrets**: each key the workload reads (`ciamWorkloadSecret <secret>/<key> <- <role>`) is set as the environment variable of its name (`secretKeyRef`).
  - The exception is `pingfederate.lic`, which is mounted as the license file at `/opt/in/instance/server/default/conf/pingfederate.lic`, as in the chart's own example.
  - The chart writes no Secret; they come from the kubernetes adapter (`external-secrets`) or the operator.
- **Storage**: when the binding records `ciamStorageSize` or `ciamStorageClass`, the product runs as a StatefulSet with a volume for `/opt/out`.
  - A release first installed as a Deployment can't be changed to a StatefulSet in place.
- **Ingress** for the hosts the workload records (`ciamIngressHost`), TLS from the chart's default TLS secret; none when it records none.

What the record doesn't hold stays the chart's default. That includes the engines' wait for the admin console (an init container running the chart's `pingidentity/pingtoolkit:2609`) and PingFederate's clustering settings (`OPERATIONAL_MODE`, DNS discovery through the release's cluster service).

## Listeners

The chart's PingFederate pods' container ports (`release.py`, `POD_PORTS`), declared as listeners `on="kubernetes"`: the admin console's 9999 (operators, and the engines' wait for it), the engines' runtime 9031 (clients), and the cluster ports 7600 and 7700 between the admin console and the engines. The kubernetes adapter's network policies admit them to the pods; the firewall checks leave them out.

## Planner check

`check_ping_devops` adds actions on the target environment:
- a placed PingFederate workload with no license recorded: neither the key `pingfederate.lic` nor both `PING_IDENTITY_DEVOPS_USER` and `PING_IDENTITY_DEVOPS_KEY` (a license from Ping's license server);
- an admin console with no `PING_IDENTITY_PASSWORD` recorded (the image's default administrator password is published);
- an admin console recording more than one replica (a PingFederate cluster has one admin console node);
- engines in a namespace with no admin console (the chart clusters engines with their release's admin console);
- a workload of a role beyond the first in its namespace (not deployed).

## The chart

`scripts/fetch-ping-devops.sh` downloads the pinned chart into `tools/ping-devops/0.16.0/` (gitignored). The archive comes from Ping's GitHub release and is checked against the SHA-256 that Ping's chart repository index lists for it, pinned in `release.py`. The test marked `kubernetes` renders the values, runs `helm template` on the chart with them, and checks the result with kubeconform (`opsdir/scripts/validate-kubernetes.sh`). It needs the tools from `opsdir/scripts/fetch-tools.sh`.

Tests: `tests/test_ping_devops.py`.

Not done here:
- The chart's own Secret Provider Class mount, for the kubernetes adapter's `csi` target. Use `external-secrets`.
- PingFederate's configuration. The `pingfederate` adapter renders it (Admin API payloads, Terraform) to apply to the running admin console; server profiles are milestone 5.9.
- The rest of the chart's products.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `ping-devops`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

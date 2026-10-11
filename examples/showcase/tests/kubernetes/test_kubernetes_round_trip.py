"""Round trip of the showcase's Kubernetes output through a cluster's eyes: each environment's render with a kubernetes/
folder, rendered from the record as `opsdir render` writes it, is expanded as it is deployed (each Helm values file
rendered with its kit's chart, `helm template`, into the namespace its folder names, as `helm install -n` places it;
each kubernetes/<namespace> folder built with `kustomize build`), then read back by the kubernetes adapter's
workloads importer against the record the render came from (connectors.roundtrip.read_back). ForgeOps' Kustomize
overlay is the deprecated alternative to its Helm values, so only the values are deployed. Runs with the local tools
and kit sources; skipped without them."""
import pathlib
import subprocess

import pytest
import yaml

from opsdir.connectors.render import render_env
from opsdir.connectors.roundtrip import read_back
from opsdir.connectors.registry import environment, environment_specs
from opsdir_adapter_forgeops import release as forgeops
from opsdir_adapter_kubernetes.adapter import ADAPTER
from opsdir_adapter_ping_devops import release as ping_devops

ROOT = pathlib.Path(__file__).resolve().parents[4]
BIN = ROOT / "tools" / "bin"
FORGEOPS = ROOT / "tools" / "forgeops" / forgeops.VERSION
PING_DEVOPS = ROOT / "tools" / "ping-devops" / ping_devops.VERSION / ping_devops.CHART
pytestmark = [pytest.mark.kubernetes,
              pytest.mark.skipif(not (BIN / "helm").exists() or not (BIN / "kustomize").exists()
                                 or not (FORGEOPS / ".complete").exists()
                                 or not (PING_DEVOPS.parent / ".complete").exists(),
                                 reason="no tools (opsdir/scripts/fetch-tools.sh) or kit sources (fetch-forgeops.sh, "
                                        "fetch-ping-devops.sh)")]
# kinds the API server keeps outside any namespace
CLUSTER_SCOPED = {"Namespace", "ClusterRole", "ClusterRoleBinding", "CustomResourceDefinition", "GatewayClass",
                  "StorageClass", "PriorityClass", "PersistentVolume", "MutatingWebhookConfiguration",
                  "ValidatingWebhookConfiguration", "IngressClass"}
# What target/prod's deployment doesn't read back as yet, before and after the approved changes ((changetype, DN,
# attributes), meta attributes aside): the kits' workloads carry no cluster-role mark, ping-devops names its
# workloads after the Helm release, ForgeOps' AM container is `openam` and its UIs aren't in the record, and IDM is
# served under AM's host, which the record doesn't say. Milestone 88 (5.5b Kubernetes read-back parity) empties it.
TARGET_REMAINING = (('add',
                     'cn=admin-ui,ou=bindings,env=prod,cloud=target,ou=environments,dc=ciam-ops',
                     ('ciamBindingRole',
                      'ciamContainerImage',
                      'ciamCpuRequest',
                      'ciamMemoryLimit',
                      'ciamMemoryRequest',
                      'ciamWorkloadReplicas',
                      'cn',
                      'objectClass')),
                    ('add',
                     'cn=admin-ui,ou=workloads,dc=ciam-ops',
                     ('ciamClusterRole',
                      'ciamIngressHost',
                      'ciamNamespace',
                      'ciamPodSecurity',
                      'ciamRepoPath',
                      'ciamServiceAccount',
                      'ciamTargetRole',
                      'ciamWorkloadKind',
                      'ciamWorkloadRole',
                      'cn',
                      'objectClass')),
                    ('add',
                     'cn=ciam-pingfederate-admin,ou=bindings,env=prod,cloud=target,ou=environments,dc=ciam-ops',
                     ('ciamBindingRole',
                      'ciamContainerImage',
                      'ciamCpuLimit',
                      'ciamCpuRequest',
                      'ciamMemoryLimit',
                      'ciamMemoryRequest',
                      'ciamStorageClass',
                      'ciamStorageSize',
                      'ciamWorkloadReplicas',
                      'cn',
                      'objectClass')),
                    ('add',
                     'cn=ciam-pingfederate-admin,ou=workloads,dc=ciam-ops',
                     ('ciamClusterRole',
                      'ciamIdentityRole',
                      'ciamNamespace',
                      'ciamPodSecurity',
                      'ciamRepoPath',
                      'ciamSecretName',
                      'ciamServiceAccount',
                      'ciamTargetRole',
                      'ciamWorkloadKind',
                      'ciamWorkloadRole',
                      'cn',
                      'objectClass')),
                    ('add',
                     'cn=ciam-pingfederate-engine,ou=bindings,env=prod,cloud=target,ou=environments,dc=ciam-ops',
                     ('ciamBindingRole',
                      'ciamContainerImage',
                      'ciamCpuLimit',
                      'ciamCpuRequest',
                      'ciamMemoryLimit',
                      'ciamMemoryRequest',
                      'ciamWorkloadReplicas',
                      'cn',
                      'objectClass')),
                    ('add',
                     'cn=ciam-pingfederate-engine,ou=workloads,dc=ciam-ops',
                     ('ciamClusterRole',
                      'ciamIdentityRole',
                      'ciamNamespace',
                      'ciamPodSecurity',
                      'ciamRepoPath',
                      'ciamSecretName',
                      'ciamServiceAccount',
                      'ciamTargetRole',
                      'ciamWorkloadKind',
                      'ciamWorkloadRole',
                      'cn',
                      'objectClass')),
                    ('add',
                     'cn=end-user-ui,ou=bindings,env=prod,cloud=target,ou=environments,dc=ciam-ops',
                     ('ciamBindingRole',
                      'ciamContainerImage',
                      'ciamCpuRequest',
                      'ciamMemoryLimit',
                      'ciamMemoryRequest',
                      'ciamWorkloadReplicas',
                      'cn',
                      'objectClass')),
                    ('add',
                     'cn=end-user-ui,ou=workloads,dc=ciam-ops',
                     ('ciamClusterRole',
                      'ciamIngressHost',
                      'ciamNamespace',
                      'ciamPodSecurity',
                      'ciamRepoPath',
                      'ciamServiceAccount',
                      'ciamTargetRole',
                      'ciamWorkloadKind',
                      'ciamWorkloadRole',
                      'cn',
                      'objectClass')),
                    ('add',
                     'cn=login-ui,ou=bindings,env=prod,cloud=target,ou=environments,dc=ciam-ops',
                     ('ciamBindingRole',
                      'ciamContainerImage',
                      'ciamCpuRequest',
                      'ciamMemoryLimit',
                      'ciamMemoryRequest',
                      'ciamWorkloadReplicas',
                      'cn',
                      'objectClass')),
                    ('add',
                     'cn=login-ui,ou=workloads,dc=ciam-ops',
                     ('ciamClusterRole',
                      'ciamIngressHost',
                      'ciamNamespace',
                      'ciamPodSecurity',
                      'ciamRepoPath',
                      'ciamServiceAccount',
                      'ciamTargetRole',
                      'ciamWorkloadKind',
                      'ciamWorkloadRole',
                      'cn',
                      'objectClass')),
                    ('modify',
                     'cn=am,ou=bindings,env=prod,cloud=target,ou=environments,dc=ciam-ops',
                     ('ciamContainerImage',)),
                    ('modify', 'cn=am,ou=workloads,dc=ciam-ops', ('ciamClusterRole',)),
                    ('modify', 'cn=idm,ou=workloads,dc=ciam-ops', ('ciamClusterRole', 'ciamIngressHost')),
                    ('modify', 'cn=ig,ou=workloads,dc=ciam-ops', ('ciamClusterRole',)))
# (environment, state) -> what doesn't read back yet
REMAINING = {("target/prod", state): list(TARGET_REMAINING) for state in ("before", "after")}


def _run(*argv):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return done.stdout


def _namespaced(text, namespace):
    """The manifests with each namespaced object placed in namespace when it names none, as the API server does."""
    docs = [o for o in yaml.safe_load_all(text) if o]
    placed = [{**o, "metadata": {"namespace": namespace, **(o.get("metadata") or {})}}
              if o.get("kind") not in CLUSTER_SCOPED else o for o in docs]
    return yaml.safe_dump_all(placed, sort_keys=False)


def deployed(render):
    """{kubernetes/<name>.yaml: manifests} of a render, expanded as it is deployed."""
    charts = [(FORGEOPS / "charts" / f.name.removesuffix("-values.yaml"), f)
              for f in sorted(render.glob("forgeops/helm/*/*-values.yaml"))]
    charts += [(PING_DEVOPS, f) for f in sorted(render.glob(f"{ping_devops.CHART}/helm/*/*-values.yaml"))]
    helm = {f"kubernetes/helm-{values.parent.name}-{values.name}":
            _namespaced(_run(BIN / "helm", "template", "ciam", chart, "-f", values, "-n", values.parent.name),
                        values.parent.name)
            for chart, values in charts}
    built = {f"kubernetes/kustomize-{k.parent.name}.yaml": _namespaced(_run(BIN / "kustomize", "build", k.parent),
                                                                       k.parent.name)
             for k in sorted((render / "kubernetes").glob("*/kustomization.yaml"))}
    return {**helm, **built}


def _summary(trip):
    return sorted((c.changetype, c.dn, tuple(sorted({m[1] for m in c.mods} if c.changetype == "modify"
                                                    else set(c.attrs))))
                  for rt in trip for c in rt.drift)


def _written(files, root):
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    return root


@pytest.mark.parametrize("state", ["before", "after"])
def test_each_deployed_render_reads_back_as_the_record(estate, tmp_path, state):
    d = estate[state]
    specs = [s for s in environment_specs(d) if ADAPTER in environment(d, s)[1]]
    trips = {s: read_back(d, ADAPTER, deployed(_written(render_env(d, s)[1], tmp_path / s)), environment=s)
             for s in specs}
    found = {s: _summary(t) for s, t in trips.items()}
    print(*(x for s in specs for x in found[s]), sep="\n")
    assert specs and found == {s: REMAINING.get((s, state), []) for s in specs}

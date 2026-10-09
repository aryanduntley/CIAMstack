"""The importer `kubernetes/workloads`: Kubernetes manifests read into the record as workloads. Pure.

Takes manifests as files: `kubectl get … -o yaml` (or -o json) output, rendered Helm or Kustomize output, any multi-
document YAML. Every StatefulSet, Deployment and DaemonSet is one workload (ciamWorkload, the core compute domain): a
server role run as containers, intent, the same in every environment. Manifests under <cloud>/<env>/ (an environment
the record holds) also give that environment's workload binding (ciamWorkloadBinding: how it runs the workload on
Kubernetes); manifests anywhere else give the intent only, and the notices say so.

  role             label or annotation opsdir.io/role, else label app.kubernetes.io/component, else
                   app.kubernetes.io/name, else roles.json beside the manifests ({workload name: role}); without one
                   the workload is named, not imported
  cluster          annotation opsdir.io/cluster-role: the binding role of the cluster it runs in, else `cluster`
  recorded         namespace, service account, pod security facts (runAsNonRoot, readOnlyRootFilesystem,
                   privileged, hostNetwork, hostPID, the namespace's pod-security level), network policies that select
                   its pods, ingress hosts that reach it through a Service
  workload role    annotation opsdir.io/workload-role, else <name>-workload: the binding role of its workload binding
  binding          (manifests under <cloud>/<env>/) named like the workload under the environment's bindings: each
                   container's image (container=image), replicas, the main (first) container's CPU and memory
                   requests and limits, the storage each replica claims (its first volume claim template: size and
                   storage class)
  identity         when its service account carries a cloud identity (EKS IRSA, Azure workload identity, GKE), the
                   binding role each environment gives it: annotation opsdir.io/identity-role, else <role>-identity
  secrets          the names of the Secrets it reads (env, envFrom, volumes): names only. Secret objects in the
                   manifests are never read (counted in the notices)

A CronJob is a job (ciamJob, the core automation domain), realized by the cluster it runs in (ciamJobRole: its cluster
role): kind cron, its schedule, the command it runs (not recorded when it holds secret material), its image
(ciamRuntime), service account (ciamRunsAs) and the Secrets it reads by name. It is named k8s-<name>.

A Gateway API Gateway under <cloud>/<env>/ is that environment's cluster gateway binding (gateway_import.py).

A workload is named by its metadata name (namespace-name when two namespaces use the name); a re-import finds it by
name and changes nothing; what the record adds (owners, criticality) is kept.
"""
import yaml

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, make_entry, merged_attrs, ou_entry
from opsdir.core.environment import env_dn
from opsdir.core.naming import rdn_safe
from opsdir.core.secrets import text_concerns
from opsdir.core.sources import json_document, parsed
from opsdir.domains.automation.naming import job_dn
from opsdir.domains.automation.pipelines import jobs_container
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from .gateway_import import read_gateways

KINDS = (("StatefulSet", "statefulset"), ("Deployment", "deployment"), ("DaemonSet", "daemonset"))
ROLE_MAP = "roles.json"
IDENTITY_ANNOTATIONS = ("eks.amazonaws.com/role-arn", "azure.workload.identity/client-id",
                        "iam.gke.io/gcp-service-account")
OWNED = ("cn", "ciamWorkloadKind", "ciamTargetRole", "ciamClusterRole", "ciamNamespace", "ciamWorkloadRole",
         "ciamServiceAccount", "ciamIdentityRole", "ciamPodSecurity", "ciamNetworkPolicy", "ciamSecretName",
         "ciamIngressHost", "ciamRepoPath")
BINDING_OWNED = ("cn", "ciamBindingRole", "ciamContainerImage", "ciamWorkloadReplicas", "ciamCpuRequest",
                 "ciamCpuLimit", "ciamMemoryRequest", "ciamMemoryLimit", "ciamStorageSize", "ciamStorageClass")


def _load_all(text):
    return [d for d in yaml.safe_load_all(text) if d is not None]


def objects(files):
    """(path, object) of every Kubernetes object in the files, Lists unpacked; (path, None) for a file that isn't
    YAML or JSON."""
    def unpacked(doc):
        return [i for i in doc.get("items") or () if isinstance(i, dict)] if doc.get("kind", "").endswith("List") \
            else [doc]
    read = [(p, parsed(_load_all, t, (yaml.YAMLError,))) for p, t in sorted(files.items()) if p != ROLE_MAP]
    return [(p, o) for p, docs in read if docs is not None
            for d in docs if isinstance(d, dict) and d.get("kind") for o in unpacked(d)] + \
        [(p, None) for p, docs in read if docs is None]


def _meta(o):
    return o.get("metadata") or {}


def _labels(o):
    return _meta(o).get("labels") or {}


def _annotations(o):
    return _meta(o).get("annotations") or {}


def _namespace(o):
    return _meta(o).get("namespace") or "default"


def _pod(o):
    """A workload's pod template (a CronJob's is under its job template)."""
    spec = o.get("spec") or {}
    return (spec.get("template") or ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {})


def _pod_spec(o):
    return _pod(o).get("spec") or {}


def _containers(o):
    return [c for c in _pod_spec(o).get("containers") or () if isinstance(c, dict)]


def workload_role(o, roles):
    """The server role a workload realizes, or None."""
    labels, notes = _labels(o), _annotations(o)
    return (labels.get("opsdir.io/role") or notes.get("opsdir.io/role") or labels.get("app.kubernetes.io/component")
            or labels.get("app.kubernetes.io/name") or roles.get(_meta(o).get("name")))


def _selects(selector, labels):
    """Whether a label selector (matchLabels, or a plain map) selects these labels."""
    wanted = (selector or {}).get("matchLabels", selector or {}) if isinstance(selector, dict) else {}
    return isinstance(wanted, dict) and all(labels.get(k) == v for k, v in wanted.items())


def pod_security(o, namespaces):
    """Security facts of a workload's pods, and its namespace's pod-security level."""
    spec = _pod_spec(o)
    contexts = [spec.get("securityContext") or {}, *((c.get("securityContext") or {}) for c in _containers(o))]
    level = (_labels(namespaces.get(_namespace(o)) or {}) or {}).get("pod-security.kubernetes.io/enforce")
    facts = (("runAsNonRoot", any(c.get("runAsNonRoot") is True for c in contexts)),
             ("readOnlyRootFilesystem", bool(_containers(o)) and all((c.get("securityContext") or {})
                                                                      .get("readOnlyRootFilesystem") is True
                                                                      for c in _containers(o))),
             ("privileged", any(c.get("privileged") is True for c in contexts)),
             ("hostNetwork", spec.get("hostNetwork") is True), ("hostPID", spec.get("hostPID") is True))
    return (*(name for name, on in facts if on), *((f"level={level}",) if level else ()))


def secret_names(o):
    """Names of the Secrets a workload's pods read: env secretKeyRef, envFrom secretRef, secret and projected
    volumes."""
    spec = _pod_spec(o)
    containers = [*_containers(o), *(c for c in spec.get("initContainers") or () if isinstance(c, dict))]
    found = (*(((e.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name") for c in containers
               for e in c.get("env") or ()),
             *((f.get("secretRef") or {}).get("name") for c in containers for f in c.get("envFrom") or ()),
             *((v.get("secret") or {}).get("secretName") for v in spec.get("volumes") or ()),
             *((s.get("secret") or {}).get("name") for v in spec.get("volumes") or ()
               for s in (v.get("projected") or {}).get("sources") or ()))
    return tuple(sorted({n for n in found if n}))


def _storage(o):
    claim = next(iter((o.get("spec") or {}).get("volumeClaimTemplates") or ()), None) or {}
    spec = claim.get("spec") or {}
    return ((spec.get("resources") or {}).get("requests") or {}).get("storage"), spec.get("storageClassName")


def _policies(o, policies):
    labels = _pod(o).get("metadata", {}).get("labels") or {}
    return tuple(f"{_meta(p).get('name')}: {', '.join((p.get('spec') or {}).get('policyTypes') or ('Ingress',))}"
                 for p in policies if _namespace(p) == _namespace(o)
                 and _selects((p.get("spec") or {}).get("podSelector"), labels))


def _hosts(o, services, ingresses):
    labels = _pod(o).get("metadata", {}).get("labels") or {}
    mine = {_meta(s).get("name") for s in services if _namespace(s) == _namespace(o)
            and (s.get("spec") or {}).get("selector") and _selects((s.get("spec") or {}).get("selector"), labels)}
    return tuple(sorted({r.get("host") for i in ingresses if _namespace(i) == _namespace(o)
                         for r in (i.get("spec") or {}).get("rules") or () if r.get("host")
                         for path in ((r.get("http") or {}).get("paths") or ())
                         if (((path.get("backend") or {}).get("service") or {}).get("name")
                             or (path.get("backend") or {}).get("serviceName")) in mine}))


def _identity(o, role, accounts):
    account = accounts.get((_namespace(o), _pod_spec(o).get("serviceAccountName") or "default")) or {}
    if not any(a in _annotations(account) for a in IDENTITY_ANNOTATIONS):
        return None
    return _annotations(o).get("opsdir.io/identity-role") or _annotations(account).get("opsdir.io/identity-role") \
        or f"{role}-identity"


def workload_role_of(o, name):
    """The binding role of a workload's workload binding: annotation opsdir.io/workload-role, else <name>-workload."""
    return _annotations(o).get("opsdir.io/workload-role") or f"{name}-workload"


def workload_entry(d, name, path, o, role, context):
    """The ciamWorkload entry for one workload object; context: namespaces, policies, services, ingresses, accounts."""
    dn = workload_dn(name)
    kind = dict(KINDS)[o.get("kind")]
    owned = {"cn": (name,), "ciamWorkloadKind": (kind,), "ciamTargetRole": (role,),
             "ciamClusterRole": (_annotations(o).get("opsdir.io/cluster-role") or "cluster",),
             "ciamNamespace": (_namespace(o),), "ciamWorkloadRole": (workload_role_of(o, name),),
             "ciamServiceAccount": (_pod_spec(o).get("serviceAccountName"),),
             "ciamIdentityRole": (_identity(o, role, context["accounts"]),),
             "ciamPodSecurity": pod_security(o, context["namespaces"]),
             "ciamNetworkPolicy": _policies(o, context["policies"]),
             "ciamSecretName": secret_names(o),
             "ciamIngressHost": _hosts(o, context["services"], context["ingresses"]), "ciamRepoPath": (path,)}
    return make_entry(dn, ("top", "ciamObject", "ciamWorkload"), merged_attrs(get(d, dn), owned, OWNED))


def _main_resources(o):
    resources = next(iter(_containers(o)), {}).get("resources") or {}
    return resources.get("requests") or {}, resources.get("limits") or {}


def _quantity(v):
    return None if v is None else str(v)


def binding_entry(d, env, name, o):
    """Environment env's ciamWorkloadBinding for one workload object: images per container, replicas, the main
    container's resources, the storage each replica claims."""
    dn = f"cn={name},ou=bindings,{env}"
    size, storage_class = _storage(o)
    requests, limits = _main_resources(o)
    replicas = (o.get("spec") or {}).get("replicas")
    owned = {"cn": (name,), "ciamBindingRole": (workload_role_of(o, name),),
             "ciamContainerImage": tuple(dict.fromkeys(f"{c.get('name')}={c.get('image')}" for c in _containers(o)
                                                       if c.get("image") and c.get("name"))),
             "ciamWorkloadReplicas": (str(replicas) if o.get("kind") != "DaemonSet" and replicas is not None
                                      else None,),
             "ciamCpuRequest": (_quantity(requests.get("cpu")),), "ciamCpuLimit": (_quantity(limits.get("cpu")),),
             "ciamMemoryRequest": (_quantity(requests.get("memory")),),
             "ciamMemoryLimit": (_quantity(limits.get("memory")),),
             "ciamStorageSize": (size,), "ciamStorageClass": (storage_class,)}
    return make_entry(dn, ("top", "ciamWorkloadBinding"), merged_attrs(get(d, dn), owned, BINDING_OWNED))


def environment_at(d, path):
    """The environment a manifest's <cloud>/<env>/ folder names, when the record holds it; else None."""
    parts = path.split("/")
    if len(parts) < 3 or not all(rdn_safe(p) for p in parts[:2]):
        return None
    env = env_dn(f"{parts[0]}/{parts[1]}")
    return env if get(d, env) is not None else None


def entry_names(workloads):
    """Each workload's entry name, in order: its metadata name, namespace-name when two namespaces use the name."""
    names = [_meta(o).get("name") for _, o in workloads]
    shared = {n for n in names if names.count(n) > 1}
    return [f"{_namespace(o)}-{n}" if n in shared else n for (_, o), n in zip(workloads, names)]


JOB_OWNED = ("cn", "ciamJobKind", "ciamSchedule", "ciamCommand", "ciamRuntime", "ciamRunsAs", "ciamJobRole",
             "ciamSecretName", "ciamRepoPath")


def cron_job_entry(d, path, o, patterns):
    """(entry, notices) of the job a CronJob is."""
    name = f"k8s-{_meta(o).get('name')}"
    dn = job_dn(name)
    first = next(iter(_containers(o)), {})
    command = " ".join(str(x) for x in (*(first.get("command") or ()), *(first.get("args") or ()))) or None
    secret = bool(command and text_concerns(command, patterns))
    owned = {"cn": (name,), "ciamJobKind": ("cron",), "ciamSchedule": ((o.get("spec") or {}).get("schedule"),),
             "ciamCommand": (None if secret else command,), "ciamRuntime": (first.get("image"),),
             "ciamRunsAs": (_pod_spec(o).get("serviceAccountName"),),
             "ciamJobRole": (_annotations(o).get("opsdir.io/cluster-role") or "cluster",),
             "ciamSecretName": secret_names(o), "ciamRepoPath": (path,)}
    return (make_entry(dn, ("top", "ciamObject", "ciamJob"), merged_attrs(get(d, dn), owned, JOB_OWNED)),
            ((f"job {name} ({path}): its command holds secret material; not recorded",) if secret else ()))


def read_workloads(files, d, patterns, at=None):
    """Imported: the workloads the manifests run."""
    roles = json_document(files.get(ROLE_MAP, ""), dict) or {}
    found = objects(files)
    of = {k: [o for _, o in found if o and o.get("kind") == k]
          for k in ("Namespace", "NetworkPolicy", "Service", "Ingress", "ServiceAccount", "Secret")}
    context = {"namespaces": {_meta(n).get("name"): n for n in of["Namespace"]}, "policies": of["NetworkPolicy"],
               "services": of["Service"], "ingresses": of["Ingress"],
               "accounts": {(_namespace(a), _meta(a).get("name")): a for a in of["ServiceAccount"]}}
    workloads = [(p, o) for p, o in found if o and o.get("kind") in dict(KINDS)]
    placed = [(p, o, n, workload_role(o, roles)) for (p, o), n in zip(workloads, entry_names(workloads))]
    kept = [(p, o, n, r) for p, o, n, r in placed if r and rdn_safe(n or "")]
    entries = [workload_entry(d, n, p, o, r, context) for p, o, n, r in kept]
    bindings = [binding_entry(d, environment_at(d, p), n, o) for p, o, n, r in kept if environment_at(d, p)]
    unplaced = sorted({p for p, o, n, r in kept if not environment_at(d, p)})
    gateways, gateway_notices = read_gateways(d, found, environment_at, rdn_safe)
    cron = [(p, o) for p, o in found if o and o.get("kind") == "CronJob"]
    jobs = [cron_job_entry(d, p, o, patterns) for p, o in cron if rdn_safe(f"k8s-{_meta(o).get('name')}")]
    return Imported(
        containers=(ou_entry(WORKLOADS), *((jobs_container(),) if jobs else ()),
                    *(ou_entry(b) for b in dict.fromkeys(e.dn.split(",", 1)[1] for e in (*bindings, *gateways)))),
        groups=(*((e.dn, (e,)) for e in entries), *((e.dn, (e,)) for e in bindings), *((e.dn, (e,)) for e in gateways),
                *((e.dn, (e,)) for e, _ in jobs)),
        notices=(*(f"{p}: {o.get('kind')} {n}: no role (label opsdir.io/role or app.kubernetes.io/component, or "
                   f"{ROLE_MAP}); not imported" for p, o, n, r in placed if not r),
                 *(f"{p}: {o.get('kind')} {n!r} can't be a record name; not imported" for p, o, n, r in placed
                   if r and not rdn_safe(n or "")),
                 *((f"{len(of['Secret'])} Secret object(s) in the manifests: never read (their values stay in the "
                    "cluster)",) if of["Secret"] else ()),
                 *((f"{len(unplaced)} manifest file(s) not under <cloud>/<env>/ of an environment the record "
                    f"holds ({', '.join(unplaced)}): workloads only, no environment's images, replicas, resources "
                    "or storage",) if unplaced else ()),
                 *(n for _, ns in jobs for n in ns), *gateway_notices,
                 *(f"not YAML or JSON, not read: {p}" for p, o in found if o is None),
                 *(("no workloads (StatefulSets, Deployments, DaemonSets, CronJobs) in the manifests",)
                   if not workloads and not cron and not gateways else ())))


WORKLOADS_IMPORTER = Importer("workloads", "Kubernetes manifests (kubectl get -o yaml/json, rendered Helm or "
                                           "Kustomize output) as workloads and their CronJobs as jobs",
                               read_workloads)

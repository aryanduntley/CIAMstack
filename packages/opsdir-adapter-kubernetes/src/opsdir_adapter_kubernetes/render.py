"""Kubernetes adapter, rendering: what every workload an environment runs on Kubernetes needs around it, whatever kit
deploys it (ForgeOps, ping-devops, plain manifests). Pure.

For an environment that runs workloads on Kubernetes (their workload bindings), one folder per namespace,
kubernetes/<namespace>/, a kustomization of:

  namespace.yaml               the namespace, with the most permissive pod-security level its workloads record
  serviceaccounts.yaml         each workload's service account, annotated with the cloud identity it assumes (the
                               provider adapter's workload identity for the environment's identity binding)
  networkpolicies.yaml         a default deny of ingress, and per workload what its pods listen on (its deployment
                               kit's container ports, else its products' listeners): client and admin ports from
                               anywhere, its peers and the other server roles by the pod label
                               opsdir.io/role when they run on Kubernetes here, by their servers' subnets otherwise.
                               The deployment kit labels each pod with opsdir.io/role
  externalsecrets.yaml         (target external-secrets) a SecretStore per secret store, scheme and service account,
                               and an ExternalSecret per Secret filling its keys from the record's references
  secretproviderclasses.yaml   (target csi) a SecretProviderClass per workload and secret store, syncing the Secrets
                               the workload reads (while a pod mounts it: a kit that can mounts it in the workload's
                               pods, Adapter.mounts_secrets; mounted_classes names them)
  secretsync.yaml              (target csi) for the workloads no kit mounts (and the cluster gateways), a sync pod per
                               service account: a Deployment of the pause image running as that account (its cloud
                               identity) and mounting its classes, so the driver keeps their Secrets (the pattern
                               opsdir/scripts/validate-csi-sync.sh validates on a local cluster)
  secrets-required.yaml        not a Kubernetes object: every Secret key the workloads read, the role and reference
                               that fill it, and what delivers it (or that the operator creates it)

How a reference is read is the adapter's that owns its scheme (Services.secret_delivery); a scheme none delivers is
named for the operator. Values the record can't give are written UNBOUND:<what>. Under csi its render notes (notes)
name a Secret filled from several stores (each class syncs it on its own) and, until the environment records
ciamConfigurationMet csi-provider-identity, that its sync pods rely on its cloud's CSI provider reading the stores as
their identity, which only that cloud can show.
"""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, one_role, secret, servers_with_role
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import documents, dump
from opsdir.core.manifest import header
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.compute.workloads import (namespace_of, service_account_of, workload_binding,
                                              workload_secrets, workloads)
from opsdir.domains.network.ports import pod_listeners, role_cidrs
from opsdir.domains.pki.credentials import secret_store, split_ref
from .gateway import cluster_gateways, gateway_docs, gateway_namespace, route_docs
from .names import MANAGED_BY, NAME, k8s_name

ROLE_LABEL = "opsdir.io/role"
LEVELS = ("privileged", "baseline", "restricted")
EXTERNAL_SECRETS, CSI = "external-secrets", "csi"
TARGETS = ((EXTERNAL_SECRETS, "External Secrets Operator SecretStores and ExternalSecrets filling the Secrets the "
                              "workloads read from the record's references", False),
           (CSI, "Secrets Store CSI driver SecretProviderClasses syncing those Secrets (pods mount them)", False))
PROTOCOLS = ("TCP", "UDP", "SCTP")
SYNC_IMAGE = "registry.k8s.io/pause:3.10.2"    # the current pause image; runs as 65535:65535 and only holds the mounts
SYNC_LABEL = "opsdir.io/secret-sync"            # a sync pod's label: the service account it syncs for
MOUNTS = "/run/secrets"                         # where a pod mounts each class: <MOUNTS>/<class>
MET = "csi-provider-identity"                   # what the environment records once its cloud's provider is checked
RESTRICTED = {"runAsNonRoot": True, "runAsUser": 65535, "allowPrivilegeEscalation": False,
              "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]},
              "seccompProfile": {"type": "RuntimeDefault"}}


def on_kubernetes(m):
    """The workloads environment m runs on Kubernetes (those it has a workload binding for)."""
    return tuple(w for w in workloads(m.d) if workload_binding(m, w) is not None)


def applies(m):
    """Whether environment m runs any workload on Kubernetes."""
    return bool(on_kubernetes(m))


def _level(ws):
    levels = [v.split("=", 1)[1] for w in ws for v in values(w, "ciamPodSecurity") if v.startswith("level=")]
    known = [x for x in levels if x in LEVELS]
    return min(known, key=LEVELS.index) if known else None


def namespace_doc(ns, ws):
    """The Namespace, labelled with the most permissive pod-security level its workloads record."""
    level = _level(ws)
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": ns, **({"labels": {"pod-security.kubernetes.io/enforce": level}} if level else {})}}


def identity_binding(m, w):
    """Environment m's identity binding of the identity role a workload assumes, or None."""
    return one_role(m, one(w, "ciamIdentityRole")) if one(w, "ciamIdentityRole") else None


def _annotations(m, services, ws):
    found = [services.workload_identity(m, b) for w in ws for b in (identity_binding(m, w),) if b is not None]
    return dict(next((i.annotations for i in found if i), ()))


def service_account_docs(m, services, ns, ws):
    """A ServiceAccount per account the namespace's workloads run as, with its cloud identity's annotations."""
    accounts = dict.fromkeys(service_account_of(w) for w in ws)
    return [{"apiVersion": "v1", "kind": "ServiceAccount",
             "metadata": {"name": sa, "namespace": ns, **({"annotations": a} if a else {})}}
            for sa in accounts for a in (_annotations(m, services, [w for w in ws if service_account_of(w) == sa]),)]


def _port(listener):
    lo, _, hi = str(listener.port).partition("-")
    protocol = (listener.protocol or "tcp").upper()
    return {"port": int(lo), **({"endPort": int(hi)} if hi else {}),
            "protocol": protocol if protocol in PROTOCOLS else "TCP"}


def _sources(m, here, peer, own):
    """Where a listener's traffic from one kind of peer comes from: pods of a role running here, else its servers'
    subnets; [] for none."""
    role = own if peer == "peers" else peer
    if any(one(w, "ciamTargetRole") == role for w in here):
        return [{"namespaceSelector": {}, "podSelector": {"matchLabels": {ROLE_LABEL: role}}}]
    return [{"ipBlock": {"cidr": c}} for c in (role_cidrs(m, role) if servers_with_role(m, role) else ())]


def policy_doc(m, listeners, here, ns, w):
    """The NetworkPolicy admitting what a workload's pods listen for (its deployment kit's container ports, else its
    products' listeners): clients and admin from anywhere, peers and other server roles from where they run."""
    role = one(w, "ciamTargetRole")
    rules = []
    for listener in pod_listeners(listeners, role):
        anyone = any(p in ("clients", "admin") for p in listener.peers)
        froms = [] if anyone else [s for p in listener.peers for s in _sources(m, here, p, role)]
        rules += [{**({"from": froms} if froms else {}), "ports": [_port(listener)]}] if anyone or froms else []
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": f"{k8s_name(rdn_value(w))}-ingress", "namespace": ns,
                         "labels": {MANAGED_BY[0]: MANAGED_BY[1]}},
            "spec": {"podSelector": {"matchLabels": {ROLE_LABEL: role}}, "policyTypes": ["Ingress"],
                     "ingress": rules}}


def network_policy_docs(m, listeners, here, ns, ws):
    """The namespace's default deny of ingress, then one policy per workload, each marked as opsdir's (MANAGED_BY)."""
    deny = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny-ingress", "namespace": ns, "labels": {MANAGED_BY[0]: MANAGED_BY[1]}},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}}
    return [deny, *(policy_doc(m, listeners, here, ns, w) for w in ws)]


def secret_items(m, ws):
    """(workload, Secret, key, role, ref-uri or None) for every Secret key the workloads read."""
    return [(w, s, k, r, secret(m, r)) for w in ws for s, k, r in workload_secrets(w)]


def _delivery(services, uri):
    scheme, rest = split_ref(uri)
    return scheme, rest, (services.secret_delivery(scheme) if uri else None)


def _delivered_by(services, targets, ns, s, k, uri):
    scheme, rest, d = _delivery(services, uri)
    if not uri:
        return "nothing: the environment binds no secret for the role"
    if scheme == "k8s-secret" and rest == f"{ns}/{s}/{k}":
        return "it is the Kubernetes Secret itself"
    if d and EXTERNAL_SECRETS in targets:
        return f"ExternalSecret (externalsecrets.yaml, provider {scheme})"
    if d and CSI in targets:
        return (f"SecretProviderClass (secretproviderclasses.yaml, provider {d.csi_provider}), synced while a pod "
                "mounts it: the deployment kit's, else a sync pod (secretsync.yaml)")
    return ("you: create it (render with --target kubernetes=external-secrets or csi to have it delivered)" if d
            else f"you: create it (no installed adapter delivers {scheme}:// references to Kubernetes)")


def required_doc(m, services, targets, ns, items):
    """Every Secret key the namespace's workloads read, the role and reference that fill it, and what delivers it."""
    keys = {}
    for w, s, k, r, uri in items:
        keys.setdefault(s, {}).setdefault(k, {"key": k, "role": r, "ref": uri or f"{UNBOUND}{r}",
                                               "delivered by": _delivered_by(services, targets, ns, s, k, uri),
                                               "read by": []})["read by"].append(rdn_value(w))
    return {"environment": m.label, "namespace": ns,
            "secrets": [{"name": s, "keys": list(ks.values())} for s, ks in keys.items()]}


def _store_name(scheme, key, sa):
    return k8s_name("-".join(x for x in (scheme, key, sa) if x))


def external_secret_docs(m, services, ns, items):
    """SecretStores (one per scheme, store and service account) and ExternalSecrets (one per Secret and store: the
    first owns the Secret, the others merge into it) for every key a delivering adapter can read."""
    rows = [(w, s, k, scheme, rest, d) for w, s, k, r, uri in items if uri
            for scheme, rest, d in (_delivery(services, uri),) if d]
    stores, groups = {}, {}
    for w, s, k, scheme, rest, d in rows:
        key, sa = d.store_key(rest), service_account_of(w)
        name = _store_name(scheme, key, sa)
        stores.setdefault(name, {"apiVersion": "external-secrets.io/v1", "kind": "SecretStore",
                                 "metadata": {"name": name, "namespace": ns},
                                 "spec": {"provider": d.eso_provider(m, secret_store(m, scheme), key, sa,
                                                                     one_role(m, one(w, "ciamClusterRole") or ""))}})
        groups.setdefault(s, {}).setdefault(name, {}).setdefault(k, d.eso_ref(rest))
    secrets = [{"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret",
                "metadata": {"name": s if i == 0 else k8s_name(f"{s}-{store}"), "namespace": ns},
                "spec": {"refreshInterval": "1h", "secretStoreRef": {"kind": "SecretStore", "name": store},
                         "target": {"name": s, "creationPolicy": "Owner" if i == 0 else "Merge"},
                         "data": [{"secretKey": k, "remoteRef": ref} for k, ref in data.items()]}}
               for s, by_store in groups.items() for i, (store, data) in enumerate(by_store.items())]
    return [*stores.values(), *secrets]


def class_name(w, scheme, key):
    """The name of the SecretProviderClass of a workload and secret store (scheme, store key)."""
    return k8s_name(f"{rdn_value(w)}-{scheme}-{key}")


def workload_classes(m, services, w):
    """The SecretProviderClasses the csi target renders for a workload (or cluster gateway): one per secret store its
    Secrets are read from, in order."""
    return tuple(dict.fromkeys(class_name(w, scheme, d.store_key(rest)) for _, _, _, _, uri in secret_items(m, [w])
                               if uri for scheme, rest, d in (_delivery(services, uri),) if d))


def mounted_classes(m, services, w):
    """The classes a deployment kit mounts in a workload's pods in this render: workload_classes when this adapter
    renders csi (Services.render_targets), else ()."""
    return workload_classes(m, services, w) if CSI in services.render_targets(NAME) else ()


def class_mount(name):
    """(volume, volume mount) of a SecretProviderClass in a pod: read-only, at <MOUNTS>/<class>."""
    return ({"name": name, "csi": {"driver": "secrets-store.csi.k8s.io", "readOnly": True,
                                   "volumeAttributes": {"secretProviderClass": name}}},
            {"name": name, "mountPath": f"{MOUNTS}/{name}", "readOnly": True})


def unmounted(m, services, ws):
    """The workloads (and gateways) with classes that no deployment kit mounts (Services.mounts_secrets)."""
    return tuple(w for w in ws if workload_classes(m, services, w) and not services.mounts_secrets(m, w))


def _identity_labels(m, services, ws):
    found = [services.workload_identity(m, b) for w in ws for b in (identity_binding(m, w),) if b is not None]
    return dict(next((i.pod_labels for i in found if i), ()))


def sync_deployment(ns, sa, classes, pod_labels=None):
    """A sync pod as a Deployment, from plain values (what opsdir/scripts/validate-csi-sync.sh deploys too): one
    replica of the pause image running as service account sa with no token mounted, its pods labelled pod_labels
    (the cloud identity's), restricted, mounting each class read-only so the driver keeps its Secrets."""
    mounts = [class_mount(c) for c in classes]
    labels = {SYNC_LABEL: sa}
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": k8s_name(f"{sa}-secret-sync"), "namespace": ns,
                         "labels": {MANAGED_BY[0]: MANAGED_BY[1], **labels}},
            "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                     "template": {"metadata": {"labels": {**labels, **(pod_labels or {})}},
                                  "spec": {"serviceAccountName": sa, "automountServiceAccountToken": False,
                                           "containers": [{"name": "sync", "image": SYNC_IMAGE,
                                                           "resources": {"requests": {"cpu": "1m", "memory": "4Mi"},
                                                                         "limits": {"memory": "16Mi"}},
                                                           "securityContext": RESTRICTED,
                                                           "volumeMounts": [mt for _, mt in mounts]}],
                                           "volumes": [v for v, _ in mounts]}}}}


def sync_pod_doc(m, services, ns, sa, ws):
    """The sync pod of service account sa for the workloads ws: sync_deployment of their classes, with their cloud
    identity's pod labels."""
    return sync_deployment(ns, sa, tuple(dict.fromkeys(c for w in ws for c in workload_classes(m, services, w))),
                           _identity_labels(m, services, ws))


def sync_pod_docs(m, services, ns, ws):
    """A sync pod per service account of the workloads no kit mounts."""
    left = unmounted(m, services, ws)
    return [sync_pod_doc(m, services, ns, sa, [w for w in left if service_account_of(w) == sa])
            for sa in dict.fromkeys(service_account_of(w) for w in left)]


def csi_notes(m, services, ns, ws):
    """(notes on secretproviderclasses.yaml, notes on secretsync.yaml) of a namespace under csi: each Secret filled
    from several stores; the sync pods' reliance on the cloud's provider identity until the environment records it."""
    stores = {}
    for w, s, k, r, uri in secret_items(m, ws):
        scheme, rest, d = _delivery(services, uri) if uri else ("", "", None)
        if d:
            stores.setdefault(s, {})[(scheme, d.store_key(rest))] = rdn_value(w)
    split = tuple(note("Secrets", "action", f"Secret `{s}` in namespace `{ns}`",
                       f"its keys come from {len(found)} secret stores ({', '.join(f'{a}:{b}' for a, b in found)}): "
                       "each SecretProviderClass syncs the Secret on its own and the CSI driver documents nothing for "
                       "two classes writing one Secret",
                       ("Fill the Secret's keys from one secret store", "or deliver it with --target "
                        "kubernetes=external-secrets, which merges them"))
                  for s, found in stores.items() if len(found) > 1)
    left = unmounted(m, services, ws)
    identity = (note("Secrets", "action", f"secret sync pods in namespace `{ns}`",
                     f"the Secrets of {', '.join(rdn_value(w) for w in left)} reach their pods through sync pods, "
                     "which rely on this cloud's Secrets Store CSI provider reading the secret stores as each pod's "
                     "service account (its workload identity): validated on a local cluster "
                     "(opsdir/scripts/validate-csi-sync.sh), not yet in this cloud",
                     ("In a non-production cluster of this cloud, check: a sync pod mounts its class and the Secret "
                      "appears; a pod of another service account is refused; a changed value reaches the Secret; "
                      "deleting the sync pod deletes the Secret",
                      f"Record ciamConfigurationMet: {MET} on the environment {RECORD}"), m.env.dn),) \
        if left and MET not in values(m.env, "ciamConfigurationMet") else ()
    return split, identity


def _comments(notes):
    return "".join(f"# {note_comment(n)}\n" for n in notes)


def provider_class_docs(m, services, ns, items):
    """A SecretProviderClass per workload and secret store, its objects aliased <secret>-<key> and synced into the
    Secrets the workload reads."""
    groups = {}
    for w, s, k, r, uri in items:
        scheme, rest, d = _delivery(services, uri) if uri else ("", "", None)
        if d:
            group = groups.setdefault((rdn_value(w), scheme, d.store_key(rest)), {"w": w, "d": d, "objects": {}})
            group["objects"][(s, k)] = rest
    return [{"apiVersion": "secrets-store.csi.x-k8s.io/v1", "kind": "SecretProviderClass",
             "metadata": {"name": class_name(g["w"], scheme, key), "namespace": ns},
             "spec": {"provider": g["d"].csi_provider,
                      "parameters": g["d"].csi_parameters(
                          m, secret_store(m, scheme), key,
                          tuple((k8s_name(f"{s}-{k}"), rest) for (s, k), rest in g["objects"].items()),
                          identity_binding(m, g["w"])),
                      "secretObjects": [{"secretName": s, "type": "Opaque",
                                         "data": [{"objectName": k8s_name(f"{s}-{k}"), "key": k}
                                                  for (s2, k) in g["objects"] if s2 == s]}
                                        for s in dict.fromkeys(s for s, _ in g["objects"])]}}
            for (name, scheme, key), g in groups.items()]


def _file(m, what, body, notes=()):
    return header(m, what, YAML) + _comments(notes) + body


def namespace_files(m, services, targets, listeners, here, ns, ws, gateways=(), extra=()):
    """{path: text} of one namespace's folder: its workloads' (ws), and the cluster gateways in it (their Secrets and
    service accounts like a workload's; extra: ((file, what, objects), ...) the gateway module renders here)."""
    base = f"kubernetes/{ns}"
    items = secret_items(m, (*ws, *gateways))
    split, identity = csi_notes(m, services, ns, (*ws, *gateways)) if CSI in targets else ((), ())
    file_notes = {"secretproviderclasses.yaml": split, "secretsync.yaml": identity}
    objects = {
        "namespace.yaml": ("The namespace", [namespace_doc(ns, ws)]),
        "serviceaccounts.yaml": ("Service accounts and the cloud identities they assume",
                                 service_account_docs(m, services, ns, (*ws, *gateways))),
        "networkpolicies.yaml": ("Network policies from the products' listeners",
                                 network_policy_docs(m, listeners, here, ns, ws)),
        **({"externalsecrets.yaml": ("External Secrets Operator stores and secrets",
                                     external_secret_docs(m, services, ns, items))}
           if EXTERNAL_SECRETS in targets and items else {}),
        **({"secretproviderclasses.yaml": ("Secrets Store CSI driver provider classes",
                                           provider_class_docs(m, services, ns, items)),
            "secretsync.yaml": ("Pods keeping the CSI-synced Secrets of the workloads no deployment kit mounts",
                                sync_pod_docs(m, services, ns, (*ws, *gateways)))}
           if CSI in targets and items else {}),
        **{f: (what, list(docs)) for f, what, docs in extra}}
    kept = {f: (what, docs) for f, (what, docs) in objects.items() if docs}
    kustomization = {"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization", "resources": list(kept)}
    return {**{f"{base}/{f}": _file(m, what, documents(docs), file_notes.get(f, ()))
               for f, (what, docs) in kept.items()},
            f"{base}/kustomization.yaml": _file(m, "The namespace's resources", dump(kustomization)),
            **({f"{base}/secrets-required.yaml": _file(m, "The Secrets the workloads read and what delivers them "
                                                        "(not a Kubernetes object)",
                                                        dump(required_doc(m, services, targets, ns, items)))}
               if items else {})}


def _gateway_objects(m, services):
    """({namespace: ((file, what, objects), ...)}, {namespace: gateways}): what the cluster gateways render where (a
    gateway's own objects in its namespace, its routes in each fronted role's)."""
    files, readers = {}, {}
    for gw in cluster_gateways(m):
        ns, docs = gateway_namespace(m, gw), gateway_docs(m, services, gw)
        if docs:
            what = "The in-cluster gateway behind the cloud's front"
            files.setdefault((ns, "gateway.yaml"), (what, []))[1].extend(docs)
            readers.setdefault(ns, []).append(gw)
        for rns, rdocs in route_docs(m, services, gw).items():
            what = "The service names' routes through the gateway"
            files.setdefault((rns, "routes.yaml"), (what, []))[1].extend(rdocs)
    extra = {}
    for (ns, f), (what, docs) in files.items():
        extra.setdefault(ns, []).append((f, what, tuple(docs)))
    return extra, readers


def _namespaces(m, services):
    """{namespace: (workloads, cluster gateways reading Secrets there)} of what environment m runs on Kubernetes, and
    the gateway objects per namespace."""
    here = on_kubernetes(m)
    extra, readers = _gateway_objects(m, services)
    spaces = dict.fromkeys((*(namespace_of(w) for w in here), *extra))
    return {ns: ([w for w in here if namespace_of(w) == ns], readers.get(ns, ())) for ns in spaces}, extra


def notes(m, services):
    """Adapter.notes: under csi (Services.render_targets), each namespace's csi_notes."""
    if CSI not in services.render_targets(NAME):
        return ()
    spaces, _ = _namespaces(m, services)
    return tuple(n for ns, (ws, gws) in spaces.items() for group in csi_notes(m, services, ns, (*ws, *gws))
                 for n in group)


def render(m, services, targets=()):
    """{path: text}: a folder per namespace of the workloads environment m runs on Kubernetes, and of the in-cluster
    gateways it records (gateway.py)."""
    here = on_kubernetes(m)
    listeners = services.listeners(m)
    spaces, extra = _namespaces(m, services)
    return {p: text for ns, (ws, gws) in spaces.items()
            for p, text in namespace_files(m, services, targets, listeners, here, ns, ws, gws,
                                           extra.get(ns, ())).items()}

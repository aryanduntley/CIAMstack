"""The ping-devops values that make PingFederate's log files their own containers' output (user decision 2348): for each
file an environment's log routes pick (logs.SIDECAR_FILES), a sidecar tailing it, so a collector tells the files
apart by container name. Pure.

As the pinned chart reads them (tools/ping-devops/0.16.0: templates/pinglib/_workload.tpl): a sidecar is defined
under the top-level sidecars (rendered as `- name: <key>` and its definition) and included by its product's
includeSidecars; a volume likewise under volumes and includeVolumes; a product's volumeMounts are its main
container's. The sidecar runs the product's own image (nothing else to pull), `tail -n +1 -F` on the file (waiting
for it, following it across rotation), with out-dir mounted read-only at /pf-out, small resources and no privilege
escalation. A StatefulSet's out-dir is the chart's persistent volume at /opt/out. A Deployment's /opt/out is the
container's own, so out-dir is an emptyDir mounted there: at /opt/out, never at /opt/out/instance/log (the image's
start hooks take an existing server root for a restart, and kubelet would create it for that mount).
"""
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.sources import shipments
from .logs import LOGS, OUT_DIR, SIDECAR_FILES

OUT_VOLUME, MOUNT = "out-dir", "/pf-out"
RESOURCES = {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"memory": "64Mi"}}
SECURITY = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}


def picked(m, role):
    """((sidecar container, path under the server root), ...) of a role's files environment m's log routes pick (from
    this kit's own declarations), in declaration order."""
    wanted = {x.source.container for x in shipments(m, log_routes(m.d), LOGS)
              if x.on == "kubernetes" and x.role == role and x.source.container}
    return tuple((c, path) for r, c, path, _ in SIDECAR_FILES if r == role and c in wanted)


def sidecar(image, path):
    """A sidecar definition tailing a file under the server root (the chart adds its name)."""
    return {"image": image, "command": ["tail"], "args": ["-n", "+1", "-F", f"{MOUNT}/instance/{path}"],
            "volumeMounts": [{"name": OUT_VOLUME, "mountPath": MOUNT, "readOnly": True}],
            "resources": RESOURCES, "securityContext": SECURITY}


def product_logs(found, stateful):
    """A product's values for its sidecars: includeSidecars, and for a Deployment out-dir mounted at /opt/out."""
    if not found:
        return {}
    return {"includeSidecars": [c for c, _ in found],
            **({} if stateful else {"includeVolumes": [OUT_VOLUME],
                                    "volumeMounts": [{"name": OUT_VOLUME, "mountPath": OUT_DIR}]})}


def shared_logs(products):
    """The top-level values: sidecars ((image, ((container, path), ...), stateful) per product) and, when a Deployment
    has any, the out-dir emptyDir."""
    return {**({"sidecars": {c: sidecar(image, path) for image, found, _ in products for c, path in found}}
               if any(found for _, found, _ in products) else {}),
            **({"volumes": {OUT_VOLUME: {"emptyDir": {}}}}
               if any(found and not stateful for _, found, stateful in products) else {})}

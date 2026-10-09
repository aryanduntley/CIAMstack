"""ForgeOps adapter, rendering: per namespace of the workloads an environment runs with ForgeOps, Helm values for its
charts (target helm) and an overlay in its Kustomize layout (target kustomize); both by default, as `forgeops env`
writes both. What surrounds the workloads (namespace, service accounts, network policies, Secret delivery) is the
kubernetes adapter's. Pure.
"""
from .components import placements
from .helm import helm_files
from .kustomize import kustomize_files
from .release import HELM, KUSTOMIZE, VERSION

TARGETS = ((HELM, f"Helm values for ForgeOps {VERSION}'s identity-platform and ping-gateway charts"),
           (KUSTOMIZE, f"a Kustomize overlay in ForgeOps {VERSION}'s layout (copied into a checkout's "
                       "kustomize/overlay/)"))


def applies(m):
    """Whether environment m runs any workload with ForgeOps."""
    return bool(placements(m))


def render(m, services, targets=(HELM, KUSTOMIZE)):
    """{path: text}: per namespace, the Helm values and/or the Kustomize overlay of the render targets chosen."""
    parts = ((HELM, helm_files), (KUSTOMIZE, kustomize_files))
    return {path: text for p in placements(m) for target, files in parts if target in targets
            for path, text in files(m, services, p).items()}

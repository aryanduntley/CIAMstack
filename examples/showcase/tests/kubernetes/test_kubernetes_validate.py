"""The showcase's golden Kubernetes output checked by the real tools (opsdir/scripts/validate-kubernetes.sh: kustomize
build, helm template, kubeconform -strict), with the deployment kits' own sources: each render's kubernetes/ folders as
they are, its ForgeOps overlay built inside the pinned ForgeOps release's bases, and each Helm values file rendered with
its chart (ForgeOps' identity-platform and ping-gateway, Ping's ping-devops). Runs with the local tools
(opsdir/scripts/fetch-tools.sh) and the kits' sources (fetch-forgeops.sh, fetch-ping-devops.sh); skipped without
them."""
import pathlib
import shutil
import subprocess

import pytest

from opsdir_adapter_forgeops import release as forgeops
from opsdir_adapter_ping_devops import release as ping_devops

ROOT = pathlib.Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "opsdir" / "scripts" / "validate-kubernetes.sh"
GOLDEN = ROOT / "examples" / "showcase" / "golden"
FORGEOPS = ROOT / "tools" / "forgeops" / forgeops.VERSION
PING_DEVOPS = ROOT / "tools" / "ping-devops" / ping_devops.VERSION / ping_devops.CHART
pytestmark = [pytest.mark.kubernetes,
              pytest.mark.skipif(not (ROOT / "tools" / "bin" / "kubeconform").exists()
                                 or not (FORGEOPS / ".complete").exists()
                                 or not (PING_DEVOPS.parent / ".complete").exists(),
                                 reason="no tools (opsdir/scripts/fetch-tools.sh) or kit sources (fetch-forgeops.sh, "
                                        "fetch-ping-devops.sh)")]


def _charts(render):
    """--helm pairs for every values file a render holds, each with its kit's chart."""
    found = [(FORGEOPS / "charts" / f.name.removesuffix("-values.yaml"), f)
             for f in sorted(render.glob("forgeops/helm/*/*-values.yaml"))]
    found += [(PING_DEVOPS, f) for f in sorted(render.glob(f"{ping_devops.CHART}/helm/*/*-values.yaml"))]
    return [x for chart, values in found for x in ("--helm", str(chart), str(values))]


def _overlays(render, tmp_path):
    """The render's ForgeOps overlays copied next to the release's bases, as they are used in a ForgeOps checkout."""
    if not (render / "forgeops" / "kustomize" / "overlay").exists():
        return []
    shutil.copytree(FORGEOPS / "kustomize" / "base", tmp_path / "kustomize" / "base")
    shutil.copytree(render / "forgeops" / "kustomize" / "overlay", tmp_path / "kustomize" / "overlay")
    return [str(tmp_path / "kustomize" / "overlay")]


@pytest.mark.parametrize("render", sorted(p.relative_to(GOLDEN) for p in GOLDEN.glob("render-*/*")
                                          if (p / "kubernetes").exists()), ids=str)
def test_the_showcase_kubernetes_output_is_valid(tmp_path, render):
    path = GOLDEN / render
    done = subprocess.run([str(SCRIPT), *_charts(path), str(path / "kubernetes"), *_overlays(path, tmp_path)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "checked sets valid" in done.stdout

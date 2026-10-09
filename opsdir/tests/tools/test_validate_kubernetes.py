"""opsdir/scripts/validate-kubernetes.sh, the check every Kubernetes renderer's output goes through: plain manifests,
kustomizations (built first) and Helm charts with values files (rendered first) are checked by kubeconform against
the Kubernetes schemas and the pinned CRDs-catalog; a resource no schema describes fails instead of passing. Runs with
the local tools (opsdir/scripts/fetch-tools.sh); skipped without them. The first run needs network access for the
schemas, cached in tools/ after that."""
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "opsdir" / "scripts" / "validate-kubernetes.sh"
pytestmark = [pytest.mark.kubernetes,
              pytest.mark.skipif(not all((ROOT / "tools" / "bin" / t).exists() for t in ("kustomize", "kubeconform",
                                                                                         "helm")),
                                 reason="no kustomize/kubeconform/helm in tools/bin (opsdir/scripts/fetch-tools.sh)")]

NAMESPACE = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: identity\n"
DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: am
spec:
  replicas: 2
  selector:
    matchLabels:
      app: am
  template:
    metadata:
      labels:
        app: am
    spec:
      containers:
      - name: am
        image: registry.example.test/am:8.0.1
"""
EXTERNAL_SECRET = """apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: am-passwords
spec:
  secretStoreRef:
    name: vault
    kind: SecretStore
  target:
    name: am-passwords
  data:
  - secretKey: admin
    remoteRef:
      key: ciam/am/admin
"""
WIDGET = "apiVersion: example.test/v1\nkind: Widget\nmetadata:\n  name: w\n"


def _run(*args):
    done = subprocess.run([str(SCRIPT), *map(str, args)], capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def _write(base, files):
    for rel, text in files.items():
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text(text)
    return base


def test_manifests_and_kustomizations_pass(tmp_path):
    tree = _write(tmp_path, {"plain/namespace.yaml": NAMESPACE, "plain/values.yaml": "replicas: 3\n",
                             "kz/kustomization.yaml": "resources:\n- deployment.yaml\n- secret.yaml\n",
                             "kz/deployment.yaml": DEPLOYMENT, "kz/secret.yaml": EXTERNAL_SECRET})
    code, out = _run(tree)
    assert code == 0, out
    assert "ok      " in out and "(kustomize build)" in out and "all 2 checked sets valid" in out
    assert "values.yaml" not in out                     # Helm values aren't Kubernetes objects


def test_a_resource_no_schema_describes_fails(tmp_path):
    code, out = _run(_write(tmp_path, {"widget.yaml": WIDGET}))
    assert code == 1 and "FAILED" in out and "Widget" in out


def test_a_broken_kustomization_fails(tmp_path):
    code, out = _run(_write(tmp_path, {"kz/kustomization.yaml": "resources:\n- missing.yaml\n"}))
    assert code == 1 and "(kustomize build)" in out


def test_a_chart_is_rendered_with_its_values_and_checked(tmp_path):
    chart = _write(tmp_path / "chart", {"Chart.yaml": "apiVersion: v2\nname: sample\nversion: 0.1.0\n",
                                        "templates/deployment.yaml": DEPLOYMENT.replace("replicas: 2",
                                                                                        "replicas: {{ .Values.replicas }}")})
    values = _write(tmp_path / "render", {"values.yaml": "replicas: 3\n"}) / "values.yaml"
    code, out = _run("--helm", chart, values, tmp_path / "render")
    assert code == 0 and "helm template" in out, out
    values.write_text("replicas: three\n")
    code, out = _run("--helm", chart, values, tmp_path / "render")
    assert code == 1 and "FAILED  helm template" in out


def test_nothing_to_check_is_not_a_failure(tmp_path):
    assert _run(_write(tmp_path, {"README.txt": "no manifests\n"})) == (0, "nothing to check\n")

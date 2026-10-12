"""The showcase's Azure environment rendered as Bicep and ARM JSON (the azure render targets bicep and arm), before and
after the approved changes, checked by the pinned Bicep CLI (tools/bin/bicep, opsdir/scripts/fetch-tools.sh; skipped
without it): every Bicep file builds and lints without an error, and builds to the ARM JSON file rendered beside it
(but for Bicep's generator stamp): the two targets are one deployment. Warnings (the record's literal admin user name,
say) don't fail."""
import json
import subprocess
from pathlib import Path

import pytest

from opsdir.connectors.render import render_env

ROOT = Path(__file__).resolve().parents[4]
BICEP = ROOT / "tools" / "bin" / "bicep"
pytestmark = [pytest.mark.bicep,
              pytest.mark.skipif(not BICEP.exists(), reason="no tools/bin/bicep (opsdir/scripts/fetch-tools.sh)")]


def _built(path):
    done = subprocess.run([str(BICEP), "build", str(path), "--stdout"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    doc = json.loads(done.stdout)
    doc["metadata"].pop("_generator")
    return {k: v for k, v in doc.items() if k != "metadata" or v}


@pytest.mark.parametrize("state", ["before", "after"])
def test_the_showcase_bicep_builds_to_its_arm_json_and_lints_clean(estate, tmp_path, state):
    _, files = render_env(estate[state], "target/prod", wanted={"azure": ("bicep", "arm")})
    bicep = {p: text for p, text in files.items() if p.endswith(".bicep")}
    assert len(bicep) >= 5
    for p, text in bicep.items():
        path = tmp_path / p
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        assert _built(path) == json.loads(files["arm/" + p[len("bicep/"):-len(".bicep")] + ".json"]), p
        lint = subprocess.run([str(BICEP), "lint", str(path)], capture_output=True, text=True)
        assert lint.returncode == 0 and " Error " not in lint.stderr, (p, lint.stderr)

"""The two writers give one deployment: `bicep build` (the pinned Bicep CLI, tools/bin/bicep from
opsdir/scripts/fetch-tools.sh) of the Bicep file is the ARM JSON writer's template, but for Bicep's generator stamp;
and `bicep lint` finds no error in it."""
import json
import subprocess
from pathlib import Path

import pytest

from opsdir_format_arm.arm_json import template_doc
from opsdir_format_arm.bicep import as_bicep
from arm_samples import PLATFORM, SUBSCRIPTION

ROOT = Path(__file__).resolve().parents[3]
BICEP = ROOT / "tools" / "bin" / "bicep"
pytestmark = [pytest.mark.bicep,
              pytest.mark.skipif(not BICEP.exists(), reason="no tools/bin/bicep (opsdir/scripts/fetch-tools.sh)")]


def _built(path):
    done = subprocess.run([str(BICEP), "build", str(path), "--stdout"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    doc = json.loads(done.stdout)
    doc["metadata"].pop("_generator")
    return {k: v for k, v in doc.items() if k != "metadata" or v}


@pytest.mark.parametrize("template", [PLATFORM, SUBSCRIPTION], ids=["resource-group", "subscription"])
def test_bicep_builds_the_arm_json_writers_template(tmp_path, template):
    path = tmp_path / "main.bicep"
    path.write_text(as_bicep(template))
    assert _built(path) == template_doc(template)
    lint = subprocess.run([str(BICEP), "lint", str(path)], capture_output=True, text=True)
    assert lint.returncode == 0, lint.stdout + lint.stderr

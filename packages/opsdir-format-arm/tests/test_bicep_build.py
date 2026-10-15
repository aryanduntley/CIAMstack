"""The two writers give one deployment: `bicep build` (the pinned Bicep CLI, tools/bin/bicep from
opsdir/scripts/fetch-tools.sh) of the Bicep file is the ARM JSON writer's template, but for Bicep's generator stamps
(the template's and each module's: Bicep's own hash); and `bicep lint` finds no error in it. A template with modules
is written with its modules' files beside it."""
import json
import subprocess
from pathlib import Path

import pytest

from opsdir_format_arm.arm_json import template_doc
from opsdir_format_arm.bicep import as_bicep, bicep_files
from arm_samples import PLATFORM, SUBSCRIPTION

ROOT = Path(__file__).resolve().parents[3]
BICEP = ROOT / "tools" / "bin" / "bicep"
pytestmark = [pytest.mark.bicep,
              pytest.mark.skipif(not BICEP.exists(), reason="no tools/bin/bicep (opsdir/scripts/fetch-tools.sh)")]


def unstamped(doc):
    """A built template without Bicep's generator stamps, at every level (a module's template has its own)."""
    if isinstance(doc, list):
        return [unstamped(x) for x in doc]
    if not isinstance(doc, dict):
        return doc
    meta = {k: v for k, v in (doc.get("metadata") or {}).items() if k != "_generator"} \
        if isinstance(doc.get("metadata"), dict) else doc.get("metadata")
    return {k: unstamped(v) for k, v in {**doc, "metadata": meta}.items() if k != "metadata" or v}


def _built(path):
    done = subprocess.run([str(BICEP), "build", str(path), "--stdout"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return unstamped(json.loads(done.stdout))


@pytest.mark.parametrize("template", [PLATFORM, SUBSCRIPTION], ids=["resource-group", "subscription"])
def test_bicep_builds_the_arm_json_writers_template(tmp_path, template):
    path = tmp_path / "main.bicep"
    path.write_text(as_bicep(template))
    assert _built(path) == template_doc(template)
    lint = subprocess.run([str(BICEP), "lint", str(path)], capture_output=True, text=True)
    assert lint.returncode == 0, lint.stdout + lint.stderr


def test_bicep_builds_a_template_with_modules_from_their_shared_file(tmp_path, module_sample):
    for p, text in bicep_files(module_sample.MODULES, "main.bicep").items():
        (tmp_path / p).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / p).write_text(text)
    assert _built(tmp_path / "main.bicep") == template_doc(module_sample.MODULES)
    lint = subprocess.run([str(BICEP), "lint", str(tmp_path / "main.bicep")], capture_output=True, text=True)
    assert lint.returncode == 0, lint.stdout + lint.stderr

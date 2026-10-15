"""What the writers write is valid OSCAL: each document the render gives (a POA&M, an SSP, assessment results)
validates against NIST's complete JSON schema of the version they target (tools/oscal/<OSCAL_VERSION>/
oscal_complete_schema.json from opsdir/scripts/fetch-tools.sh), as does a document the readers can't tell from another
tool's. Marker `oscal`; skipped without the schema."""
import json
from pathlib import Path

import jsonschema
import pytest

from opsdir_format_oscal.adapter import render_oscal
from opsdir_format_oscal.common import OSCAL_VERSION

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / "tools" / "oscal" / OSCAL_VERSION / "oscal_complete_schema.json"
pytestmark = [pytest.mark.oscal,
              pytest.mark.skipif(not SCHEMA.exists(), reason=f"no {SCHEMA.relative_to(ROOT)} "
                                                             "(opsdir/scripts/fetch-tools.sh)")]


def _validator():
    """Draft-07 validation of the schema, its token pattern's Unicode classes (\\p{L}, \\p{N}: XML Schema regular
    expressions Python's don't know) as Python's equivalents."""
    text = SCHEMA.read_text().replace("\\\\p{L}", "[^\\\\W\\\\d_]").replace("\\\\p{N}", "\\\\d")
    return jsonschema.Draft7Validator(json.loads(text))


def test_every_document_the_render_gives_is_valid_oscal(oscal_record):
    validator = _validator()
    files = render_oscal(oscal_record.d)
    assert len(files) == 3
    problems = {p: [f"{list(e.absolute_path)}: {e.message}" for e in validator.iter_errors(json.loads(t))]
                for p, t in files.items()}
    assert problems == {p: [] for p in files}


def test_the_schema_is_the_version_the_writers_target():
    assert json.loads(SCHEMA.read_text())["$id"].endswith(f"/{OSCAL_VERSION}/oscal-complete-schema.json")

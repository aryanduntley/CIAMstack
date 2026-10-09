"""No line over 120 characters anywhere in the repository's Python (ruff.toml at the root: E501 only). Runs the ruff
the core's test extras pin (opsdir[test]); skipped without it."""
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
RUFF = pathlib.Path(sys.executable).parent / "ruff"


@pytest.mark.skipif(not RUFF.exists() and shutil.which("ruff") is None,
                    reason="no ruff (opsdir/scripts/dev-install.sh installs it)")
def test_no_line_is_longer_than_120_characters():
    ruff = str(RUFF) if RUFF.exists() else shutil.which("ruff")
    done = subprocess.run([ruff, "check", "--output-format", "concise", str(ROOT)], capture_output=True, text=True,
                          cwd=ROOT)
    assert done.returncode == 0, done.stdout + done.stderr

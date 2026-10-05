"""Rendered Terraform checked by Terraform itself (opsdir/scripts/validate-terraform.sh: fmt -check, init without a
backend, validate): every root of the showcase's golden renders, and every kind of network plumbing as each cloud's
landing zone renders it. Runs with the local tools/bin/terraform (opsdir/scripts/fetch-tools.sh); skipped without it.
The first run needs network access for the providers, cached in tools/ after that."""
import pathlib
import subprocess

import pytest

from plumbing_sample import write_samples

ROOT = pathlib.Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "opsdir" / "scripts" / "validate-terraform.sh"
pytestmark = [pytest.mark.terraform,
              pytest.mark.skipif(not (ROOT / "tools" / "bin" / "terraform").exists(),
                                 reason="no tools/bin/terraform (opsdir/scripts/fetch-tools.sh)")]


def _validate(*trees):
    done = subprocess.run([str(SCRIPT), *map(str, trees)], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_showcase_renders_are_valid_terraform():
    _validate(*sorted((ROOT / "examples" / "showcase" / "golden").glob("render-*")))


def test_every_kind_of_plumbing_is_valid_terraform_on_each_cloud(tmp_path):
    _validate(write_samples(tmp_path))

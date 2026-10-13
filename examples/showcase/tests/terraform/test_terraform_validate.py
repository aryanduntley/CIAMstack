"""Rendered Terraform checked by Terraform itself (opsdir/scripts/validate-terraform.sh: fmt -check, init without a
backend, validate): every root of the showcase's golden renders, every kind of network plumbing as each cloud's landing
zone renders it, the front each cloud renders before a cluster's in-cluster gateway, and the AWS and Azure samples'
services (a compute group with its disks, among others the showcase doesn't render). Runs with the local
tools/bin/terraform (opsdir/scripts/fetch-tools.sh); skipped without it.
The first run needs network access for the providers, cached in tools/ after that."""
import pathlib
import subprocess

import pytest

from azure_sample import write_samples as write_azure_samples
from cloudformation_sample import write_samples as write_aws_samples
from gateway_sample import write_samples as write_gateway_samples
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


def test_the_front_before_a_cluster_gateway_is_valid_terraform_on_each_cloud(tmp_path):
    _validate(write_gateway_samples(tmp_path))


def test_the_aws_samples_services_are_valid_terraform(tmp_path):
    _validate(write_aws_samples(tmp_path))


def test_the_azure_samples_services_are_valid_terraform(tmp_path):
    _validate(write_azure_samples(tmp_path))

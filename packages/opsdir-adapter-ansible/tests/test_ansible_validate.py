"""Rendered Ansible checked by Ansible itself (opsdir/scripts/validate-ansible.sh: ansible-inventory --list,
ansible-playbook --syntax-check, ansible-lint with the production profile), with the pinned tools, collections and
roles in tools/ansible (opsdir/scripts/fetch-tools.sh); skipped without them."""
import pathlib
import subprocess

import pytest

from opsdir.connectors.registry import services
from opsdir.core.contract import HostFile
from opsdir_adapter_ansible.render import render
from host_samples import host_config_model

ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "opsdir" / "scripts" / "validate-ansible.sh"
pytestmark = [pytest.mark.ansible,
              pytest.mark.skipif(not (ROOT / "tools" / "ansible" / "venv" / "bin" / "ansible-playbook").exists(),
                                 reason="no tools/ansible (opsdir/scripts/fetch-tools.sh)")]


CONFIG = (("ds", "/opt/ds/config/tools.properties", "ds/config/tools.properties",
           "port=4444\nbindPassword=${secret:aws-sm://ciam/ds-admin}\n"),)


def test_a_render_with_every_host_config_feature_passes_ansibles_own_checks(tmp_path):
    _, alpha = host_config_model()
    agent = HostFile("ds", "/etc/google-cloud-ops-agent/config.yaml", "logging: {}\n",
                     ("systemctl", "restart", "google-cloud-ops-agent"))
    for path, text in render(alpha, services()._replace(deployable_config=lambda m: CONFIG,
                                                        host_files=lambda m: (agent,))).items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    done = subprocess.run([str(SCRIPT), str(tmp_path)], capture_output=True, text=True)
    assert done.returncode == 0 and done.stdout.count("ok      ") == 3, done.stdout + done.stderr

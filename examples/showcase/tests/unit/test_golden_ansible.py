"""The golden Ansible output passes Ansible's own checks (ansible-inventory, syntax, ansible-lint production, the AS3
schema), with the pinned tools (opsdir/scripts/fetch-tools.sh): what the showcase renders is what runs."""
import pathlib
import subprocess

import pytest

from showcase_support import GOLDEN

ROOT = pathlib.Path(__file__).resolve().parents[4]
FOLDERS = sorted(GOLDEN.glob("render-*/*/ansible"))


@pytest.mark.ansible
@pytest.mark.skipif(not (ROOT / "tools" / "ansible" / "venv" / "bin" / "ansible-playbook").exists(),
                    reason="no tools/ansible (opsdir/scripts/fetch-tools.sh)")
@pytest.mark.parametrize("folder", FOLDERS, ids=lambda f: str(f.parent.relative_to(GOLDEN)))
def test_the_golden_ansible_passes_ansibles_own_checks(folder):
    done = subprocess.run([str(ROOT / "opsdir" / "scripts" / "validate-ansible.sh"), str(folder)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr

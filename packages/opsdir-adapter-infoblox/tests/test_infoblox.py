"""The records an environment publishes, on Infoblox: the grid master as the play's provider (password read at run
time), one record per value by type, types it doesn't write, and the planner check."""
import pathlib
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from opsdir.connectors.registry import services
from opsdir.core.environment import StackComponent
from opsdir_adapter_infoblox.adapter import check_appliances
from opsdir_adapter_infoblox.render import render
from edge_samples import alpha_with_dns, appliance

ROOT = pathlib.Path(__file__).resolve().parents[3]
GRID = appliance("gm-1", "dns", "gm-1.mgmt.example.test", "internal")


def test_the_grid_master_and_the_records_written():
    files = render(alpha_with_dns(*GRID), services())
    host = yaml.safe_load(files["ansible/inventory/infoblox.yml"])["all"]["children"]["infoblox"]["hosts"]["gm-1"]
    assert (host["ansible_connection"], host["ciam_nios_view"], host["ciam_nios_provider"]["host"]) == (
        "local", "internal", "gm-1.mgmt.example.test")
    (play,) = yaml.safe_load(files["ansible/infoblox.yml"])
    assert play["vars"]["ciam_dns_records"] == {
        "A": [{"fqdn": "sso.example.test", "value": "10.1.9.10", "ttl": 300}], "AAAA": [], "CNAME": [],
        "TXT": [{"fqdn": "example.test", "value": "v=opsdir1", "ttl": 300}]}
    assert [t["name"] for t in play["tasks"]] == [
        "A records", "TXT records", "Records of types this play doesn't write"]
    assert play["tasks"][0]["infoblox.nios_modules.nios_a_record"]["ipv4"] == "{{ item.value }}"
    assert play["vars"]["ciam_dns_not_written"] == ["MX example.test"]


def test_a_target_declaring_infoblox_without_a_grid_master_is_blocked():
    alpha = alpha_with_dns()
    declared = alpha._replace(stack=(*alpha.stack, StackComponent("dns", "infoblox", None, None)))
    (blocker,) = check_appliances(SimpleNamespace(d=alpha.d, src=alpha, dst=declared)).blockers
    assert "records no Infoblox grid master" in blocker[1]


@pytest.mark.ansible
@pytest.mark.skipif(not (ROOT / "tools" / "ansible" / "venv" / "bin" / "ansible-playbook").exists(),
                    reason="no tools/ansible (opsdir/scripts/fetch-tools.sh)")
def test_the_play_passes_ansibles_own_checks(tmp_path):
    from opsdir_adapter_ansible.render import render as ansible
    alpha = alpha_with_dns(*GRID)
    for path, text in {**ansible(alpha, services()), **render(alpha, services())}.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(text)
    done = subprocess.run([str(ROOT / "opsdir" / "scripts" / "validate-ansible.sh"), str(tmp_path)],
                          capture_output=True, text=True)
    assert done.returncode == 0 and "infoblox.yml (syntax)" in done.stdout, done.stdout + done.stderr

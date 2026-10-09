"""The records an environment publishes, on its Windows DNS servers: the servers as Ansible reaches them (password
read at run time), the play's records, types it doesn't write, and the planner check."""
import pathlib
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from opsdir.connectors.registry import services
from opsdir.core.environment import StackComponent
from opsdir_adapter_windows_dns.adapter import check_appliances
from opsdir_adapter_windows_dns.render import render
from edge_samples import alpha_with_dns, appliance

ROOT = pathlib.Path(__file__).resolve().parents[3]
DC = appliance("dc-1", "dns", "dc-1.corp.example.test", "dns-1.corp.example.test")


def test_the_dns_servers_and_the_records_written():
    files = render(alpha_with_dns(*DC), services())
    host = yaml.safe_load(files["ansible/inventory/ad-dns.yml"])["all"]["children"]["ad_dns"]["hosts"]["dc-1"]
    assert (host["ansible_connection"], host["ansible_port"], host["ciam_dns_server"]) == (
        "ansible.builtin.psrp", 5986, "dns-1.corp.example.test")
    assert host["ansible_password"].startswith('{{ lookup("community.hashi_vault.vault_kv2_get", "ciam/dc-1"')
    (play,) = yaml.safe_load(files["ansible/ad-dns.yml"])
    assert play["vars"]["ciam_dns_records"] == [
        {"zone": "example.test", "name": "sso", "type": "A", "values": ["10.1.9.10"], "ttl": 300},
        {"zone": "example.test", "name": "@", "type": "TXT", "values": ["v=opsdir1"], "ttl": 300}]
    assert play["vars"]["ciam_dns_not_written"] == ["MX example.test"]
    assert "ansible.windows" in files["ansible/requirements-ad-dns.yml"]


def test_a_target_declaring_windows_dns_without_a_server_is_blocked():
    alpha = alpha_with_dns()
    declared = alpha._replace(stack=(*alpha.stack, StackComponent("dns", "ad-dns", None, None)))
    (blocker,) = check_appliances(SimpleNamespace(d=alpha.d, src=alpha, dst=declared)).blockers
    assert "records no DNS server" in blocker[1]


@pytest.mark.ansible
@pytest.mark.skipif(not (ROOT / "tools" / "ansible" / "venv" / "bin" / "ansible-playbook").exists(),
                    reason="no tools/ansible (opsdir/scripts/fetch-tools.sh)")
def test_the_play_passes_ansibles_own_checks(tmp_path):
    from opsdir_adapter_ansible.render import render as ansible
    alpha = alpha_with_dns(*DC)
    for path, text in {**ansible(alpha, services()), **render(alpha, services())}.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(text)
    done = subprocess.run([str(ROOT / "opsdir" / "scripts" / "validate-ansible.sh"), str(tmp_path)],
                          capture_output=True, text=True)
    assert done.returncode == 0 and "ad-dns.yml (syntax)" in done.stdout, done.stdout + done.stderr

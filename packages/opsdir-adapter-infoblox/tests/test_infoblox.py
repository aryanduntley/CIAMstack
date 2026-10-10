"""The records an environment publishes, on Infoblox: the grid master as the play's provider (verified TLS, password
read once at run time), one record per value by type, each marked with the environment's comment, the clean-up of what
it wrote before, and the planner check."""
import pathlib
import subprocess
from types import SimpleNamespace

import pytest
from ansible_yaml import load

from opsdir.connectors.registry import services
from opsdir.core.environment import StackComponent
from opsdir_adapter_infoblox.adapter import check_appliances
from opsdir_adapter_infoblox.render import render
from edge_samples import alpha_with_dns, appliance

ROOT = pathlib.Path(__file__).resolve().parents[3]
GRID = appliance("gm-1", "dns", "gm-1.mgmt.example.test", "internal")


def test_the_grid_master_and_the_records_written():
    files = render(alpha_with_dns(*GRID), services())
    host = load(files["ansible/inventory/infoblox.yml"])["all"]["children"]["infoblox"]["hosts"]["gm-1"]
    assert (host["ansible_connection"], host["ciam_nios_view"], host["ciam_nios_provider"]["host"]) == (
        "local", "internal", "gm-1.mgmt.example.test")
    assert host["ciam_nios_provider"]["validate_certs"] is True
    assert host["ansible_python_interpreter"] == "{{ ansible_playbook_python }}"
    (play,) = load(files["ansible/infoblox.yml"])
    records = play["vars"]["ciam_dns_records"]
    assert (records["A"], records["TXT"], records["MX"]) == (
        [{"name": "sso.example.test", "ipv4addr": "10.1.9.10", "ttl": 300}],
        [{"name": "example.test", "text": "v=opsdir1", "ttl": 300}],
        [{"name": "example.test", "preference": 10, "mail_exchanger": "mail.example.test", "ttl": 3600}])
    assert play["vars"]["ciam_dns_wanted"]["MX"] == ["example.test 10 mail.example.test"]
    assert play["vars"]["ciam_dns_not_written"] == [] and play["vars"]["ciam_dns_comment"] == "opsdir alpha/prod"
    names = [t["name"] for t in play["tasks"]]
    assert names[:4] == ["The grid master's login, read once", "A records", "TXT records", "MX records"]
    assert play["tasks"][0]["no_log"] is True
    written = play["tasks"][1]["infoblox.nios_modules.nios_a_record"]
    assert (written["comment"], written["provider"]) == ("{{ ciam_dns_comment }}", "{{ ciam_nios }}")
    tidy = next(t for t in play["tasks"] if t["name"].startswith("A records this environment wrote before"))
    assert tidy["infoblox.nios_modules.nios_a_record"]["state"] == "absent"
    assert "filter={'comment': ciam_dns_comment, 'view': ciam_nios_view}" in tidy["loop"]
    assert tidy["when"] == "(item.name ~ ' ' ~ item.ipv4addr | string) not in ciam_dns_wanted['A']"


def test_a_target_declaring_infoblox_without_a_grid_master_is_blocked():
    alpha = alpha_with_dns()
    declared = alpha._replace(stack=(*alpha.stack, StackComponent("dns", "infoblox", None, None)))
    (blocker,) = check_appliances(SimpleNamespace(d=alpha.d, src=alpha, dst=declared)).blockers
    assert "records no appliance for it" in blocker[1] and "Record the grid master(s)" in blocker[1]


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

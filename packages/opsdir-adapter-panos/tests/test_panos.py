"""The record's firewall rules on Palo Alto Networks: objects and security rules, the Panorama or firewall as the
play's provider (password read at run time), device group vs vsys, commits only when asked, the planner check."""
import pathlib
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from opsdir.connectors.registry import services
from opsdir.core.environment import StackComponent
from opsdir_adapter_panos.adapter import check_appliances
from opsdir_adapter_panos.render import render
from opsdir_adapter_panos.rules import objects
from edge_samples import appliance
from network_fixtures import ALPHA, entry, model, rule

ROOT = pathlib.Path(__file__).resolve().parents[3]
RULES = (rule(ALPHA, "fw-ldaps", ("10.1.2.0/24", "fd00::/64"), ("1636", "1389"), "ds"),
         entry(ALPHA, "ds-1-ip", "ciamServer", ciamServerRole="ds", ciamHostname="ds-9.example.test",
               ciamPrivateIp="10.1.1.9", ciamSubnet=f"cn=subnet-ds,ou=bindings,{ALPHA}"))


def _alpha(*extra):
    _, alpha, _ = model(alpha=(*RULES, *extra))
    return alpha


def test_objects_and_a_security_rule_per_firewall_rule():
    found = objects(_alpha())
    assert {a["name"]: a["value"] for a in found["addresses"]} == {
        "opsdir-10.1.2.0_24": "10.1.2.0/24", "opsdir-fd00--_64": "fd00::/64",
        "opsdir-ds-1": "UNBOUND:ds-1-address", "opsdir-ds-2": "UNBOUND:ds-2-address",
        "opsdir-ds-1-ip": "10.1.1.9"}
    assert [s["name"] for s in found["services"]] == ["opsdir-tcp-1636", "opsdir-tcp-1389"]
    (r,) = found["rules"]
    assert (r["rule_name"], r["source_ip"], r["service"]) == (
        "opsdir-fw-ldaps", ["opsdir-10.1.2.0_24", "opsdir-fd00--_64"], ["opsdir-tcp-1636", "opsdir-tcp-1389"])
    assert r["destination_ip"] == ["opsdir-ds-1", "opsdir-ds-1-ip", "opsdir-ds-2"]


def test_panorama_device_group_or_firewall_vsys_and_commits_only_when_asked():
    files = render(_alpha(*appliance("pano", "network-firewall", "panorama.mgmt.example.test", "CIAM-DG"),
                          *appliance("fw-1", "network-firewall", "fw-1.mgmt.example.test", "vsys2")), services())
    hosts = yaml.safe_load(files["ansible/inventory/panos.yml"])["all"]["children"]["panos"]["hosts"]
    assert (hosts["pano"]["ciam_panos_device_group"], hosts["fw-1"]["ciam_panos_vsys"]) == ("CIAM-DG", "vsys2")
    assert hosts["pano"]["ciam_panos_provider"]["password"].startswith(
        '{{ lookup("community.hashi_vault.vault_kv2_get", "ciam/pano"')
    (play,) = yaml.safe_load(files["ansible/panos.yml"])
    assert [t["name"] for t in play["tasks"] if "never" in t["tags"]] == [
        "Commit on Panorama", "Push to the device group", "Commit on the firewall"]
    assert "paloaltonetworks.panos" in files["ansible/requirements-panos.yml"]


def test_without_a_scope_the_device_group_is_the_environments():
    files = render(_alpha(*appliance("pano", "network-firewall", "panorama.mgmt.example.test")), services())
    host = yaml.safe_load(files["ansible/inventory/panos.yml"])["all"]["children"]["panos"]["hosts"]["pano"]
    assert host["ciam_panos_device_group"] == "opsdir-alpha-prod"


def test_a_target_declaring_palo_alto_without_a_firewall_is_blocked():
    alpha = _alpha()
    declared = alpha._replace(stack=(*alpha.stack, StackComponent("network-firewall", "panos", None, None)))
    (blocker,) = check_appliances(SimpleNamespace(d=alpha.d, src=alpha, dst=declared)).blockers
    assert "records no Panorama or firewall" in blocker[1]


@pytest.mark.ansible
@pytest.mark.skipif(not (ROOT / "tools" / "ansible" / "venv" / "bin" / "ansible-playbook").exists(),
                    reason="no tools/ansible (opsdir/scripts/fetch-tools.sh)")
def test_the_play_passes_ansibles_own_checks(tmp_path):
    from opsdir_adapter_ansible.render import render as ansible
    alpha = _alpha(*appliance("pano", "network-firewall", "panorama.mgmt.example.test", "CIAM-DG"))
    for path, text in {**ansible(alpha, services()), **render(alpha, services())}.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(text)
    done = subprocess.run([str(ROOT / "opsdir" / "scripts" / "validate-ansible.sh"), str(tmp_path)],
                          capture_output=True, text=True)
    assert done.returncode == 0 and "panos.yml (syntax)" in done.stdout, done.stdout + done.stderr

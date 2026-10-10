"""The record's firewall rules on Palo Alto Networks: objects and security rules named per environment, the Panorama
or firewall as the play's provider (password read once at run time), device group vs vsys, the network team's settings
kept, stale rules removed, commits only when asked and only of the login's own changes, the planner check."""
import pathlib
import subprocess
from types import SimpleNamespace

import pytest
from ansible_yaml import load

from opsdir.connectors.registry import services
from opsdir.core.environment import StackComponent
from opsdir_adapter_panos.adapter import check_appliances
from opsdir_adapter_panos.render import render
from opsdir_adapter_panos.rules import name, objects
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
        "opsdir-alpha-prod-ds-1": "UNBOUND:ds-1-address", "opsdir-alpha-prod-ds-2": "UNBOUND:ds-2-address",
        "opsdir-alpha-prod-ds-1-ip": "10.1.1.9"}
    assert [s["name"] for s in found["services"]] == ["opsdir-tcp-1636", "opsdir-tcp-1389"]
    (r,) = found["rules"]
    assert (r["rule_name"], r["source_ip"], r["service"], r["after"]) == (
        "opsdir-alpha-prod-fw-ldaps", ["opsdir-10.1.2.0_24", "opsdir-fd00--_64"],
        ["opsdir-tcp-1636", "opsdir-tcp-1389"], None)
    assert r["destination_ip"] == ["opsdir-alpha-prod-ds-1", "opsdir-alpha-prod-ds-1-ip", "opsdir-alpha-prod-ds-2"]
    assert r["description"].startswith("opsdir alpha/prod: fw-ldaps")


def test_rules_in_priority_order_and_names_that_never_meet():
    def pinned(cn, cidr, priority):
        return entry(ALPHA, cn, "ciamFirewallRule", ciamBindingRole=cn, ciamSourceCidr=cidr, ciamPort="443",
                     ciamTargetRole="ds", ciamRulePriority=priority)
    found = objects(_alpha(pinned("fw-b", "10.9.0.0/16", "200"), pinned("fw-a", "10.8.0.0/16", "100")))
    assert [(r["rule_name"], r["after"]) for r in found["rules"]] == [
        ("opsdir-alpha-prod-fw-a", None), ("opsdir-alpha-prod-fw-b", "opsdir-alpha-prod-fw-a"),
        ("opsdir-alpha-prod-fw-ldaps", "opsdir-alpha-prod-fw-b")]               # unpinned last
    long_a, long_b = name("x" * 70 + "a"), name("x" * 70 + "b")
    assert len(long_a) == len(long_b) == 63 and long_a != long_b


def test_panorama_device_group_or_firewall_vsys():
    files = render(_alpha(*appliance("pano", "network-firewall", "panorama.mgmt.example.test", "CIAM-DG"),
                          *appliance("fw-1", "network-firewall", "fw-1.mgmt.example.test", "vsys2"),
                          *appliance("fw-2", "network-firewall", "fw-2.mgmt.example.test")), services())
    hosts = load(files["ansible/inventory/panos.yml"])["all"]["children"]["panos"]["hosts"]
    assert (hosts["pano"]["ciam_panos_device_group"], hosts["fw-1"]["ciam_panos_vsys"],
            hosts["fw-2"]["ciam_panos_vsys"]) == ("CIAM-DG", "vsys2", "vsys1")       # no scope: a firewall
    assert hosts["pano"]["ciam_panos_provider"]["password"].startswith(
        '{{ lookup("community.hashi_vault.vault_kv2_get", "ciam/pano"')
    assert hosts["pano"]["ansible_python_interpreter"] == "{{ ansible_playbook_python }}"
    assert "paloaltonetworks.panos" in files["ansible/requirements-panos.yml"]


def _play():
    (play,) = load(render(_alpha(*appliance("pano", "network-firewall", "pano.example.test", "DG")),
                          services())["ansible/panos.yml"])
    return play


def test_commits_only_when_asked_and_only_the_logins_own_changes():
    tasks = _play()["tasks"]
    commits = [t for t in tasks if any(k.startswith("paloaltonetworks.panos.panos_commit") for k in t)]
    assert len(commits) == 3 and all(t["tags"] == ["commit", "never"] for t in commits)
    assert all(next(v for k, v in t.items() if k.startswith("paloaltonetworks"))["admins"] ==
               ["{{ ciam_panos_login.username }}"] for t in commits)
    panorama = next(t for t in commits if "paloaltonetworks.panos.panos_commit_panorama" in t)
    assert panorama["paloaltonetworks.panos.panos_commit_panorama"]["device_groups"] == [
        "{{ ciam_panos_device_group }}"]
    others = [t for t in tasks if t not in commits]
    assert not any("commit" in (next((v for k, v in t.items() if k.startswith("paloaltonetworks")), {}) or {})
                   for t in others)                                     # no object or rule task commits
    assert all("never" not in t["tags"] for t in others)


def test_the_teams_settings_are_kept_and_a_rule_is_placed_only_when_created():
    tasks = {t["name"]: t for t in _play()["tasks"]}
    gathered = tasks["The rules this environment wrote, as the firewall has them"]
    args = gathered["paloaltonetworks.panos.panos_security_rule"]
    assert (args["state"], args["gathered_filter"]) == (
        "gathered", "description starts-with '{{ ciam_panos_marker }}'")
    rule = tasks["Security rules"]["paloaltonetworks.panos.panos_security_rule"]
    assert rule["state"] == "present"
    assert rule["source_zone"] == "{{ ciam_rule_now.source_zone | default(['any'], true) }}"
    assert rule["antivirus"] == "{{ ciam_rule_now.antivirus | default(omit, true) }}"
    assert rule["location"] == "{{ omit if ciam_rule_now else ('after' if item.after else 'top') }}"
    stale = tasks["Rules this environment wrote before and the record no longer holds, removed"]
    assert stale["paloaltonetworks.panos.panos_security_rule"]["state"] == "absent"
    assert stale["loop"].startswith("{{ ciam_panos_rules_now.gathered")
    assert tasks["The login, read once"]["no_log"] is True and tasks["The login, read once"]["tags"] == ["always"]


def test_a_target_declaring_palo_alto_without_a_firewall_is_blocked():
    alpha = _alpha()
    declared = alpha._replace(stack=(*alpha.stack, StackComponent("network-firewall", "panos", None, None)))
    (blocker,) = check_appliances(SimpleNamespace(d=alpha.d, src=alpha, dst=declared)).blockers
    assert "records no appliance for it" in blocker[1] and "Record the Panorama or firewalls" in blocker[1]


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

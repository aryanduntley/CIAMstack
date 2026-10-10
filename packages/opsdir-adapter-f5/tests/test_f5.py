"""F5 BIG-IP in front of an environment's service names: the AS3 declaration shaped by each service name's policies,
the BIG-IPs as Ansible reaches them (password read at run time), the play, and the planner check."""
import json
import pathlib
import subprocess
from types import SimpleNamespace

import pytest
from ansible_yaml import load

from opsdir.connectors.registry import services
from opsdir.core.environment import StackComponent
from opsdir_adapter_f5.as3 import declaration
from opsdir_adapter_f5.checks import check_appliances
from opsdir_adapter_f5.render import render
from network_fixtures import ALPHA, entry, model
from edge_samples import KEY, alpha_with_policy

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIGIP = (entry(ALPHA, "bigip-1", "ciamAppliance", ciamBindingRole="lb-bigip-1", ciamStackRole="load-balancer",
               ciamManagementAddress="bigip-1.mgmt.example.test", ciamApplianceScope="CIAM_Prod",
               ciamLoginName="opsdir-as3", ciamLoginSecretRole="bigip-login"),
         entry(ALPHA, "bigip-login", "ciamSecretRef", ciamBindingRole="bigip-login",
               ciamRefUri="vault://secret/ciam/bigip"),
         entry(ALPHA, "web-2", "ciamServer", ciamServerRole="web", ciamHostname="web-2.example.test",
               ciamPrivateIp="10.1.2.21", ciamSubnet=f"cn=subnet-web,ou=bindings,{ALPHA}"))


def _app(alpha):
    return declaration(alpha, (), None)["declaration"]["opsdir_alpha_prod"]["svc_sso"]


def test_a_terminating_service_name_is_an_https_virtual_server():
    app = _app(alpha_with_policy(KEY, *BIGIP))
    assert app["vs_443"] == {"class": "Service_HTTPS", "redirect80": False, "serverTLS": "tls_server",
                             "virtualAddresses": ["10.1.9.10"], "virtualPort": 443, "pool": "pool_443",
                             "persistenceMethods": ["cookie"]}
    assert app["pool_443"]["members"] == [{"servicePort": 443,
                                           "serverAddresses": ["UNBOUND:web-1-address", "10.1.2.21"]}]
    assert app["tls_server"]["tls1_0Enabled"] is False and app["tls_server"]["tls1_1Enabled"] is False
    assert app["certificate"]["privateKey"] == {"bigip": "/Common/internal-ca.key"}      # never the key itself
    assert app["monitor"]["send"].startswith("GET /health HTTP/1.1\\r\\nHost: sso.example.test")


def test_without_a_policy_tls_passes_through_a_tcp_virtual_server():
    _, alpha, _ = model()
    app = _app(alpha)
    assert app["vs_443"]["class"] == "Service_TCP" and app["pool_443"]["monitors"] == ["tcp"]
    assert app["vs_443"]["virtualAddresses"] == ["UNBOUND:sso-service-frontend-ip"]


def test_the_bigips_inventory_reads_the_password_at_run_time():
    files = render(alpha_with_policy(KEY, *BIGIP), services())
    group = load(files["ansible/inventory/f5-bigip.yml"])["all"]["children"]["f5_bigip"]["children"]
    host = group["f5_CIAM_Prod"]["hosts"]["bigip-1"]
    assert (host["ansible_host"], host["ansible_user"], host["ansible_connection"]) == (
        "bigip-1.mgmt.example.test", "opsdir-as3", "ansible.netcommon.httpapi")
    assert host["ansible_httpapi_password"] == ('{{ lookup("community.hashi_vault.vault_kv2_get", "ciam/bigip", '
                                                'engine_mount_point="secret").secret.value }}')
    (play,) = load(files["ansible/f5-bigip.yml"])
    assert play["hosts"] == "f5_CIAM_Prod[0]"                       # one request per tenant: the cluster syncs
    dry, deploy = play["tasks"]
    assert (dry["tags"], dry["f5networks.f5_bigip.bigip_as3_deploy"]["controls"]) == (["dry-run", "never"],
                                                                                       {"dry_run": True})
    assert deploy["f5networks.f5_bigip.bigip_as3_deploy"]["tenant"] == "CIAM_Prod" and deploy["tags"] == ["deploy"]
    assert json.loads(files["ansible/f5/as3-CIAM_Prod.json"])["declaration"]["CIAM_Prod"]["class"] == "Tenant"
    assert "f5networks.f5_bigip" in files["ansible/requirements-f5-bigip.yml"]


def test_bigips_by_scope_and_no_empty_tenant():
    second = entry(ALPHA, "bigip-2", "ciamAppliance", ciamBindingRole="lb-bigip-2", ciamStackRole="load-balancer",
                   ciamManagementAddress="bigip-2.mgmt.example.test", ciamLoginName="opsdir-as3")
    files = render(alpha_with_policy(KEY, *BIGIP, second), services())
    plays = load(files["ansible/f5-bigip.yml"])
    assert [p["hosts"] for p in plays] == ["f5_CIAM_Prod[0]", "f5_opsdir_alpha_prod[0]"]
    assert {p for p in files if p.startswith("ansible/f5/")} == {"ansible/f5/as3-CIAM_Prod.json",
                                                                "ansible/f5/as3-opsdir_alpha_prod.json"}
    svc = (f"dn: cn=svc-sso,ou=bindings,{ALPHA}\nchangetype: delete\n",)
    from opsdir.core.interchange.ldif import parse
    _, bare, _ = model(alpha=BIGIP, changes=tuple(r for t in svc for r in parse(t)))
    files = render(bare, services())
    (play,) = load(files["ansible/f5-bigip.yml"])
    assert [t["name"] for t in play["tasks"]] == ["Nothing to deploy"]
    assert not [p for p in files if p.startswith("ansible/f5/")]


def test_a_target_declaring_f5_without_an_appliance_is_blocked():
    _, alpha, _ = model()
    declared = alpha._replace(stack=(*alpha.stack, StackComponent("load-balancer", "f5-bigip", None, None)))
    (blocker,) = check_appliances(SimpleNamespace(d=alpha.d, src=alpha, dst=declared)).blockers
    assert "records no appliance for it" in blocker[1]


@pytest.mark.ansible
@pytest.mark.skipif(not (ROOT / "tools" / "ansible" / "venv" / "bin" / "ansible-playbook").exists(),
                    reason="no tools/ansible (opsdir/scripts/fetch-tools.sh)")
def test_the_play_and_declaration_pass_ansible_and_the_as3_schema(tmp_path):
    from opsdir_adapter_ansible.render import render as ansible
    alpha = alpha_with_policy(KEY, *BIGIP)
    for path, text in {**ansible(alpha, services()), **render(alpha, services())}.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(text)
    done = subprocess.run([str(ROOT / "opsdir" / "scripts" / "validate-ansible.sh"), str(tmp_path)],
                          capture_output=True, text=True)
    assert done.returncode == 0 and "as3-CIAM_Prod.json (AS3 schema)" in done.stdout, done.stdout + done.stderr

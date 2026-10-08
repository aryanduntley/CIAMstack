"""Azure collectors: the identity check (the subscription and the cloud the record names: Azure Government when it
is in it); the cli-inventory calls scoped to the environment's resource group, network, region, vaults and storage
accounts, in rounds (zones, keys, apps, profiles, servers, vaults, identities, then their items), exactly the
operations pinned below and none that returns secret material (VPN connections projected; secrets listed, never
shown); the collected export reads as the same export saved by hand; Terraform state from the collection source's
blob or with terraform state pull."""
import importlib.util
import json
import pathlib
import shlex

from opsdir.connectors.collecting import collect, provenance
from opsdir.core.directory import make_entry
from opsdir.core.environment import env_model
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.cli import read_cli_inventory
from opsdir_adapter_azure.collect import COLLECTORS, VPN_PROJECTION, identity_check, inventory_steps, state_steps

# the CLI reader's own fixtures (its record and the outputs saved by hand), loaded by path: one source of truth
_SPEC = importlib.util.spec_from_file_location("azure_cli_fixtures",
                                               pathlib.Path(__file__).with_name("test_azure_cli.py"))
_CLI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CLI)
SUB_ID = "00000000-0000-0000-0000-000000000000"
# every az command (its words before the first option) the cli-inventory collector may run: reviewed, read-only
OPERATIONS = {
    "network vnet list", "vm list", "network nic list", "network lb list", "network public-ip list",
    "network public-ip prefix list", "network nsg list", "network nat gateway list", "disk-encryption-set list",
    "network dns zone list", "network private-dns zone list", "network dns record-set list",
    "network private-dns record-set list", "storage container-rm list", "keyvault secret list", "keyvault key list",
    "keyvault key show", "keyvault key rotation-policy show", "functionapp list", "functionapp function list",
    "network application-gateway list", "network application-gateway waf-policy list", "network ddos-protection list",
    "network traffic-manager profile list", "afd profile list", "afd endpoint list", "afd security-policy list",
    "afd origin-group list", "afd origin list", "network front-door waf-policy list",
    "dns-resolver forwarding-ruleset list", "dns-resolver forwarding-rule list", "network route-table list",
    "network private-endpoint list", "network private-endpoint dns-zone-group list",
    "network private-link-service list", "network firewall list", "network firewall policy list",
    "network firewall policy rule-collection-group list", "network vnet peering list", "network vpn-connection list",
    "network local-gateway list", "network vnet-gateway list", "network watcher flow-log list",
    "monitor diagnostic-settings subscription list", "postgres flexible-server list",
    "postgres flexible-server parameter list", "mysql flexible-server list", "mysql flexible-server parameter list",
    "disk list", "dataprotection backup-vault list", "dataprotection backup-policy list",
    "dataprotection backup-instance list", "lock list", "identity list", "identity federated-credential list",
    "role assignment list", "role definition list", "rest", "keyvault list", "keyvault show", "policy assignment list",
    "network bastion list"}
NEVER = ("secret show", "secret download", "appsettings", "config", "show-connection-string", "keys list",
         "get-shared-key", "connection-string", "--debug")


def _model(**cloud):
    d = _CLI._record()
    dn = "cloud=main,ou=environments,dc=ciam-ops"
    if cloud:
        d = d._replace(entries={**d.entries, dn: make_entry(dn, (*d.entries[dn].classes, "ciamCloudAccount"),
                                                            {**d.entries[dn].attrs,
                                                             **{k: (v,) for k, v in cloud.items()}})})
    return env_model(d, "main/prod")


def _fixture():
    return {p.split("/", 2)[2]: json.loads(t) for p, t in _CLI._outputs().items()}


def _words(argv):
    """The command's words before its first option."""
    words = []
    for a in argv[1:]:
        if a.startswith("-"):
            break
        words.append(a)
    return " ".join(words)


def _answer(argv):
    f, cmd = _fixture(), _words(argv)
    files = {"network vnet list": "network.json", "vm list": "vms.json", "network nic list": "nics.json",
             "network lb list": "lbs.json", "network public-ip list": "public-ips.json", "network nsg list": "nsgs.json",
             "network nat gateway list": "nat.json", "disk-encryption-set list": "des.json",
             "storage container-rm list": "containers.json", "keyvault secret list": "kv-secrets.json",
             "keyvault key list": "kv-keys.json", "keyvault key show": "kv-key-disk-cmk.json",
             "keyvault key rotation-policy show": "kv-rotation-disk-cmk.json"}
    zones = {"network dns zone list": [{"name": "example.test"}],
             "network private-dns zone list": [{"name": "id.example.test"}],
             "network dns record-set list": f["dns-public.json"],
             "network private-dns record-set list": f["dns-private.json"],
             "account show": {"id": SUB_ID, "environmentName": "AzureCloud", "user": {"name": "op@example.test"}}}
    if cmd in zones:
        return json.dumps(zones[cmd]), None
    return json.dumps(f[files[cmd]] if cmd in files else []), None


def _run(call):
    return _answer(call.argv)


def test_the_collectors_are_declared_on_the_adapter():
    assert [(c.importer, c.scope) for c in ADAPTER.collectors] == [("cli-inventory", "environment"),
                                                                    ("terraform-state", "environment")]


def test_the_login_must_be_the_subscription_and_cloud_the_record_names():
    call, check = identity_check(None, _model(ciamAccountRef=SUB_ID))
    assert call.argv == ("az", "account", "show", "-o", "json")
    assert check(json.dumps({"id": SUB_ID, "environmentName": "AzureCloud"})) is None
    assert check(json.dumps({"id": "1111", "environmentName": "AzureCloud"})) == \
        f"signed in to subscription 1111, the record names {SUB_ID}"
    _, gov = identity_check(None, _model(ciamAccountRef=SUB_ID, ciamCloudEnvironment="usgovernment"))
    assert gov(json.dumps({"id": SUB_ID, "environmentName": "AzureCloud"})) == \
        "signed in to cloud AzureCloud, the record's is AzureUSGovernment (az cloud set)"
    assert gov(json.dumps({"id": SUB_ID, "environmentName": "AzureUSGovernment"})) is None


def test_the_collected_export_reads_as_the_export_saved_by_hand():
    m = _model(ciamAccountRef=SUB_ID)
    c = collect("azure/cli-inventory", COLLECTORS[0], m.d, m, _run)
    assert c.problems == () and all(p.startswith("main/prod/") for p in c.files)
    by_hand = read_cli_inventory(_CLI._outputs(), m.d, ())
    collected = read_cli_inventory(c.files, m.d, ())
    assert collected.groups == by_hand.groups


def test_exactly_the_reviewed_operations_and_never_a_secret():
    m = _model(ciamAccountRef=SUB_ID)
    c = collect("azure/cli-inventory", COLLECTORS[0], m.d, m, _run)
    ran = [shlex.split(x.provenance) for x in c.calls]
    assert {_words(a) for a in ran} <= OPERATIONS
    assert not [a for a in ran for word in NEVER if word in " ".join(a)]
    assert all(a[0] == "az" and a[-2:] == ["-o", "json"] for a in ran)
    assert ["az", "network", "vnet", "list", "-g", "rg-ciam-prod"] == ran[0][:6]
    assert {a[a.index("--vault-name") + 1] for a in ran if "--vault-name" in a} == {"kv-ciam-prod"}
    assert {a[a.index("--storage-account") + 1] for a in ran if "--storage-account" in a} == {"stciamprod"}
    vpn = next(a for a in ran if _words(a) == "network vpn-connection list")
    assert vpn[vpn.index("--query") + 1] == VPN_PROJECTION                      # shared keys never fetched
    rest = [a for a in ran if _words(a) == "rest"]
    assert all(a[2:4] == ["--method", "get"] and a[5].startswith(f"https://management.azure.com/subscriptions/{SUB_ID}/")
               for a in rest) and len(rest) == 2
    assert {"dns-example.test.json", "private-dns-id.example.test.json", "kv-key-disk-cmk.json"} <= \
        {x.path.rsplit("/", 1)[-1] for x in c.calls}


def test_azure_government_reads_its_own_management_endpoint_and_no_group_nothing():
    m = _model(ciamAccountRef=SUB_ID, ciamCloudEnvironment="usgovernment")
    rest = [c for _, c in inventory_steps(m.d, m, {}, {}) if c.argv[1] == "rest"]
    assert all("https://management.usgovcloudapi.net/" in c.argv[5] for c in rest)
    no_group = m._replace(bindings=tuple(b for b in m.bindings if "ciamNetwork" not in b.classes))
    assert inventory_steps(m.d, no_group, {}, {}) == ()


def test_terraform_state_from_the_source_blob_or_terraform_state_pull():
    m = _model(ciamAccountRef=SUB_ID)
    assert state_steps(m.d, m, {}, {}) == ()
    source = make_entry("cn=tf-state,ou=bindings,env=prod,cloud=main,ou=environments,dc=ciam-ops",
                        ("top", "ciamCollectionSource"),
                        {"cn": ("tf-state",), "ciamBindingRole": ("collect-state",),
                         "ciamImporter": ("azure/terraform-state",),
                         "ciamSourceRef": ("azblob://stciamtfstate/tfstate/ciam-prod.terraform.tfstate",)})
    with_source = m._replace(bindings=(*m.bindings, source))
    ((path, call),) = state_steps(m.d, with_source, {}, {})
    assert path == "main/prod/ciam-prod.terraform.tfstate"
    assert provenance(call) == ("az storage blob download --account-name stciamtfstate --container-name tfstate "
                                "--name ciam-prod.terraform.tfstate --auth-mode login -o none")
    ((_, pull),) = state_steps(m.d, with_source, {}, {"terraform_dir": "/work/ciam"})
    assert pull.argv == ("terraform", "-chdir=/work/ciam", "state", "pull")

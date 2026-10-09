"""Vault for Kubernetes workloads: External Secrets and the Vault CSI provider read vault://<mount>/<path> references'
`value` field, with the address, auth role and mount and engine version from the environment's secret store."""
import yaml

from opsdir.core.directory import make_entry
from opsdir_adapter_hashicorp_vault.kubernetes import SECRET_DELIVERY

STORE = make_entry("cn=vault,ou=bindings,env=prod,cloud=target,ou=environments,dc=ciam-ops", ("top", "ciamSecretStore"),
                   {"ciamBindingRole": ("secret-store-vault",), "ciamRefScheme": ("vault",),
                    "ciamStoreEndpoint": ("https://vault.example.test:8200",), "ciamStoreAuthRole": ("ciam-am",)})
D = SECRET_DELIVERY["vault"]


def test_external_secrets_reads_the_value_field_under_the_mount():
    assert D.store_key("secret/ciam/am/admin") == "secret"
    assert D.eso_ref("secret/ciam/am/admin") == {"key": "ciam/am/admin", "property": "value"}
    assert D.eso_provider(None, STORE, "secret", "am", None) == {"vault": {
        "server": "https://vault.example.test:8200", "path": "secret", "version": "v2",
        "auth": {"kubernetes": {"mountPath": "kubernetes", "role": "ciam-am", "serviceAccountRef": {"name": "am"}}}}}
    assert D.eso_provider(None, None, "secret", "am", None)["vault"]["server"] == "UNBOUND:vault-address"


def test_csi_reads_the_kv2_data_path():
    params = D.csi_parameters(None, STORE, "secret", (("admin", "secret/ciam/am/admin"),), None)
    assert (D.csi_provider, params["vaultAddress"], params["roleName"]) == \
        ("vault", "https://vault.example.test:8200", "ciam-am")
    assert yaml.safe_load(params["objects"]) == [{"objectName": "admin", "secretPath": "secret/data/ciam/am/admin",
                                                  "secretKey": "value"}]
    kv1 = make_entry(STORE.dn, STORE.classes, {**STORE.attrs, "ciamStoreKvVersion": ("1",)})
    assert yaml.safe_load(D.csi_parameters(None, kv1, "secret", (("admin", "secret/ciam/am/admin"),), None)
                          ["objects"])[0]["secretPath"] == "secret/ciam/am/admin"

"""PingFederate rendered as Terraform for Ping's provider (render target terraform), from the same Admin API requests:
the provider release pinned by the PingFederate version (none for an unsupported one); each request a resource in the
provider's terms (snake_case, its id argument, a discriminated object as its variant, plugin fields holding secrets
among sensitive_fields, map keys as they are), what the provider doesn't take named; secrets as sensitive variables
named by their role, never values; groups of resources depending on the group before. The Terraform itself is checked
by Terraform on the showcase's renders (examples/showcase/tests/terraform)."""
import importlib.util
import pathlib
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir_adapter_pingfederate.admin_api import Request
from opsdir_adapter_pingfederate.terraform_target import (OUTPUT, load_provider_schema, provider_release, resource,
                                                          secret_variables, snake, terraform_files)

_SPEC = importlib.util.spec_from_file_location("pf_api_tests",
                                               pathlib.Path(__file__).with_name("test_pingfederate_admin_api.py"))
_API = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_API)


def test_the_provider_release_follows_the_pingfederate_version():
    assert [provider_release(v) for v in ("PingFederate 13.1.2", "12.2", "PingFederate 12.1.4", "11.3", "11.2",
                                          "14.0", None)] == \
        [("1.10.0", "13.1"), ("1.10.0", "12.2"), ("1.8.1", "12.1"), ("1.8.1", "11.3"), (None, None), (None, None),
         (None, None)]
    assert [snake(n) for n in ("userDN", "x509File", "idpBrowserSso", "includeSHashInIdToken")] == \
        ["user_dn", "x509_file", "idp_browser_sso", "include_s_hash_in_id_token"]


def test_a_request_becomes_the_providers_resource_with_secrets_as_variables():
    schema = load_provider_schema("1.10.0")
    vault = make_entry("cn=ds-pw,ou=bindings,env=prod,cloud=c,ou=environments,dc=ciam-ops", ("top", "ciamSecretRef"),
                       {"cn": ("ds-pw",), "ciamBindingRole": ("pf-ds-password",), "ciamRefUri": ("vault://kv/pf#ds",)})
    known = secret_variables(SimpleNamespace(bindings=(vault,)))
    store = Request("PUT", "/dataStores/users", "POST /dataStores", {
        "type": "LDAP", "id": "users", "ldapType": "PING_DS", "hostnames": ["ds:1636"], "userDN": "cn=pf",
        "password": "${secret:vault://kv/pf#ds}", "lastModified": "2026-01-01T00:00:00Z", "madeUp": 1})
    tf_type, name, args, dropped, variables = resource(store, schema, known)
    assert (tf_type, name, args["data_store_id"]) == ("pingfederate_data_store", "users", "users")
    assert args["ldap_data_store"]["user_dn"] == "cn=pf" and "type" not in args["ldap_data_store"]
    assert args["ldap_data_store"]["password"].text == "var.pf_ds_password"
    assert variables == (("pf_ds_password", "the secret of role pf-ds-password (vault://kv/pf#ds), supplied at "
                                            "apply time"),)
    assert dropped == ("pingfederate_data_store.ldap_data_store.madeUp",)    # read-only lastModified: silently
    adapter = Request("PUT", "/idp/adapters/form", "POST /idp/adapters", {
        "id": "form", "name": "Form", "pluginDescriptorRef": {"id": "x"},
        "configuration": {"fields": [{"name": "Realm", "value": "r"}, {"name": "Secret", "value": "UNBOUND:pf-form"}],
                          "tables": []},
        "attributeMapping": {"attributeContractFulfillment": {"urn:claim": {"source": {"type": "ADAPTER"},
                                                                           "value": "u"}}}})
    _, _, args, _, variables = resource(adapter, schema, {})
    assert args["configuration"]["fields"] == [{"name": "Realm", "value": "r"}]
    assert args["configuration"]["sensitive_fields"][0]["value"].text == "var.pf_form"
    assert list(args["attribute_mapping"]["attribute_contract_fulfillment"]) == ["urn:claim"]      # a map: keys kept
    assert variables[0][0] == "pf_form"


def test_the_root_pins_the_provider_and_holds_no_secret_value():
    d = _API._after()
    files = terraform_files(_API._env(d, "PingFederate 12.1.4"))
    assert set(files) == {f"{OUTPUT}versions.tf", f"{OUTPUT}variables.tf", f"{OUTPUT}main.tf"}
    assert 'version = "1.8.1"' in files[f"{OUTPUT}versions.tf"] and 'product_version = "12.1"' in \
        files[f"{OUTPUT}versions.tf"]
    main = files[f"{OUTPUT}main.tf"]
    assert 'resource "pingfederate_sp_idp_connection"' in main and "depends_on = [" in main
    assert "sensitive   = true" in files[f"{OUTPUT}variables.tf"]
    newer = terraform_files(_API._env(d, "PingFederate 13.1.0"))
    assert 'version = "1.10.0"' in newer[f"{OUTPUT}versions.tf"]
    assert terraform_files(_API._env(d, "PingFederate 10.3.0")) == {f"{OUTPUT}main.tf": (
        "# Not rendered: no pinned pingidentity/pingfederate release supports PingFederate 10.3.0 (supported: 11.3 to "
        "13.1); apply the admin-api requests\n")}


def test_only_the_targets_chosen_are_rendered():
    from opsdir_adapter_pingfederate.adapter import ADAPTER
    from opsdir_adapter_pingfederate.admin_api import OUTPUT as REQUESTS
    m = _API._env(_API._after(), "PingFederate 12.1.4")
    assert [t[0] for t in ADAPTER.render_targets] == ["admin-api", "terraform", "terraform-imports"]
    both = ADAPTER.render_env(m, None)
    assert REQUESTS in both and f"{OUTPUT}main.tf" in both
    assert set(ADAPTER.render_env(m, None, ("admin-api",))) == {p for p in both if not p.startswith(OUTPUT)}
    assert set(ADAPTER.render_env(m, None, ("terraform",))) == {p for p in both if p != REQUESTS}


def test_import_blocks_only_when_asked_adopting_what_the_terraform_renders():
    import pytest
    from opsdir_adapter_pingfederate.adapter import ADAPTER
    m = _API._env(_API._after(), "PingFederate 12.1.4")
    assert f"{OUTPUT}imports.tf" not in ADAPTER.render_env(m, None)
    files = ADAPTER.render_env(m, None, ("terraform", "terraform-imports"))
    imports = files[f"{OUTPUT}imports.tf"]
    assert 'to = pingfederate_data_store.user_directory\n  id = "user-directory"' in imports
    assert "to = pingfederate_oauth_client.mobile" in imports
    with pytest.raises(SystemExit, match="choose both"):
        ADAPTER.render_env(m, None, ("terraform-imports",))

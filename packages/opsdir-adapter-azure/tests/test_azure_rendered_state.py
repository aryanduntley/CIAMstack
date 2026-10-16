"""Azure's rendered Terraform as the state applying it would record (the round trip, 5.5c): ids as Azure gives them
(the importers read them by their segments), a realized binding's provider reference and what the record holds of
what Azure assigned it, data sources found by name and resource group, the subscription a root runs in."""
import json

from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_azure.rendered_state import resource_id, rendered_states, subscription_of
from opsdir_format_terraform.hcl import TfBlock, block, ref
import mini_estate
from support import build_directory

ENV = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
SUB = "11111111-2222-3333-4444-555555555555"
IDENTITY = (f"dn: cn=identity-pf,ou=bindings,{ENV}\nobjectClass: top\nobjectClass: ciamIdentityBinding\n"
            "cn: identity-pf\nciamBindingRole: identity-pf\nciamIdentityKind: managed-identity\n"
            f"ciamProviderRef: /subscriptions/{SUB}/resourceGroups/rg-ciam/providers/Microsoft.ManagedIdentity/"
            "userAssignedIdentities/id-ciam-pf\nciamIdentityClientId: 6f1c2a40-0000-4000-8000-00000000c1d0\n")
PROVIDER = (TfBlock("provider", ("azurerm",), (("subscription_id", ref("var.subscription_id")),)),
            TfBlock("variable", ("subscription_id",), (("default", SUB),)))


def test_the_subscription_a_root_runs_in():
    assert subscription_of(PROVIDER) == SUB
    assert subscription_of(()) == "00000000-0000-0000-0000-000000000000"


def test_ids_as_azure_gives_them():
    group = f"/subscriptions/{SUB}/resourceGroups/rg-ciam"
    assert resource_id("azurerm_key_vault", "kv", None, {"name": "kv-ciam", "resource_group_name": "rg-ciam"}, SUB) \
        == f"{group}/providers/Microsoft.KeyVault/vaults/kv-ciam"
    assert resource_id("azurerm_subnet", "snet", None, {"name": "snet-pf", "resource_group_name": "rg-ciam",
                                                         "virtual_network_name": "vnet"}, SUB) == \
        f"{group}/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet-pf"
    assert resource_id("azurerm_security_center_subscription_pricing", "p", None, {"resource_type": "CloudPosture"},
                       SUB) == f"/subscriptions/{SUB}/providers/Microsoft.Security/pricings/CloudPosture"
    assert resource_id("azurerm_resource_group", "main", None, {"name": "rg-ciam"}, SUB) == group
    assert "/opsdirSynthetic/" in resource_id("azurerm_something_new", "x", 2, {}, SUB)
    lb = f"{group}/providers/Microsoft.Network/loadBalancers/lb-a"
    assert resource_id("azurerm_lb_backend_address_pool", "a", None, {"name": "servers", "loadbalancer_id": lb},
                       SUB) == f"{lb}/backendAddressPools/servers"           # two load balancers' pools stay apart


def test_a_realized_binding_keeps_its_reference_and_client_id():
    d = build_directory(mini_estate.REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + IDENTITY)))
    main = "\n\n".join(block(*b) for b in (
        *PROVIDER, TfBlock("data", ("azurerm_resource_group", "main"), (("name", "rg-ciam"),)),
        TfBlock("resource", ("azurerm_user_assigned_identity", "identity_pf"), (
            ("name", "id-ciam-pf"), ("resource_group_name", ref("data.azurerm_resource_group.main.name")))),
        TfBlock("resource", ("azurerm_user_assigned_identity", "helper"), (
            ("name", "id-helper"), ("resource_group_name", "rg-ciam"))),
        TfBlock("data", ("azurerm_key_vault", "kv"), (("name", "kv-ciam"), ("resource_group_name", "rg-ciam"))))) + "\n"
    (text,) = rendered_states({"alpha/prod/main.tf": main}, d, "alpha/prod").values()
    found = {(r["mode"], r["type"], r["name"]): r["instances"][0]["attributes"]
             for r in json.loads(text)["resources"]}
    pf = found[("managed", "azurerm_user_assigned_identity", "identity_pf")]
    assert (pf["id"], pf["client_id"]) == (
        f"/subscriptions/{SUB}/resourceGroups/rg-ciam/providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
        "id-ciam-pf", "6f1c2a40-0000-4000-8000-00000000c1d0")
    helper = found[("managed", "azurerm_user_assigned_identity", "helper")]
    assert helper["id"].endswith("/userAssignedIdentities/id-helper") and len(helper["principal_id"]) == 36
    assert found[("data", "azurerm_key_vault", "kv")]["id"] == \
        f"/subscriptions/{SUB}/resourceGroups/rg-ciam/providers/Microsoft.KeyVault/vaults/kv-ciam"
    assert found[("data", "azurerm_resource_group", "main")]["location"] == "region-1"

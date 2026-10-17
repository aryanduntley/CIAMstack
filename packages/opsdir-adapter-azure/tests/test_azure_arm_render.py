"""ARM templates translated from the Azure render's Terraform data (5.6 e3a): values (interpolations, ids, lookups),
a template per deployment scope (the resource group a block names, a child's parent's, a variable's), children under
their parents (a template resource, a lookup, a literal id), parts inline where the parent's PUT would drop them
(self-references by resourceId), merges, an ephemeral secret as a secure parameter, only the parameters used, and what
stays Terraform saying why."""
from types import SimpleNamespace

from opsdir_format_arm.template import Call, Interp, Member, Param, ResourceId
from opsdir_format_terraform.hcl import Block, TfFile, ref, tf_block
from opsdir_adapter_azure.arm_render import _concat, parse_id
from opsdir_adapter_azure.arm_types import arm_files, arm_translation

M = SimpleNamespace(dn="env=prod,cloud=alpha,ou=environments,dc=ciam-ops", label="alpha/prod")
WHAT = "Azure infrastructure"
RG = [("name", "rg-a")]
MAIN_RG = ref("data.azurerm_resource_group.main.name")


def test_values_concatenate_into_one_interpolation():
    assert _concat("a", "b") == "ab" and _concat(Param("p")) == Param("p")
    assert _concat("x-", Interp(("y-", Param("p"))), "-z") == Interp(("x-y-", Param("p"), "-z"))


def test_literal_arm_ids_name_their_group_type_and_names():
    assert parse_id("/subscriptions/0/resourceGroups/rg-hub/providers/Microsoft.Network/firewallPolicies/fwp") == \
        ("rg-hub", "Microsoft.Network/firewallPolicies", ("fwp",))
    assert parse_id("/subscriptions/0/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st/blobServices"
                    "/default") == ("rg", "Microsoft.Storage/storageAccounts/blobServices", ("st", "default"))
    assert parse_id("not an id") is None


ROOT = TfFile("", (
    tf_block("data", ["azurerm_resource_group", "main"], RG),
    tf_block("data", ["azurerm_virtual_network", "main"], [("name", "vnet-a"), ("resource_group_name", MAIN_RG)]),
    tf_block("data", ["azurerm_subnet", "s"], [("name", "snet"), ("virtual_network_name", "vnet-a"),
                                              ("resource_group_name", ref("data.azurerm_resource_group.main.name"))]),
    tf_block("resource", ["azurerm_network_security_group", "g"], [
        ("name", "nsg-a"), ("location", ref("data.azurerm_resource_group.main.location")),
        ("resource_group_name", ref("data.azurerm_resource_group.main.name")), ("tags", {"Role": "ds"})]),
    tf_block("resource", ["azurerm_network_security_rule", "r"], [
        ("name", "ldaps"), ("priority", 100), ("direction", "Inbound"), ("access", "Allow"), ("protocol", "Tcp"),
        ("source_port_range", "*"), ("destination_port_ranges", ["1636"]), ("source_address_prefixes", ["10.0.0.0/8"]),
        ("destination_address_prefix", "*"), ("resource_group_name", ref("data.azurerm_resource_group.main.name")),
        ("network_security_group_name", ref("azurerm_network_security_group.g.name"))]),
    tf_block("resource", ["azurerm_network_interface", "n"], [
        ("name", "nic-a"), ("location", ref("data.azurerm_resource_group.main.location")),
        ("resource_group_name", ref("data.azurerm_resource_group.main.name")),
        ("ip_configuration", Block((("name", "primary"), ("subnet_id", ref("data.azurerm_subnet.s.id")),
                                    ("private_ip_address_allocation", "Dynamic"))))]),
    tf_block("resource", ["azurerm_network_interface_security_group_association", "n"], [
        ("network_interface_id", ref("azurerm_network_interface.n.id")),
        ("network_security_group_id", ref("azurerm_network_security_group.g.id"))]),
    tf_block("resource", ["azurerm_subnet_network_security_group_association", "s"], [
        ("subnet_id", ref("data.azurerm_subnet.s.id")), ("network_security_group_id",
                                                          ref("azurerm_network_security_group.g.id"))]),
    tf_block("resource", ["azurerm_firewall_policy_rule_collection_group", "hub"], [
        ("name", "sites"), ("priority", 500),
        ("firewall_policy_id", "/subscriptions/0/resourceGroups/rg-hub/providers/Microsoft.Network/firewallPolicies/"
                               "fwp")]),
    tf_block("variable", ["watcher_rg"], [("type", ref("string"))]),
    tf_block("variable", ["watcher"], [("type", ref("string"))]),
    tf_block("resource", ["azurerm_network_watcher_flow_log", "f"], [
        ("name", "fl-a"), ("network_watcher_name", ref("var.watcher")), ("resource_group_name", ref("var.watcher_rg")),
        ("target_resource_id", ref("data.azurerm_virtual_network.main.id")), ("storage_account_id", "/st"),
        ("enabled", True), ("version", 2)])))


def _translation(root=ROOT):
    return arm_translation(M, {"terraform/main.tf": root}, WHAT)


def _template(t, key):
    return next(x for (_, k), x in t.templates.items() if k == key)


def test_a_template_per_scope_parents_and_existing_lookups():
    t = _translation()
    assert {k for _, k in t.templates} == {("resourceGroup", "rg-a"), ("resourceGroup", "rg-hub"),
                                           ("resourceGroup", ("var", "watcher_rg"))}
    hub = {r.symbol: r for r in _template(t, ("resourceGroup", "rg-hub")).resources}
    policy = hub["firewallpolicies_fwp"]
    assert policy.existing and policy.resource_group is None                      # the template's own group
    assert hub["firewall_policy_rule_collection_group_hub"].parent == "firewallpolicies_fwp"
    watcher = _template(t, ("resourceGroup", ("var", "watcher_rg")))
    assert [p.name for p in watcher.parameters] == ["watcher"]                     # the group var: the deployment's
    vnet = next(r for r in watcher.resources if r.type == "Microsoft.Network/virtualNetworks")
    assert vnet.existing and vnet.resource_group == "rg-a"


def test_rules_inline_merges_and_resource_group_values():
    main = {r.symbol: r for r in _template(_translation(), ("resourceGroup", "rg-a")).resources}
    nsg, nic = main["network_security_group_g"], main["network_interface_n"]
    assert nsg.fields["location"] == Member(Call("resourceGroup", ()), "location")
    assert nsg.properties["securityRules"][0]["name"] == "ldaps"
    assert nic.properties["networkSecurityGroup"] == {"id": ResourceId("network_security_group_g")}
    assert nic.properties["ipConfigurations"][0]["properties"]["subnet"] == {"id": ResourceId("subnets_snet")}
    assert main["subnets_snet"].parent == "virtualnetworks_vnet_a"


def test_what_stays_terraform_says_why():
    places = _translation().placements["terraform"]
    assert places["azurerm_subnet_network_security_group_association.s"].detail.startswith(
        "a property of the landing zone's subnet")
    assert places["azurerm_network_security_rule.r"].kind == "merged"
    files = arm_files(M, {"terraform/main.tf": ROOT}, WHAT, ("bicep",))
    side = files["bicep/terraform/main.tf"]
    assert "#   azurerm_subnet_network_security_group_association.s: a property" in side.head


def test_a_balancers_parts_refer_to_it_by_resource_id_inside_it():
    lb = TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], RG),
        tf_block("resource", ["azurerm_lb", "l"], [
            ("name", "lb-a"), ("location", "eastus2"), ("resource_group_name", MAIN_RG), ("sku", "Standard"),
            ("frontend_ip_configuration", Block((("name", "fe"), ("private_ip_address", "10.0.0.4"))))]),
        tf_block("resource", ["azurerm_lb_backend_address_pool", "p"], [
            ("name", "servers"), ("loadbalancer_id", ref("azurerm_lb.l.id"))]),
        tf_block("resource", ["azurerm_lb_rule", "r"], [
            ("name", "tcp"), ("loadbalancer_id", ref("azurerm_lb.l.id")), ("protocol", "Tcp"), ("frontend_port", 1),
            ("backend_port", 1), ("frontend_ip_configuration_name", "fe"),
            ("backend_address_pool_ids", [ref("azurerm_lb_backend_address_pool.p.id")])])))
    t = arm_translation(M, {"terraform/main.tf": lb}, WHAT)
    balancer = next(r for x in t.templates.values() for r in x.resources if r.symbol == "lb_l")
    own = Call("resourceId", ("Microsoft.Network/loadBalancers", "lb-a"))
    rule = balancer.properties["loadBalancingRules"][0]["properties"]
    assert rule["backendAddressPools"] == [{"id": Interp((own, "/backendAddressPools/servers"))}]
    assert rule["frontendIPConfiguration"] == {"id": Interp((own, "/frontendIPConfigurations/fe"))}


def test_an_ephemeral_secret_is_a_secure_parameter():
    db = TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], RG),
        tf_block("data", ["azurerm_key_vault", "kv"], [("name", "kv-a"), ("resource_group_name", MAIN_RG)]),
        tf_block("ephemeral", ["azurerm_key_vault_secret", "admin"], [
            ("name", "db-password"), ("key_vault_id", ref("data.azurerm_key_vault.kv.id"))]),
        tf_block("resource", ["azurerm_postgresql_flexible_server", "db"], [
            ("name", "psql-a"), ("location", "eastus2"), ("resource_group_name", MAIN_RG),
            ("version", "16"), ("sku_name", "GP_Standard_D2ds_v5"), ("storage_mb", 131072),
            ("administrator_login", "ciam"),
            ("administrator_password_wo", ref("ephemeral.azurerm_key_vault_secret.admin.value")),
            ("administrator_password_wo_version", 1)])))
    template = next(iter(arm_translation(M, {"terraform/main.tf": db}, WHAT).templates.values()))
    secret = next(p for p in template.parameters if p.secure)
    server = next(r for r in template.resources if r.symbol == "postgresql_flexible_server_db")
    assert server.properties["administratorLoginPassword"] == Param(secret.name)
    assert server.fields["sku"] == {"name": "Standard_D2ds_v5", "tier": "GeneralPurpose"}
    assert "fills it from the vault" in secret.description


def test_an_azapi_sensitive_body_merges_into_its_body_its_secret_a_secure_parameter():
    # an Event Hub's continuous export (task 581): its connection string only in azapi's write-only sensitive_body
    from opsdir_adapter_azure.arm_types import azapi_merged
    assert azapi_merged({"a": [{"x": 1}], "b": 2}, {"a": [{"y": 3}]}) == {"a": [{"x": 1, "y": 3}], "b": 2}
    assert azapi_merged({"a": [{"x": 1}]}, {"a": [{"y": 3}, {"z": 4}]}) == {"a": [{"y": 3}, {"z": 4}]}
    hub = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns/eventhubs/sec"
    action = {"actionType": "EventHub", "eventHubResourceId": hub}
    export = TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], RG),
        tf_block("data", ["azurerm_key_vault", "kv"], [("name", "kv-a"), ("resource_group_name", MAIN_RG)]),
        tf_block("ephemeral", ["azurerm_key_vault_secret", "send"], [
            ("name", "sec-hub-send"), ("key_vault_id", ref("data.azurerm_key_vault.kv.id"))]),
        tf_block("resource", ["azapi_resource", "export"], [
            ("type", "Microsoft.Security/automations@2023-12-01-preview"), ("name", "defender-export"),
            ("parent_id", ref("data.azurerm_resource_group.main.id")),
            ("location", ref("data.azurerm_resource_group.main.location")),
            ("body", {"properties": {"isEnabled": True, "sources": [{"eventSource": "Alerts"}], "actions": [action]}}),
            ("sensitive_body", {"properties": {"actions": [
                {**action, "connectionString": ref("ephemeral.azurerm_key_vault_secret.send.value")}]}})])))
    template = next(iter(arm_translation(M, {"terraform/main.tf": export}, WHAT).templates.values()))
    secret = next(p for p in template.parameters if p.secure)
    automation = next(r for r in template.resources if r.type == "Microsoft.Security/automations")
    assert automation.properties["actions"] == [{**action, "connectionString": Param(secret.name)}]
    assert automation.properties["sources"] == [{"eventSource": "Alerts"}]


def test_an_incident_export_s_rule_sets_translate():
    rule = Block((("property_path", "Severity"), ("operator", "Equals"), ("expected_value", "high"),
                  ("property_type", "String")))
    export = TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], RG),
        tf_block("data", ["azurerm_subscription", "current"], []),
        tf_block("resource", ["azurerm_security_center_automation", "incidents"], [
            ("name", "defender-incidents"), ("location", "eastus2"), ("resource_group_name", MAIN_RG),
            ("scopes", [ref("data.azurerm_subscription.current.id")]),
            ("action", Block((("type", "Workspace"), ("resource_id", "/subscriptions/0/w")))),
            ("source", Block((("event_source", "Alerts"), ("rule_set", Block((("rule", rule),))))))])))
    template = next(iter(arm_translation(M, {"terraform/main.tf": export}, WHAT).templates.values()))
    (automation,) = template.resources
    assert automation.properties["sources"] == [{"eventSource": "Alerts", "ruleSets": [{"rules": [{
        "propertyJPath": "Severity", "operator": "Equals", "expectedValue": "high", "propertyType": "String"}]}]}]


# ------------------------------------------------------------------ 5.6 (e3b): access, subscription and tenant scope

SCOPES = TfFile("", (
    tf_block("data", ["azurerm_resource_group", "main"], RG),
    tf_block("data", ["azurerm_subscription", "current"], []),
    tf_block("data", ["azurerm_key_vault", "kv"], [("name", "kv-a"), ("resource_group_name", MAIN_RG)]),
    tf_block("data", ["azurerm_policy_set_definition", "nist"], [("display_name", "NIST SP 800-53 Rev. 5")]),
    tf_block("data", ["azurerm_policy_set_definition", "il5"], [("display_name", "DoD Impact Level 5")]),
    tf_block("resource", ["azurerm_user_assigned_identity", "pf"], [
        ("name", "id-pf"), ("location", "eastus2"), ("resource_group_name", MAIN_RG)]),
    tf_block("resource", ["azurerm_role_assignment", "secret"], [
        ("scope", "${data.azurerm_key_vault.kv.id}/secrets/pf-admin"),
        ("role_definition_name", "Key Vault Secrets User"),
        ("principal_id", ref("azurerm_user_assigned_identity.pf.principal_id"))]),
    tf_block("resource", ["azurerm_role_assignment", "group"], [
        ("scope", ref("data.azurerm_resource_group.main.id")), ("role_definition_name", "Monitoring Reader"),
        ("principal_id", ref("azurerm_user_assigned_identity.pf.principal_id"))]),
    tf_block("resource", ["azurerm_subscription_policy_assignment", "nist"], [
        ("name", "ciam-nist"), ("policy_definition_id", ref("data.azurerm_policy_set_definition.nist.id")),
        ("subscription_id", ref("data.azurerm_subscription.current.id"))]),
    tf_block("resource", ["azurerm_subscription_policy_assignment", "il5"], [
        ("name", "ciam-il5"), ("policy_definition_id", ref("data.azurerm_policy_set_definition.il5.id")),
        ("subscription_id", ref("data.azurerm_subscription.current.id"))]),
    tf_block("resource", ["azurerm_security_center_subscription_pricing", "vms"], [
        ("tier", "Standard"), ("resource_type", "VirtualMachines")])))


def test_role_assignments_are_scoped_by_their_paths_and_named_from_them():
    t = arm_translation(M, {"terraform/main.tf": SCOPES}, WHAT)
    group = {r.symbol: r for r in _template(t, ("resourceGroup", "rg-a")).resources}
    secret = group["role_assignment_secret"]
    assert group[secret.scope].type == "Microsoft.KeyVault/vaults/secrets"
    assert group[group[secret.scope].parent].type == "Microsoft.KeyVault/vaults"
    assert secret.name == Call("guid", (Interp((ResourceId("vaults_kv_a"), "/secrets/pf-admin")),
                                        "azurerm_role_assignment.secret"))
    assert group["role_assignment_group"].scope is None                             # the group itself


def test_subscription_resources_have_their_template_and_unknown_initiatives_stay():
    t = arm_translation(M, {"terraform/main.tf": SCOPES}, WHAT)
    subscription = {r.symbol: r for r in _template(t, ("subscription", None)).resources}
    assert subscription["subscription_policy_assignment_nist"].properties["policyDefinitionId"] == Call(
        "tenantResourceId", ("Microsoft.Authorization/policySetDefinitions", "179d1daa-458f-4e47-8086-2a68d0d6c38f"))
    assert subscription["security_center_subscription_pricing_vms"].name == "VirtualMachines"
    assert _template(t, ("subscription", None)).scope == "subscription"
    assert t.placements["terraform"]["azurerm_subscription_policy_assignment.il5"].detail.startswith(
        "assigns the built-in initiative 'DoD Impact Level 5', whose id Microsoft doesn't publish")

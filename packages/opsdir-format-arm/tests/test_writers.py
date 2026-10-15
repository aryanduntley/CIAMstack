import json

import pytest

from opsdir.connectors.registry import format_named
from opsdir_format_arm.arm_json import as_arm_json, dependencies, template_doc
from opsdir_format_arm.bicep import as_bicep, bicep_files, bicep_string, bicep_value
from opsdir_format_arm.format import ARM_FORMAT, BICEP_FORMAT
from opsdir_format_arm.template import (ArmOutput, ArmResource, ArmTemplate, Interp, Param, ResourceId, ResourceName,
                                        indexed, resource_types, symbol)
from arm_samples import PLATFORM, SUBSCRIPTION


@pytest.mark.parametrize("parts, expected", [(("nsg", "pf-admin"), "nsg_pf_admin"), (("1st",), "r_1st"),
                                             (("Identity.PF",), "identity_pf")])
def test_symbols_are_bicep_identifiers(parts, expected):
    assert symbol(*parts) == expected


def test_a_template_is_checked_before_it_is_written():
    nsg = PLATFORM.resources[0]
    for bad, why in ((PLATFORM._replace(scope="region"), "unknown template scope"),
                     (PLATFORM._replace(resources=(nsg, nsg)), "used more than once: nsg_pf"),
                     (PLATFORM._replace(resources=(nsg._replace(depends_on=("nope",)),)), "doesn't hold: nope"),
                     (PLATFORM._replace(resources=(nsg, nsg._replace(symbol="x", parent="nsg_pf"))), "child type")):
        with pytest.raises(ValueError, match=why):
            indexed(bad)


def test_arm_json_is_what_bicep_compiles_the_same_template_to():
    doc = template_doc(PLATFORM)
    assert list(doc) == ["$schema", "contentVersion", "metadata", "parameters", "resources", "outputs"]
    assert doc["metadata"] == {"description": "ciam target/prod: platform"}       # comments are the Bicep file's
    assert [r["name"] for r in doc["resources"]] == [                             # existing ones aren't deployed
        "nsg-ciam-prod-pf", "[format('{0}/{1}', 'nsg-ciam-prod-pf', 'allow-https')]",
        "[format('id-{0}-pf', parameters('env'))]",
        "[guid(resourceId('Microsoft.KeyVault/vaults', 'kv-ciam-prod'), resourceId("
        "'Microsoft.ManagedIdentity/userAssignedIdentities', format('id-{0}-pf', parameters('env'))), 'read-secret')]",
        "to-law", "stciampf"]
    rule, ra, diag = doc["resources"][1], doc["resources"][3], doc["resources"][4]
    assert rule["dependsOn"] == ["[resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', "
                                 "format('id-{0}-pf', parameters('env')))]",         # sorted by symbol, as Bicep
                                 "[resourceId('Microsoft.Network/networkSecurityGroups', 'nsg-ciam-prod-pf')]"]
    assert ra["scope"] == "[resourceId('Microsoft.KeyVault/vaults', 'kv-ciam-prod')]" and "kv" not in str(
        ra["dependsOn"])
    assert ra["properties"]["principalId"] == ("[reference(resourceId('Microsoft.ManagedIdentity/"
                                               "userAssignedIdentities', format('id-{0}-pf', parameters('env'))), "
                                               "'2023-01-31').principalId]")
    assert ra["properties"]["description"] == "[not an expression] it's ${literal}"   # ARM reads it as text
    assert ra["properties"]["condition"] == "[[looks like one]"                         # escaped, or ARM evaluates
    assert diag["properties"]["workspaceId"] == (
        "[extensionResourceId(format('/subscriptions/{0}/resourceGroups/{1}', subscription().subscriptionId, "
        "'rg-ciam-shared'), 'Microsoft.OperationalInsights/workspaces', 'law-ciam-shared')]")
    assert doc["parameters"]["adminSecret"] == {"type": "securestring",
                                                "metadata": {"description": "set at deploy time"}}
    assert doc["outputs"]["ruleId"]["value"] == ("[resourceId('Microsoft.Network/networkSecurityGroups/"
                                                 "securityRules', 'nsg-ciam-prod-pf', 'allow-https')]")
    assert json.loads(as_arm_json(PLATFORM)) == doc


def test_dependencies_are_sorted_by_symbol_and_skip_existing_ones():
    index = indexed(PLATFORM)
    assert dependencies(index, index["diag"]) == ("identity_pf", "nsg_pf")       # explicit and scope, by symbol
    assert dependencies(index, index["ra_pf_read"]) == ("identity_pf",)          # kv_ciam is only read


def test_subscription_scope_ids_and_schema():
    doc = template_doc(SUBSCRIPTION)
    assert doc["$schema"].endswith("/subscriptionDeploymentTemplate.json#")
    assert doc["resources"][1]["dependsOn"] == [
        "[subscriptionResourceId('Microsoft.Security/pricings', 'VirtualMachines')]"]
    assert as_bicep(SUBSCRIPTION).startswith("targetScope = 'subscription'\n\nresource pricing_vms ")


def test_bicep_strings_and_values():
    assert bicep_string("it's ${x}\n\\") == "'it\\'s \\${x}\\n\\\\'"
    assert bicep_value({"a b": [1, True, None], "c": {}}) == "{\n  'a b': [\n    1\n    true\n    null\n  ]\n  c: {}\n}"
    assert bicep_value(Interp(("id-", Param("env"), "-pf"))) == "'id-${env}-pf'"


def test_the_bicep_file():
    text = as_bicep(PLATFORM)
    assert text.startswith("// Generated by opsdir: do not edit.\n// NOTE: a note\n\n"
                           "metadata description = 'ciam target/prod: platform'\n\n")
    assert "@description('set at deploy time')\n@secure()\nparam adminSecret string\n" in text
    assert ("resource nsg_pf_https 'Microsoft.Network/networkSecurityGroups/securityRules@2024-05-01' = {\n"
            "  name: 'allow-https'\n  parent: nsg_pf\n") in text
    assert ("// principals pingfederate and pingfederate-admin\n"
            "resource identity_pf 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {\n"
            "  name: 'id-${env}-pf'\n") in text
    assert ("resource law 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {\n"
            "  name: 'law-ciam-shared'\n  scope: resourceGroup('rg-ciam-shared')\n}") in text
    assert "  scope: kv_ciam\n  properties: {\n    principalId: identity_pf.properties.principalId\n" in text
    assert "  dependsOn: [\n    identity_pf\n  ]\n}" in text
    assert text.endswith("output subscriptionId string = subscription().subscriptionId\n\n"
                         "output principal string = identity_pf.properties.principalId\n")


def test_resource_types_leave_existing_ones_out():
    assert "Microsoft.KeyVault/vaults" not in resource_types(PLATFORM)
    assert resource_types(ArmTemplate("resourceGroup", None, (ArmResource("a", "Microsoft.X/y", "1", "a"),
                                                              ArmResource("b", "Microsoft.X/y", "1", "b")))) == (
        "Microsoft.X/y",)


def test_the_formats_are_registered():
    assert format_named("arm-json") is ARM_FORMAT and format_named("bicep") is BICEP_FORMAT
    assert BICEP_FORMAT.comment == ("//",) and ARM_FORMAT.comment == ()


def test_an_existing_child_reads_its_parents_group_and_a_literal_name_is_text():
    """A subnet under another group's virtual network is named in that group (as Bicep compiles it); an output of a
    resource's literal name is the name, not an expression."""
    vnet = ArmResource("vnet", "Microsoft.Network/virtualNetworks", "2025-09-01", "vnet-ciam", existing=True,
                       resource_group="rg-net")
    subnet = ArmResource("snet", "Microsoft.Network/virtualNetworks/subnets", "2025-09-01", "snet-ds", "vnet",
                         existing=True)
    nsg = ArmResource("nsg", "Microsoft.Network/networkSecurityGroups", "2025-09-01", "nsg-ds",
                      properties={"subnet": ResourceId("snet")})
    doc = template_doc(ArmTemplate("resourceGroup", "t", (vnet, subnet, nsg), (),
                                   (ArmOutput("name", "string", ResourceName("nsg")),)))
    assert doc["resources"][0]["properties"]["subnet"] == (
        "[extensionResourceId(format('/subscriptions/{0}/resourceGroups/{1}', subscription().subscriptionId, "
        "'rg-net'), 'Microsoft.Network/virtualNetworks/subnets', 'vnet-ciam', 'snet-ds')]")
    assert doc["outputs"]["name"]["value"] == "nsg-ds"


def test_a_module_is_a_nested_deployment_after_the_resources_and_named_by_its_group(module_sample):
    """As bicep build compiles a module: a Microsoft.Resources/deployments resource deploying its template inline at
    the group its scope names (inner expression scope), its params given as values, after every plain resource; what
    waits for it names it by extensionResourceId on that group."""
    doc = template_doc(module_sample.MODULES)
    assert [r["type"] for r in doc["resources"]] == [
        "Microsoft.ManagedIdentity/userAssignedIdentities", "Microsoft.App/jobs", "Microsoft.Resources/deployments",
        "Microsoft.Resources/deployments"]
    pull = doc["resources"][2]
    assert (pull["name"], pull["subscriptionId"], pull["resourceGroup"]) == (
        "grant-pull_a", "[split(parameters('registryId'), '/')[2]]", "[split(parameters('registryId'), '/')[4]]")
    assert pull["properties"]["expressionEvaluationOptions"] == {"scope": "inner"}
    assert pull["properties"]["parameters"]["principalId"] == {"value": (
        "[reference(resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', 'id-x'), "
        "'2023-01-31').principalId]")}
    assert pull["dependsOn"] == ["[resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', 'id-x')]"]
    inner = pull["properties"]["template"]["resources"]
    assert [r["type"] for r in inner] == ["Microsoft.Authorization/roleAssignments"]     # the existing target: no
    assert inner[0]["scope"] == "[resourceId('Microsoft.ContainerRegistry/registries', parameters('targetName'))]"
    assert module_sample.ACR_PULL in inner[0]["properties"]["roleDefinitionId"]
    assert doc["resources"][1]["dependsOn"] == [
        "[extensionResourceId(format('/subscriptions/{0}/resourceGroups/{1}', split(parameters('registryId'), '/')[2], "
        f"split(parameters('registryId'), '/')[4]), 'Microsoft.Resources/deployments', 'grant-{m}')]"
        for m in ("pull_a", "pull_b")]


def test_modules_of_one_template_share_one_bicep_file_beside_the_template(module_sample):
    MODULES, GRANT = module_sample.MODULES, module_sample.GRANT
    files = bicep_files(MODULES, "bicep/root/rg-a.bicep")
    assert sorted(files) == ["bicep/root/modules/role-assignment-registries.bicep", "bicep/root/rg-a.bicep"]
    main = files["bicep/root/rg-a.bicep"]
    assert main.count("'./modules/role-assignment-registries.bicep'") == 2
    assert "  scope: resourceGroup(split(registryId, '/')[2], split(registryId, '/')[4])\n" in main
    assert files["bicep/root/modules/role-assignment-registries.bicep"] == as_bicep(GRANT)
    other = module_sample.grant("pull_c")._replace(template=GRANT._replace(parameters=GRANT.parameters[:2] + (
        GRANT.parameters[2]._replace(description="the registry"),)))
    named = bicep_files(MODULES._replace(modules=(*MODULES.modules, other)), "x.bicep")
    assert sorted(named) == ["modules/role-assignment-registries-2.bicep", "modules/role-assignment-registries.bicep",
                             "x.bicep"]                                    # same name, another template: numbered


def test_a_module_is_checked_too(module_sample):
    MODULES, GRANT = module_sample.MODULES, module_sample.GRANT
    pull, other = MODULES.modules
    for bad, why in ((MODULES._replace(modules=(pull, pull, other)), "used more than once: pull_a"),
                     (MODULES._replace(modules=(pull._replace(depends_on=("nope",)), other)), "doesn't hold: nope"),
                     (MODULES._replace(modules=(pull._replace(template=GRANT._replace(scope="subscription")), other)),
                      "must be a resource group's"),
                     (MODULES._replace(resources=(*MODULES.resources[:1], MODULES.resources[1]._replace(
                         scope="pull_a"))), "neither a parent nor a scope")):
        with pytest.raises(ValueError, match=why):
            indexed(bad)

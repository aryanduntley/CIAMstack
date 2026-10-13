"""ARM templates (as Bicep compiles them) with their deployment read into an environment's servers and bindings: a
deployment that matches the record changes nothing; a changed template replaces the record's values; links written
with resourceId() resolve (NIC to subnet and backend pool, NSG to NIC); functions that aren't evaluated, resources that
can't be named, types not read and resources the deployment didn't produce are named; secure parameters and secret
values are never read, not even from a parameters file; the expression evaluator covers what deployments use."""
import json

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one
from opsdir_adapter_azure.arm import arm_resources, evaluate, read_arm
from support import SUPERS, after_import, imported_directory

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"
SUB = "00000000-0000-0000-0000-000000000000"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-ciam-prod"
DES = f"{RG}/providers/Microsoft.Compute/diskEncryptionSets/des-ciam-prod"
IMG = f"/subscriptions/{SUB}/resourceGroups/rg-ciam-images/providers/Microsoft.Compute/images/pingds-7.5.1-rhel9"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return imported_directory((), SUPERS, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="azure",
             ciamRegion="eastus2"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=vnet,{B}", ("ciamNetwork",), cn="vnet", ciamBindingRole="network", ciamCidr="10.60.0.0/16",
             ciamProviderRef="vnet-ciam-prod", ciamResourceGroup="rg-ciam-prod"),
        _row(f"cn=snet-ds,{B}", ("ciamSubnetBinding",), cn="snet-ds", ciamBindingRole="subnet-ds",
             ciamCidr="10.60.1.0/24", ciamProviderRef="vnet-ciam-prod/snet-ds"),
        _row(f"cn=ds-1,{ENV}", ("ciamServer",), cn="ds-1", ciamServerRole="ds", ciamHostname="ds-1.az.internal.test",
             ciamSubnet=f"cn=snet-ds,{B}", ciamPrivateIp="10.60.1.11", ciamZone="1",
             ciamInstanceSize="Standard_D4s_v5", ciamImageRef=IMG),
        _row(f"cn=svc-ldaps,{B}", ("ciamServiceName",), cn="svc-ldaps", ciamBindingRole="ds-ldaps-service",
             ciamFqdn="ldap.id.example.test", ciamDnsZone="id.example.test", ciamTargetRole="ds", ciamPort="1636",
             ciamFrontendIp="10.60.1.100", ciamEdgeFact="tls-mode passthrough", ciamTtlSeconds="300"),
        _row(f"cn=fw-app,{B}", ("ciamFirewallRule",), cn="fw-app", ciamBindingRole="fw-consumer-app",
             ciamSourceCidr=["10.30.0.0/24"], ciamPort="1636", ciamProtocol="tcp", ciamTargetRole="ds",
             ciamRulePriority="100"),
        _row(f"cn=secret-root,{B}", ("ciamSecretRef",), cn="secret-root", ciamBindingRole="ds-root-password",
             ciamRefUri="azkv://kv-ciam-prod/ds-root-password"),
        _row(f"cn=key-disk,{B}", ("ciamKeyRef",), cn="key-disk", ciamBindingRole="disk-encryption",
             ciamRefUri="azkv-key://kv-ciam-prod/keys/disk-cmk", ciamProviderRef=DES, ciamProtectionLevel="software",
             ciamAutoRotate="FALSE"),
        _row(f"cn=backup,{B}", ("ciamBackupTarget",), cn="backup", ciamBindingRole="backup-target",
             ciamStorageRef="azblob://stciamprod/ds-backups"),
        _row(f"cn=egress-pf,{B}", ("ciamEgress",), cn="egress-pf", ciamBindingRole="pf-egress",
             ciamCidr="203.0.113.200/32", ciamProviderRef="natgw-ciam-prod", ciamNatAllocation="static")))


def _template(size="Standard_D4s_v5", kty="RSA"):
    net = "Microsoft.Network"
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {"env": {"type": "string"}, "dsImage": {"type": "string"}, "vmSize": {"type": "string",
                                                                                        "defaultValue": size},
                       "rootPassword": {"type": "securestring"}, "pfPassword": {"type": "securestring"}},
        "variables": {"vnet": "[format('vnet-ciam-{0}', parameters('env'))]",
                      "subnetId": "[resourceId('Microsoft.Network/virtualNetworks/subnets', "
                                  "variables('vnet'), 'snet-ds')]",
                      "lb": "[concat('lb-ciam-', parameters('env'), '-svc-ldaps')]"},
        "resources": [
            {"type": f"{net}/networkSecurityGroups", "apiVersion": "2023-09-01",
             "name": "[format('nsg-ciam-{0}-ds', parameters('env'))]",
             "properties": {"securityRules": [{"name": "fw-app", "properties": {
                 "priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                 "sourceAddressPrefixes": ["10.30.0.0/24"], "destinationPortRanges": ["1636"]}}]}},
            {"type": f"{net}/virtualNetworks", "apiVersion": "2023-09-01", "name": "[variables('vnet')]",
             "properties": {"addressSpace": {"addressPrefixes": ["10.60.0.0/16"]}, "subnets": [
                 {"name": "snet-ds", "properties": {"addressPrefix": "10.60.1.0/24"}}]}},
            {"type": f"{net}/loadBalancers", "apiVersion": "2023-09-01", "name": "[variables('lb')]",
             "properties": {"frontendIPConfigurations": [{"name": "frontend", "properties": {
                                "privateIPAddress": "10.60.1.100", "subnet": {"id": "[variables('subnetId')]"}}}],
                            "backendAddressPools": [{"name": "servers"}],
                            "loadBalancingRules": [{"name": "tcp-1636", "properties": {"frontendPort": 1636,
                                                                                       "backendPort": 1636}}]}},
            {"type": f"{net}/networkInterfaces", "apiVersion": "2023-09-01", "name": "nic-ds-1",
             "properties": {"networkSecurityGroup": {"id": "[resourceId('Microsoft.Network/networkSecurityGroups', "
                                                           "format('nsg-ciam-{0}-ds', parameters('env')))]"},
                            "ipConfigurations": [{"name": "primary", "properties": {
                                "primary": True, "privateIPAddress": "10.60.1.11",
                                "subnet": {"id": "[variables('subnetId')]"},
                                "loadBalancerBackendAddressPools": [
                                    {"id": "[resourceId('Microsoft.Network/loadBalancers/"
                                           "backendAddressPools', variables('lb'), 'servers')]"}]}}]}},
            {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2024-03-01", "name": "ds-1", "zones": ["1"],
             "tags": {"Role": "ds", "Hostname": "ds-1.az.internal.test"},
             "properties": {"hardwareProfile": {"vmSize": "[parameters('vmSize')]"},
                            "osProfile": {"computerName": "ds-1", "adminPassword": "[parameters('rootPassword')]"},
                            "storageProfile": {"imageReference": {"id": "[parameters('dsImage')]"}},
                            "networkProfile": {"networkInterfaces": [
                                {"id": "[resourceId('Microsoft.Network/networkInterfaces', 'nic-ds-1')]"}]}}},
            {"type": f"{net}/privateDnsZones/A", "apiVersion": "2020-06-01", "name": "id.example.test/ldap",
             "properties": {"ttl": 300, "aRecords": [{"ipv4Address": "10.60.1.100"}]}},
            {"type": f"{net}/natGateways", "apiVersion": "2023-09-01", "name": "natgw-ciam-prod",
             "properties": {"publicIpAddresses": [
                 {"id": "[resourceId('Microsoft.Network/publicIPAddresses', 'pip-natgw')]"}]}},
            {"type": "Microsoft.KeyVault/vaults", "apiVersion": "2023-07-01", "name": "kv-ciam-prod",
             "properties": {"tenantId": "[subscription().tenantId]"},
             "resources": [{"type": "secrets", "apiVersion": "2023-07-01", "name": "pf-admin-password",
                            "properties": {"value": "[parameters('pfPassword')]"}}]},
            {"type": "Microsoft.KeyVault/vaults/secrets", "apiVersion": "2023-07-01",
             "name": "kv-ciam-prod/ds-root-password", "properties": {"value": "[parameters('rootPassword')]"}},
            {"type": "Microsoft.KeyVault/vaults/keys", "apiVersion": "2023-07-01", "name": "kv-ciam-prod/disk-cmk",
             "properties": {"kty": kty, "keySize": 3072, "rotationPolicy": {"lifetimeActions": [
                 {"action": {"type": "notify"}, "trigger": {"timeBeforeExpiry": "P30D"}}]}}},
            {"type": "Microsoft.Compute/diskEncryptionSets", "apiVersion": "2023-10-02", "name": "des-ciam-prod",
             "properties": {"activeKey": {"keyUrl": "[reference(resourceId('Microsoft.KeyVault/vaults/keys', "
                                                    "'kv-ciam-prod', 'disk-cmk')).keyUriWithVersion]"}}},
            {"type": "Microsoft.Storage/storageAccounts/blobServices/containers", "apiVersion": "2023-05-01",
             "name": "stciamprod/default/ds-backups", "properties": {"metadata": {}}},
            {"type": f"{net}/publicIPAddresses", "apiVersion": "2023-09-01",
             "name": "[format('pip-extra-{0}', copyIndex())]", "copy": {"name": "pips", "count": 2}},
            {"type": "Microsoft.KeyVault/vaults", "apiVersion": "2023-07-01", "name": "kv-shared", "existing": True}]}


def _deployment(produced=None):
    return {"id": f"{RG}/providers/Microsoft.Resources/deployments/ciam-prod", "name": "ciam-prod",
            "properties": {"provisioningState": "Succeeded",
                           "parameters": {"env": {"type": "String", "value": "prod"},
                                          "dsImage": {"type": "String", "value": IMG},
                                          "rootPassword": {"type": "SecureString"}},
                           **({"outputResources": [{"id": i} for i in produced]} if produced is not None else {})}}


def _files(template=None, deployment=None, extra=None):
    docs = {"template.json": template or _template(), "deployment.json": deployment or _deployment(), **(extra or {})}
    return {f"main/prod/ciam/{p}": json.dumps(d) for p, d in docs.items()}


def test_a_deployment_that_matches_the_record_changes_nothing():
    d = _record()
    imported = read_arm(_files(), d, ())
    assert len(imported.groups) == 9 and not import_changes(d, imported), imported.notices
    assert set(imported.notices) == {
        "ciam: copyIndex (1), reference (1) not evaluated; the attributes computed with them keep the record's values",
        "ciam: 1 resource(s) not deployed (condition false, or a name that isn't evaluated)",
        "ciam: resource types not read: Microsoft.KeyVault/vaults (1)",
        "main/prod: 1 secret resource(s) not in the record and naming no role, e.g. pf-admin-password (tag them Role, "
        "name them in roles.json, or record them); not imported"}


def test_a_changed_template_replaces_the_records_values():
    d = _record()
    after = after_import(d, read_arm(_files(template=_template(size="Standard_D8s_v5", kty="RSA-HSM")), d, ()))
    assert one(get(after, f"cn=ds-1,{ENV}"), "ciamInstanceSize") == "Standard_D8s_v5"
    assert (one(get(after, f"cn=key-disk,{B}"), "ciamProtectionLevel"),
            one(get(after, f"cn=key-disk,{B}"), "ciamProviderRef")) == ("hsm", DES)


def test_resource_id_links_resolve():
    resources = {r.kind: r for r in arm_resources({p.split("/", 2)[2]: t for p, t in _files().items()})[0]}
    assert (resources["server"].attrs["ciamPrivateIp"], resources["server"].links["ciamSubnet"]) == \
        (("10.60.1.11",), "vnet-ciam-prod/snet-ds")
    assert (resources["service"].attrs["ciamFqdn"], resources["service"].attrs["ciamTargetRole"]) == \
        (("ldap.id.example.test",), ("ds",))
    assert resources["firewall"].attrs["ciamTargetRole"] == ("ds",)


def test_secure_parameters_and_secret_values_are_never_read():
    params = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
              "parameters": {"rootPassword": {"value": "S3cr3t-Passw0rd!"}, "pfPassword": {"value": "An0ther!"}}}
    resources, notices = arm_resources({p.split("/", 2)[2]: t for p, t in
                                        _files(extra={"params.json": params}).items()})
    assert "S3cr3t" not in str(resources) and "An0ther" not in str(resources)


def test_what_the_deployment_did_not_produce_and_unknown_files_are_named():
    produced = [f"{RG}/providers/Microsoft.Compute/virtualMachines/ds-1"]
    resources, notices = arm_resources({p.split("/", 2)[2]: t for p, t in
                                        _files(deployment=_deployment(produced),
                                               extra={"notes.json": {"a": 1}}).items()})
    assert [r.kind for r in resources] == ["server"]
    assert "ciam/notes.json: not an ARM template, deployment or parameters file; not read" in notices
    assert any(n.startswith("ciam: 12 declared resource(s) the deployment didn't produce") for n in notices), notices


def test_a_template_and_parameters_file_without_a_deployment_still_link():
    params = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
              "parameters": {"env": {"value": "prod"}, "dsImage": {"value": IMG}}}
    resources, notices = arm_resources({"t/template.json": json.dumps(_template()),
                                        "t/params.json": json.dumps(params)})
    assert "t: no deployment (az deployment group show): subscription and resource group unknown; links within the " \
           "template resolve, disk encryption sets aren't read" in notices
    (server,) = [r for r in resources if r.kind == "server"]
    (key,) = [r for r in resources if r.kind == "key"]
    assert (server.links["ciamSubnet"], server.attrs["ciamImageRef"]) == ("vnet-ciam-prod/snet-ds", (IMG,))
    assert "ciamProviderRef" not in key.attrs


def test_the_evaluator_covers_what_deployments_use():
    ctx = {"subscription": SUB, "group": "rg", "variables": {"v": "[concat('a', parameters('p'))]"},
           "parameters": {"p": "b", "n": 2}}
    assert evaluate("[variables('v')]", ctx) == "ab"
    assert evaluate("[format('{0}-{1}', parameters('p'), 'c')]", ctx) == "b-c"
    assert evaluate("[resourceId('Microsoft.Network/virtualNetworks/subnets', 'v', 's')]", ctx) == \
        f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s"
    assert evaluate("[resourceId('other-rg', 'Microsoft.Network/publicIPAddresses', 'pip')]", ctx).startswith(
        f"/subscriptions/{SUB}/resourceGroups/other-rg/")
    assert evaluate("[if(equals(parameters('p'), 'b'), 'yes', 'no')]", ctx) == "yes"
    assert evaluate("[toUpper(last(split('a/b/c', '/')))]", ctx) == "C"
    assert evaluate("[resourceGroup().name]", ctx) == "rg" and evaluate("[subscription().subscriptionId]", ctx) == SUB
    assert evaluate("[[literal]", ctx) == "[literal]" and evaluate("plain", ctx) == "plain"
    assert evaluate("[uniqueString(resourceGroup().id)]", ctx) == ("<unknown>",)


def _tfstate(type_, name, attributes):
    """A Terraform state (format 4) holding one resource instance."""
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "serial": 1, "lineage": "l", "outputs": {},
                       "resources": [{"mode": "managed", "type": type_, "name": name,
                                      "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
                                      "instances": [{"schema_version": 0, "attributes": attributes,
                                                     "sensitive_attributes": []}]}]})


def test_the_terraform_root_kept_beside_the_deployments_is_read_with_them():
    """What a Bicep/ARM render keeps in Terraform (its side root, applied as a state) is read in the same import as
    the deployments: the environment's resources are both parts' together."""
    deployments = {p.split("/", 2)[2]: t for p, t in _files().items()}
    state = _tfstate("azurerm_key_vault_key", "audit", {
        "id": "https://kv-ciam-prod.vault.azure.net/keys/audit/1", "name": "audit", "key_type": "RSA",
        "key_vault_id": f"{RG}/providers/Microsoft.KeyVault/vaults/kv-ciam-prod",
        "versionless_id": "https://kv-ciam-prod.vault.azure.net/keys/audit", "tags": {"Role": "audit-key"}})
    alone, _ = arm_resources(deployments)
    side, _ = arm_resources({"terraform/main.tfstate": state})
    both, _ = arm_resources({**deployments, "terraform/main.tfstate": state})
    assert sorted(map(repr, both)) == sorted(map(repr, (*alone, *side))) and side


def test_subscription_tenant_and_extension_resource_ids_evaluate():
    ctx = {"subscription": "s1", "group": "g1", "parameters": {}, "variables": {}}
    assert evaluate("[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'abc')]", ctx) == \
        "/subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/abc"
    assert evaluate("[subscriptionResourceId('s2', 'Microsoft.Resources/resourceGroups', 'rg')]", ctx) == \
        "/subscriptions/s2/resourceGroups/rg"
    assert evaluate("[tenantResourceId('Microsoft.Authorization/policySetDefinitions', 'x')]", ctx) == \
        "/providers/Microsoft.Authorization/policySetDefinitions/x"
    assert evaluate("[extensionResourceId(resourceId('Microsoft.KeyVault/vaults', 'kv'), "
                    "'Microsoft.Authorization/roleAssignments', 'r1')]", ctx) == (
        "/subscriptions/s1/resourceGroups/g1/providers/Microsoft.KeyVault/vaults/kv/providers/"
        "Microsoft.Authorization/roleAssignments/r1")


def _state_of(pairs):
    """A Terraform state (format 4) holding the (type, attributes) pairs, one instance each."""
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "serial": 1, "lineage": "l", "outputs": {},
                       "resources": [{"mode": "managed", "type": t, "name": f"r{i}",
                                      "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
                                      "instances": [{"schema_version": 0, "attributes": a,
                                                     "sensitive_attributes": []}]}
                                     for i, (t, a) in enumerate(pairs)]})


KV = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-ciam-prod"
IDENTITY = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-ds"
SECRETS_USER = "4633458b-17de-408a-b874-0445c86b69e6"            # Key Vault Secrets User
CRYPTO_OFFICER = "14b46e9e-c2b7-41b4-b07b-48a6ebf60603"          # Key Vault Crypto Officer
GROUP = "5b2c0000-0000-4000-8000-0000000000a1"
NIST = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/policyAssignments/ciam-nist-800-53-r5"
NIST_SET = "/providers/Microsoft.Authorization/policySetDefinitions/179d1daa-458f-4e47-8086-2a68d0d6c38f"
GROUP_TEMPLATE = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                  "contentVersion": "1.0.0.0", "resources": [
    {"type": "Microsoft.ManagedIdentity/userAssignedIdentities", "apiVersion": "2023-01-31", "name": "id-ds",
     "location": "[resourceGroup().location]", "tags": {"Role": "identity-ds"}},
    {"type": "Microsoft.Authorization/roleAssignments", "apiVersion": "2022-04-01",
     "scope": "[resourceId('Microsoft.KeyVault/vaults/secrets', 'kv-ciam-prod', 'ds-root-password')]",
     "name": "[guid(resourceId('Microsoft.KeyVault/vaults', 'kv-ciam-prod'), 'read')]",
     "properties": {"roleDefinitionId": f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', "
                                        f"'{SECRETS_USER}')]",
                    "principalId": "[reference(resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', "
                                   "'id-ds'), '2023-01-31').principalId]"}},
    {"type": "Microsoft.Authorization/roleEligibilityScheduleRequests", "apiVersion": "2024-09-01-preview",
     "scope": "[resourceId('Microsoft.KeyVault/vaults/keys', 'kv-ciam-prod', 'disk-cmk')]",
     "name": "[guid(resourceId('Microsoft.KeyVault/vaults', 'kv-ciam-prod'), 'eligible')]",
     "properties": {"principalId": GROUP, "requestType": "AdminAssign",
                    "roleDefinitionId": f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', "
                                        f"'{CRYPTO_OFFICER}')]"}},
    {"type": "Microsoft.Network/dnsZones/MX", "apiVersion": "2018-05-01", "name": "example.test/@",
     "properties": {"TTL": 3600, "MXRecords": [{"preference": 10, "exchange": "mail1.example.test"}]}},
    {"type": "Microsoft.DBforPostgreSQL/flexibleServers", "apiVersion": "2025-08-01", "name": "psql-grants",
     "sku": {"name": "Standard_D2ds_v5", "tier": "GeneralPurpose"}, "location": "[resourceGroup().location]",
     "tags": {"Role": "pf-grants-db"},
     "properties": {"version": "16", "storage": {"storageSizeGB": 128},
                    "backup": {"backupRetentionDays": 14, "geoRedundantBackup": "Enabled"}}},
    {"type": "Microsoft.Authorization/locks", "apiVersion": "2020-05-01", "name": "psql-grants-no-delete",
     "scope": "[resourceId('Microsoft.DBforPostgreSQL/flexibleServers', 'psql-grants')]",
     "properties": {"level": "CanNotDelete"}},
    {"type": "Microsoft.OperationalInsights/workspaces", "apiVersion": "2025-07-01", "name": "law-audit",
     "tags": {"BindingRole": "audit-logs"}, "properties": {"sku": {"name": "PerGB2018"}, "retentionInDays": 90}},
    {"type": "Microsoft.Insights/metricAlerts", "apiVersion": "2026-01-01", "name": "ds-replication-lag",
     "location": "global", "tags": {"Realizes": "replication-lag", "BindingRole": "alarm-lag"},
     "properties": {"severity": 2, "actions": [{"actionGroupId": f"{RG}/providers/Microsoft.Insights/actionGroups/ag"}],
                    "criteria": {"allOf": [{"criterionType": "StaticThresholdCriterion", "metricNamespace": "CIAM/DS",
                                            "metricName": "ReplicationDelay", "operator": "GreaterThan",
                                            "threshold": 5000, "timeAggregation": "Average"}]}}},
    {"type": "Microsoft.Insights/webtests", "apiVersion": "2022-06-15", "name": "sso-alive", "kind": "standard",
     "tags": {"Realizes": "sso-alive", "BindingRole": "canary-sso"},
     "properties": {"Frequency": 600, "Request": {"RequestUrl": "https://sso.example.test/ping"}}}]}
SUBSCRIPTION_TEMPLATE = {**GROUP_TEMPLATE, "resources": [
    {"type": "Microsoft.Authorization/policyAssignments", "apiVersion": "2025-03-01", "name": "ciam-nist-800-53-r5",
     "properties": {"policyDefinitionId": "[tenantResourceId('Microsoft.Authorization/policySetDefinitions', "
                                          "'179d1daa-458f-4e47-8086-2a68d0d6c38f')]"}},
    {"type": "Microsoft.Authorization/policyExemptions", "apiVersion": "2026-01-01-preview",
     "name": "exc-EXC-7-nist-800-53-r5",
     "properties": {"policyAssignmentId": "[format('{0}/providers/Microsoft.Authorization/policyAssignments/"
                                          "ciam-nist-800-53-r5', subscription().id)]",
                    "exemptionCategory": "Waiver", "policyDefinitionReferenceIds": ["ref-a"],
                    "metadata": {"exception": "EXC-7"}}},
    {"type": "Microsoft.Security/alertsSuppressionRules", "apiVersion": "2019-01-01-preview",
     "name": "exc-EXC-8", "properties": {"alertType": "IpAnomaly", "state": "Enabled", "reason": "FalsePositive",
                                         "comment": "exception EXC-8"}}]}


def test_identities_grants_records_databases_monitoring_and_suppressions_read_as_their_state_does():
    """A resource group's deployment (a managed identity and its grant named by guid(), its principal by reference();
    a PIM eligibility request; a public zone's MX records as ARM spells them; a Flexible Server's SKU tier, storage
    and its lock, the group's location for its geo-backup copy; a workspace, a metric alert, a web test) and the
    subscription's (a policy assignment, an exemption of it, a Defender alert suppression rule) read to the same
    resources as the Terraform state of the same resources."""
    group = {"id": RG, "name": "rg-ciam-prod", "type": "Microsoft.Resources/resourceGroups", "location": "eastus2"}
    texts = {**{f"rg/{p}": json.dumps(d) for p, d in {"template.json": GROUP_TEMPLATE, "deployment.json": _deployment(),
                                                       "group.json": group}.items()},
             **{f"sub/{p}": json.dumps(d) for p, d in {
                 "template.json": SUBSCRIPTION_TEMPLATE,
                 "deployment.json": {"id": f"/subscriptions/{SUB}/providers/Microsoft.Resources/deployments/s",
                                     "name": "s", "properties": {"provisioningState": "Succeeded"}}}.items()}}
    roles = [("azurerm_role_definition", {"id": f"/providers/Microsoft.Authorization/roleDefinitions/{g}",
                                          "role_definition_id": g, "name": n})
             for n, g in (("Key Vault Secrets User", SECRETS_USER), ("Key Vault Crypto Officer", CRYPTO_OFFICER))]
    server = f"{RG}/providers/Microsoft.DBforPostgreSQL/flexibleServers/psql-grants"
    pairs = (*roles,
             ("azurerm_user_assigned_identity", {"id": IDENTITY, "name": "id-ds", "principal_id": "p-ds",
                                                 "tags": {"Role": "identity-ds"}}),
             ("azurerm_role_assignment", {"scope": f"{KV}/secrets/ds-root-password", "principal_id": "p-ds",
                                          "role_definition_id": f"/subscriptions/{SUB}/providers/Microsoft."
                                                                f"Authorization/roleDefinitions/{SECRETS_USER}"}),
             ("azurerm_pim_eligible_role_assignment", {
                 "scope": f"{KV}/keys/disk-cmk", "principal_id": GROUP,
                 "role_definition_id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/"
                                       f"{CRYPTO_OFFICER}"}),
             ("azurerm_dns_mx_record", {"name": "@", "zone_name": "example.test", "ttl": 3600,
                                        "record": [{"preference": 10, "exchange": "mail1.example.test"}]}),
             ("azurerm_postgresql_flexible_server", {"id": server, "name": "psql-grants", "version": "16",
                                                     "sku_name": "GP_Standard_D2ds_v5", "storage_mb": 131072,
                                                     "backup_retention_days": 14, "location": "eastus2",
                                                     "geo_redundant_backup_enabled": True,
                                                     "tags": {"Role": "pf-grants-db"}}),
             ("azurerm_management_lock", {"scope": server, "lock_level": "CanNotDelete"}),
             ("azurerm_log_analytics_workspace", {
                 "id": f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law-audit", "name": "law-audit",
                 "retention_in_days": 90, "tags": {"BindingRole": "audit-logs"}}),
             ("azurerm_monitor_metric_alert", {
                 "id": f"{RG}/providers/Microsoft.Insights/metricAlerts/ds-replication-lag",
                 "name": "ds-replication-lag", "tags": {"Realizes": "replication-lag", "BindingRole": "alarm-lag"},
                 "criteria": [{"metric_namespace": "CIAM/DS", "metric_name": "ReplicationDelay"}],
                 "action": [{"action_group_id": f"{RG}/providers/Microsoft.Insights/actionGroups/ag"}]}),
             ("azurerm_application_insights_standard_web_test", {
                 "id": f"{RG}/providers/Microsoft.Insights/webtests/sso-alive", "name": "sso-alive",
                 "frequency": 600, "tags": {"Realizes": "sso-alive", "BindingRole": "canary-sso"}}),
             ("azurerm_subscription_policy_assignment", {"id": NIST, "name": "ciam-nist-800-53-r5",
                                                         "subscription_id": f"/subscriptions/{SUB}",
                                                         "policy_definition_id": NIST_SET}),
             ("azurerm_subscription_policy_exemption", {
                 "id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/policyExemptions/"
                       "exc-EXC-7-nist-800-53-r5", "name": "exc-EXC-7-nist-800-53-r5", "policy_assignment_id": NIST,
                 "policy_definition_reference_ids": ["ref-a"], "metadata": json.dumps({"exception": "EXC-7"})}),
             ("azapi_resource", {"id": f"/subscriptions/{SUB}/providers/Microsoft.Security/alertsSuppressionRules/"
                                       "exc-EXC-8", "name": "exc-EXC-8",
                                 "type": "Microsoft.Security/alertsSuppressionRules@2019-01-01-preview",
                                 "body": {"properties": {"alertType": "IpAnomaly", "comment": "exception EXC-8"}}}))
    kinds = ("identity", "record", "database", "logs", "alarm", "canary", "guardrail", "suppression")
    deployed, _ = arm_resources(texts)
    from_state, _ = arm_resources({"terraform.tfstate": _state_of(pairs)})

    def kept(resources):
        return sorted((r.kind, r.name or r.ref, tuple(sorted(r.attrs.items()))) for r in resources if r.kind in kinds)
    assert kept(deployed) == kept(from_state)
    assert {k for k, *_ in kept(deployed)} == set(kinds)


AKS = f"{RG}/providers/Microsoft.ContainerService/managedClusters/aks-ciam"
AKS_SUBNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/vnet-ciam/subnets/aks"
EMAIL = f"{RG}/providers/Microsoft.Communication/emailServices/ecs-ciam/domains/example.test"
SELECTORS = {"DKIM": "selector1-azurecomm-prod-net._domainkey", "DKIM2": "selector2-azurecomm-prod-net._domainkey"}
MESSAGING_TEMPLATE = {**GROUP_TEMPLATE, "resources": [
    {"type": "Microsoft.ContainerService/managedClusters", "apiVersion": "2026-05-01", "name": "aks-ciam",
     "location": "[resourceGroup().location]", "tags": {"BindingRole": "k8s"},
     "properties": {"kubernetesVersion": "1.30.3", "oidcIssuerProfile": {"enabled": True},
                    "securityProfile": {"workloadIdentity": {"enabled": True}},
                    "addonProfiles": {"azurepolicy": {"enabled": True}, "omsagent": {"enabled": False},
                                      "azureKeyvaultSecretsProvider": {"enabled": True}},
                    "agentPoolProfiles": [{"name": "system", "mode": "System", "vmSize": "Standard_D2s_v5",
                                           "count": 2, "enableAutoScaling": True, "minCount": 2, "maxCount": 3,
                                           "availabilityZones": ["1", "2"], "vnetSubnetId": AKS_SUBNET}]}},
    {"type": "Microsoft.ContainerService/managedClusters/agentPools", "apiVersion": "2026-02-01",
     "name": "aks-ciam/ds", "properties": {"mode": "User", "vmSize": "Standard_E4s_v5", "count": 3,
                                           "availabilityZones": ["3"]}},
    {"type": "Microsoft.ServiceBus/namespaces", "apiVersion": "2026-01-01", "name": "sb",
     "location": "[resourceGroup().location]"},
    {"type": "Microsoft.ServiceBus/namespaces/queues", "apiVersion": "2026-01-01", "name": "sb/crm"},
    {"type": "Microsoft.EventGrid/topics", "apiVersion": "2025-02-15", "name": "audit",
     "location": "[resourceGroup().location]", "tags": {"Role": "audit-events"}},
    {"type": "Microsoft.Communication/emailServices", "apiVersion": "2026-03-18", "name": "ecs-ciam",
     "location": "global"},
    {"type": "Microsoft.Communication/emailServices/domains", "apiVersion": "2026-03-18",
     "name": "ecs-ciam/example.test", "location": "global", "tags": {"Role": "mail-sending"},
     "properties": {"domainManagement": "CustomerManaged", "verificationRecords": {
         k: {"type": "CNAME", "name": v, "value": f"{v}.azurecomm.net", "ttl": 3600} for k, v in SELECTORS.items()}}},
    {"type": "Microsoft.Authorization/roleAssignmentScheduleRequests", "apiVersion": "2024-09-01-preview",
     "scope": "[resourceId('Microsoft.KeyVault/vaults/keys', 'kv-ciam-prod', 'disk-cmk')]",
     "name": "[guid(resourceId('Microsoft.KeyVault/vaults', 'kv-ciam-prod'), 'active')]",
     "properties": {"principalId": GROUP, "requestType": "AdminAssign",
                    "roleDefinitionId": f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', "
                                        f"'{CRYPTO_OFFICER}')]"}}]}


def test_aks_messaging_email_and_pim_active_read_as_their_state_does():
    """A deployment's AKS cluster (its System pool inline, another pool as its own agentPools resource, add-ons by
    azurerm's profile keys), a Service Bus queue, an Event Grid topic, a Communication Services email domain with
    the DKIM selectors its verification names, and a PIM active assignment request read to the same resources as the
    Terraform state of the same resources."""
    texts = {f"rg/{p}": json.dumps(d) for p, d in {"template.json": MESSAGING_TEMPLATE,
                                                    "deployment.json": _deployment()}.items()}
    pairs = (("azurerm_kubernetes_cluster", {
                 "id": AKS, "name": "aks-ciam", "kubernetes_version": "1.30.3", "azure_policy_enabled": True,
                 "workload_identity_enabled": True, "oidc_issuer_enabled": True, "oms_agent": [],
                 "key_vault_secrets_provider": [{"secret_rotation_enabled": True}], "tags": {"BindingRole": "k8s"},
                 "default_node_pool": [{"name": "system", "vm_size": "Standard_D2s_v5", "min_count": 2,
                                        "max_count": 3, "zones": ["1", "2"], "vnet_subnet_id": AKS_SUBNET}]}),
             ("azurerm_kubernetes_cluster_node_pool", {"kubernetes_cluster_id": AKS, "name": "ds",
                                                       "vm_size": "Standard_E4s_v5", "node_count": 3, "zones": ["3"]}),
             ("azurerm_servicebus_queue", {"id": f"{RG}/providers/Microsoft.ServiceBus/namespaces/sb/queues/crm",
                                           "name": "crm"}),
             ("azurerm_eventgrid_topic", {"id": f"{RG}/providers/Microsoft.EventGrid/topics/audit", "name": "audit",
                                          "tags": {"Role": "audit-events"}}),
             ("azurerm_email_communication_service_domain", {
                 "id": EMAIL, "name": "example.test", "domain_management": "CustomerManaged",
                 "tags": {"Role": "mail-sending"},
                 "verification_records": [{k.lower(): [{"name": v}] for k, v in SELECTORS.items()}]}),
             ("azurerm_pim_active_role_assignment", {
                 "scope": f"{KV}/keys/disk-cmk", "principal_id": GROUP,
                 "role_definition_id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/"
                                       f"{CRYPTO_OFFICER}"}))
    kinds = ("cluster", "stream", "sending", "identity")
    deployed, _ = arm_resources(texts)
    from_state, _ = arm_resources({"terraform.tfstate": _state_of(pairs)})

    def kept(resources):
        return sorted((r.kind, r.ref, r.name, tuple(sorted(r.attrs.items())), tuple(sorted(r.links.items())))
                      for r in resources if r.kind in kinds)
    assert kept(deployed) == kept(from_state)
    assert {k for k, *_ in kept(deployed)} == set(kinds)
    aks = next(r for r in deployed if r.kind == "cluster")
    assert aks.attrs["ciamNodePool"] == ("ds: Standard_E4s_v5, 3-3", "system: Standard_D2s_v5, 2-3")
    assert aks.attrs["ciamClusterAddon"] == ("azure-policy", "key-vault-secrets-provider", "oidc-issuer",
                                             "workload-identity")
    assert next(r for r in deployed if r.kind == "sending").attrs["ciamDkimVerified"] == ("FALSE",)  # not in DNS
    grants = next(r for r in deployed if r.kind == "identity" and r.ref == GROUP).attrs["ciamGrant"]
    assert grants and not any("eligible" in g for g in grants)

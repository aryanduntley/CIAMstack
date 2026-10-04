"""ARM templates (as Bicep compiles them) with their deployment read into an environment's servers and bindings: a
deployment that matches the record changes nothing; a changed template replaces the record's values; links written
with resourceId() resolve (NIC to subnet and backend pool, NSG to NIC); functions that aren't evaluated, resources that
can't be named, types not read and resources the deployment didn't produce are named; secure parameters and secret
values are never read, not even from a parameters file; the expression evaluator covers what deployments use."""
import json

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one
from opsdir_adapter_azure.arm import arm_resources, evaluate, read_arm

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"
SUB = "00000000-0000-0000-0000-000000000000"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-ciam-prod"
DES = f"{RG}/providers/Microsoft.Compute/diskEncryptionSets/des-ciam-prod"
IMG = f"/subscriptions/{SUB}/resourceGroups/rg-ciam-images/providers/Microsoft.Compute/images/pingds-7.5.1-rhel9"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return make_directory((), {}, (
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
             ciamCidr="203.0.113.200/32", ciamProviderRef="natgw-ciam-prod")))


def _template(size="Standard_D4s_v5", kty="RSA"):
    net = "Microsoft.Network"
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {"env": {"type": "string"}, "dsImage": {"type": "string"}, "vmSize": {"type": "string",
                                                                                        "defaultValue": size},
                       "rootPassword": {"type": "securestring"}, "pfPassword": {"type": "securestring"}},
        "variables": {"vnet": "[format('vnet-ciam-{0}', parameters('env'))]",
                      "subnetId": "[resourceId('Microsoft.Network/virtualNetworks/subnets', variables('vnet'), 'snet-ds')]",
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
                                "loadBalancerBackendAddressPools": [{"id": "[resourceId('Microsoft.Network/loadBalancers/"
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
             "properties": {"publicIpAddresses": [{"id": "[resourceId('Microsoft.Network/publicIPAddresses', 'pip-natgw')]"}]}},
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


def _after(d, imported):
    scopes = [s.lower() for s, _ in imported.groups]
    kept = {n: e for n, e in d.entries.items() if n not in scopes}
    added = {e.norm: e for e in (*(c for c in imported.containers if c.norm not in d.entries),
                                 *(e for _, es in imported.groups for e in es))}
    return d._replace(entries={**kept, **added})


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
    after = _after(d, read_arm(_files(template=_template(size="Standard_D8s_v5", kty="RSA-HSM")), d, ()))
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
    resources, notices = arm_resources({p.split("/", 2)[2]: t for p, t in _files(extra={"params.json": params}).items()})
    assert "S3cr3t" not in str(resources) and "An0ther" not in str(resources)


def test_what_the_deployment_did_not_produce_and_unknown_files_are_named():
    produced = [f"{RG}/providers/Microsoft.Compute/virtualMachines/ds-1"]
    resources, notices = arm_resources({p.split("/", 2)[2]: t for p, t in
                                        _files(deployment=_deployment(produced), extra={"notes.json": {"a": 1}}).items()})
    assert [r.kind for r in resources] == ["server"]
    assert "ciam/notes.json: not an ARM template, deployment or parameters file; not read" in notices
    assert any(n.startswith("ciam: 12 declared resource(s) the deployment didn't produce") for n in notices), notices


def test_a_template_and_parameters_file_without_a_deployment_still_link():
    params = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
              "parameters": {"env": {"value": "prod"}, "dsImage": {"value": IMG}}}
    resources, notices = arm_resources({"t/template.json": json.dumps(_template()), "t/params.json": json.dumps(params)})
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

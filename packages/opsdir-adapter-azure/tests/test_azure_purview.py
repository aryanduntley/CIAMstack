"""Data discovery on Azure through Microsoft Purview scans recurring exactly every ciamRescanDays days: the account
referenced (ciamCatalogRef), never created; per blob container its storage account's data source, MSI scan, daily-
interval trigger and Storage Blob Data Reader grant; own data types as classification rules; Azure Government and a
cloud without the azapi add-on as comments and planner actions; prerequisites until recorded; read back from state."""
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.discovery import discovery_resources, render_discovery
from opsdir_adapter_azure.purview import (account_name, check_discovery_cadence, purview_inputs, purview_read,
                                          render_purview, renders)
from network_fixtures import ALPHA, context, entry, model

CLOUD = "cloud=alpha,ou=environments,dc=ciam-ops"
ACCOUNT = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-gov/providers/Microsoft.Purview/"
           "accounts/pview-ea")
STORES = (entry(ALPHA, "backups", "ciamObjectStore", ciamBindingRole="ds-backups",
                ciamStorageRef="azblob://eabackups/backups", ciamStorageVersioning="TRUE"),   # described: the stack's
          entry(ALPHA, "audit-sql", "ciamDatabase", ciamBindingRole="audit-db", ciamDbEngine="sqlserver"))
ALL_MET = ("catalog-scan-permission", "catalog-database-access", "catalog-custom-rules")


def dspm(**more):
    attrs = {"ciamBindingRole": "data-discovery", "ciamScansRole": ("ds-backups", "audit-db"),
             "ciamCustomIdentifier": ("cui-marking: CUI//[A-Z-]+",), "ciamRescanDays": "10",
             "ciamCatalogRef": ACCOUNT, **more}
    return entry(ALPHA, "dspm", "ciamDataDiscovery", **{k: v for k, v in attrs.items() if v is not None})


def _setup(*services, add_on=True, gov=False, met=()):
    cloud = (*((("add", "ciamProviderAddOn", ("azapi",)),) if add_on else ()),
             *((("replace", "ciamCloudEnvironment", ("usgovernment",)),) if gov else ()))
    changes = (*((LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)), *cloud)),)
                 if cloud else ()),
               *((LdifRecord(ALPHA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                                   ("replace", "ciamConfigurationMet", met))),) if met else ()))
    return model(alpha=(*STORES, *services), changes=changes)


def _plan(*services, **kw):
    d, alpha, beta = _setup(*services, **kw)
    return check_discovery_cadence(context(d, beta, alpha, cutover="2026-12-01"))


def test_the_account_is_named_by_its_resource_id():
    assert account_name(ACCOUNT) == "pview-ea" and account_name("/subscriptions/x/providers/Other/y") is None


def test_scans_every_n_days_with_the_accounts_identity():
    _, alpha, _ = _setup(dspm())
    out = "\n\n".join(as_text(render_purview(alpha)))
    assert renders(alpha)
    assert 'data "azapi_resource" "purview_pview_ea"' in out and f'resource_id            = "{ACCOUNT}"' in out
    assert 'type      = "Microsoft.Purview/accounts/Scanning/datasources@2023-09-01"' in out
    assert 'parent_id = "pview-ea.purview.azure.com/scan"' in out and 'name      = "dspm-eabackups"' in out
    assert 'endpoint = "https://eabackups.blob.core.windows.net/"' in out
    assert 'kind = "AzureStorageMsi"' in out and 'scanRulesetType = "System"' in out
    assert 'parent_id = "pview-ea.purview.azure.com/scan/datasources/dspm-eabackups/scans/dspm"' in out
    assert 'frequency = "Day"\n        interval  = 10\n        startTime = var.purview_scan_start' in out
    assert 'role_definition_name = "Storage Blob Data Reader"' in out
    assert "principal_id         = data.azapi_resource.purview_pview_ea.output.identity.principalId" in out
    assert 'classificationName = "CIAM.DSPM.CUI_MARKING"' in out and 'pattern = "CUI//[A-Z-]+"' in out
    assert "# dspm: Azure SQL database audit-db: register it in Purview" in out
    assert 'variable "purview_scan_start"' in "\n".join(as_text(purview_inputs(alpha)))


def test_the_grant_on_the_stacks_account_one_referenced_by_id_else_a_comment():
    add_on = (LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                               ("add", "ciamProviderAddOn", ("azapi",)))),)
    arm = ("/subscriptions/0/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/eabackups/blobServices/"
           "default/containers/backups")
    variants = {"held": {"ciamManagedBy": "cn=nobody,dc=ciam-ops"}, "referenced": {"ciamProviderRef": arm},
                "unknown": {}}
    out = {k: "\n".join(as_text(render_purview(model(alpha=(entry(ALPHA, "backups", "ciamObjectStore",
                                                          ciamBindingRole="ds-backups",
                                                          ciamStorageRef="azblob://eabackups/backups", **attrs),
                                                    STORES[1], dspm()), changes=add_on)[1])))
           for k, attrs in variants.items()}
    assert "# dspm: storage account eabackups: ask its keeper (cn=nobody,dc=ciam-ops) to give Purview account " \
           "pview-ea's managed identity Storage Blob Data Reader on it" in out["held"]
    assert 'scope                = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/' \
           'eabackups"' in out["referenced"]
    assert "# dspm: storage account eabackups: the record names no ARM id for it: give Purview account pview-ea's " \
           "managed identity Storage Blob Data Reader on it" in out["unknown"]


def test_nothing_without_an_account_or_an_interval():
    for service in (dspm(ciamCatalogRef=None), dspm(ciamRescanDays=None),
                    dspm(ciamManagedBy="cn=nobody,dc=ciam-ops")):
        _, alpha, _ = _setup(service)
        assert render_purview(alpha) == () and purview_inputs(alpha) == () and not renders(alpha)


def test_azure_government_and_no_add_on_are_comments():
    _, gov, _ = _setup(dspm(), gov=True)
    assert as_text(render_purview(gov)) == ("# dspm: Microsoft Purview scans every 10 days aren't rendered in Azure "
                                   "Government: azapi's Purview token audience there is unverified (see the plan)",)
    _, bare, _ = _setup(dspm(), add_on=False)
    assert as_text(render_purview(bare)) == ("# dspm: Microsoft Purview scans every 10 days need the azapi add-on "
                                    "(ciamProviderAddOn azapi): not rendered",)
    assert not renders(gov) and not renders(bare) and purview_inputs(gov) == ()


def test_defenders_comments_point_at_the_scans():
    _, alpha, _ = _setup(dspm(ciamRescanDays="3"))
    out = "\n".join(as_text(render_discovery(alpha)))
    assert "complete cataloguing needs Microsoft Purview scanning: its scans below" in out
    assert "refreshes object storage within eight days" not in out          # the scans honour 3 days
    assert "(the Purview scans have classification rules of them below)" in out
    _, alone, _ = _setup(dspm(ciamCatalogRef=None, ciamRescanDays="3"))
    assert "Purview scanning: not rendered" in "\n".join(as_text(render_discovery(alone)))


def test_the_plan_names_the_trigger_and_asks_for_the_prerequisites():
    found = _plan(dspm())
    assert found.ok == ("alpha/prod's data discovery `dspm` examines its stores every 10 days: Microsoft Purview "
                        "account pview-ea's scan trigger (every 10 days).",)
    actions = [a[1] for a in found.actions]
    assert len(actions) == 3 and all(a.startswith("alpha/prod's data discovery `dspm` through Microsoft Purview: ")
                                     for a in actions)
    assert any("Data Source Administrator and Data Curator" in a and "catalog-scan-permission" in a for a in actions)
    assert any("db_datareader" in a for a in actions) and any("custom scan rule set" in a for a in actions)
    assert _plan(dspm(), met=ALL_MET).actions == ()


def test_the_plan_names_what_keeps_the_interval_from_being_exact():
    unnamed = [a[1] for a in _plan(dspm(ciamCatalogRef=None)).actions]
    assert unnamed == ["alpha/prod's data discovery `dspm` asks for every 10 days: name the organization's Microsoft "
                       "Purview account it scans through (ciamCatalogRef: its resource id; Purview allows one account "
                       "per tenant); Defender for Cloud's sensitive data discovery refreshes object storage within "
                       "eight days of a change and databases weekly."]
    gov = [a[1] for a in _plan(dspm(), gov=True).actions]
    assert len(gov) == 1 and "aren't rendered in Azure Government" in gov[0] and "pview-ea.purview.azure.us" in gov[0]
    bare = [a[1] for a in _plan(dspm(), add_on=False).actions]
    assert len(bare) == 1 and "allow the azapi add-on (ciamProviderAddOn azapi)" in bare[0]
    assert _plan(dspm(), gov=True).ok == () and _plan(dspm(ciamRescanDays=None)).actions == ()


def test_read_back_the_interval_from_the_trigger():
    sub = "/subscriptions/00000000-0000-0000-0000-000000000000"
    plane = "azapi_data_plane_resource"
    pairs = [("azurerm_security_center_subscription_pricing", {
                 "id": f"{sub}/providers/Microsoft.Security/pricings/CloudPosture", "tier": "Standard",
                 "resource_type": "CloudPosture", "extension": [{"name": "SensitiveDataDiscovery"}]}),
             (plane, {"type": "Microsoft.Purview/accounts/Scanning/datasources@2023-09-01",
                      "parent_id": "pview-ea.purview.azure.com/scan", "name": "dspm-eabackups",
                      "body": {"kind": "AzureStorage",
                               "properties": {"endpoint": "https://eabackups.blob.core.windows.net/"}}}),
             (plane, {"type": "Microsoft.Purview/accounts/Scanning/datasources/scans/triggers@2023-09-01",
                      "parent_id": "pview-ea.purview.azure.com/scan/datasources/dspm-eabackups/scans/dspm",
                      "name": "default",
                      "body": {"properties": {"recurrence": {"frequency": "Day", "interval": 10}}}}),
             (plane, {"type": "Microsoft.Purview/accounts/Scanning/datasources/scans/triggers@2023-09-01",
                      "parent_id": "pview-ea.purview.azure.com/scan/datasources/x/scans/y", "name": "default",
                      "body": {"properties": {"recurrence": {"frequency": "Week", "interval": 1}}}})]
    (read,) = purview_read(pairs)
    assert read == ("dspm", "pview-ea", ("eabackups",), 10)
    (r,) = discovery_resources(pairs)
    assert r.attrs == {"ciamRescanDays": ("10",)}
    assert discovery_resources(pairs[:1])[0].attrs == {}

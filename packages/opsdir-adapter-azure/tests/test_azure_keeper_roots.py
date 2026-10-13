"""Where the Azure render places what someone else keeps (5.7, decisions 1860, 2732): a keeper that takes generated
infrastructure gets its own complete root (terraform/landing-zone/<party>/, with the subscription input described);
one that doesn't is named in the stack's main.tf with what it is asked for, and nothing of it is rendered."""
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.terraform import render_files
from network_fixtures import ALPHA, entry, model

DBA = "cn=dba,ou=owners,dc=ciam-ops"
LZ = "cn=lz,ou=owners,dc=ciam-ops"


def _owners(dba_takes=None, lz_takes="TRUE"):
    def party(dn, cn, takes):
        return (f"dn: {dn}\nobjectClass: top\nobjectClass: ciamParty\ncn: {cn}\nciamOwnerKind: team\n"
                + (f"ciamTakesGeneratedInfra: {takes}\n" if takes else ""))
    return ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
            party(DBA, "dba", dba_takes), party(LZ, "lz", lz_takes))


DB = entry(ALPHA, "db-dba", "ciamDatabase", ciamBindingRole="reports-db", ciamDbEngine="postgresql",
           ciamManagedBy=DBA)
GUARDRAIL = entry(ALPHA, "fence", "ciamGuardrail", ciamBindingRole="fence",
                  ciamGuardrailKind="policy-assignment",
                  ciamDenies="audit-log-disable", ciamOwner=LZ)


# the landing zone's identities look their resource group up by the network's
GROUP = LdifRecord(f"cn=net,ou=bindings,{ALPHA}", "modify", {}, (("replace", "ciamResourceGroup", ("rg-ciam",)),))


def _files(*records, **owners):
    return as_text(render_files(model(alpha=records, tree=_owners(**owners), changes=(GROUP,))[1], None))


def test_a_keeper_that_takes_generated_infrastructure_gets_a_complete_root_of_its_own():
    files = _files(DB, dba_takes="TRUE")
    main, providers = files["terraform/landing-zone/dba/main.tf"], files["terraform/landing-zone/dba/providers.tf"]
    assert 'resource "azurerm_postgresql_flexible_server" "db_dba"' in main
    assert "Azure infrastructure kept by dba" in main
    assert "azurerm_postgresql_flexible_server" not in files["terraform/main.tf"]
    assert 'provider "azurerm"' in providers and "The subscription prod runs in" in providers
    assert "azapi" not in providers and "resource_providers_to_register" not in providers


def test_a_keeper_that_does_not_is_named_with_what_it_is_asked_for_and_nothing_of_it_rendered():
    files = _files(DB)
    assert not any("landing-zone/dba" in p for p in files)
    assert not any('resource "azurerm_postgresql_flexible_server" "db_dba"' in text for text in files.values())
    assert ("# db-dba: kept by dba, not rendered here (" in files["terraform/main.tf"]
            and "azurerm_postgresql_flexible_server.db_dba" in files["terraform/main.tf"])


def test_a_landing_zone_whose_keeper_takes_none_is_named_too():
    taken, asked = _files(GUARDRAIL), _files(GUARDRAIL, lz_takes=None)
    assert "policy_assignment" in taken["terraform/landing-zone/main.tf"]
    assert "resource_providers_to_register" in taken["terraform/landing-zone/providers.tf"]
    assert not any(p.startswith("terraform/landing-zone/") for p in asked)
    assert "# The landing zone: kept by lz, not rendered here (" in asked["terraform/main.tf"]
    assert "Register these resource providers in the subscription" in asked["terraform/providers.tf"]


def test_a_vm_s_disk_someone_else_keeps_goes_to_their_root_with_its_attachment_reading_the_vm():
    from network_fixtures import BETA
    volume = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
                   ciamVolumeKind="data", ciamVolumeSizeGb="200", ciamManagedBy=DBA)
    files = as_text(render_files(model(beta=(volume,), tree=_owners(dba_takes="TRUE"))[2], None))
    main = files["terraform/landing-zone/dba/main.tf"]
    assert 'resource "azurerm_managed_disk" "ds_1_vol_ds_data"' in main
    assert "virtual_machine_id = var.azurerm_linux_virtual_machine_ds_1_id" in main
    assert "azurerm_managed_disk" not in files["terraform/main.tf"]

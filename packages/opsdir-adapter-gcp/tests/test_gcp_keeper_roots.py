"""Where the Google Cloud render places what someone else keeps (5.7, decisions 1860, 2732): a keeper that takes
generated infrastructure gets its own complete root (terraform/landing-zone/<party>/, the provider in the project
without the stack's region input, the project input described); one that doesn't is named in the stack's main.tf with
what it is asked for, and nothing of it is rendered."""
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_gcp.terraform import render_files
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
GUARDRAIL = entry(ALPHA, "fence", "ciamGuardrail", ciamBindingRole="fence", ciamDenies="public-storage", ciamOwner=LZ)


def _files(*records, **owners):
    return as_text(render_files(model(alpha=records, tree=_owners(**owners))[1], None))


def test_a_keeper_that_takes_generated_infrastructure_gets_a_complete_root_of_its_own():
    files = _files(DB, dba_takes="TRUE")
    main, providers = files["terraform/landing-zone/dba/main.tf"], files["terraform/landing-zone/dba/providers.tf"]
    assert 'resource "google_sql_database_instance" "db_dba"' in main
    assert "Google Cloud infrastructure kept by dba" in main
    assert "google_sql_database_instance" not in files["terraform/main.tf"]
    assert 'provider "google"' in providers and "The project prod runs in" in providers
    provider = providers[providers.index('provider "google"'):].split("}", 1)[0]
    assert "region" not in provider                         # the stack's own: here only what reads it (the instance)
    assert 'variable "region"' in providers and "region = var.region" in main


def test_a_keeper_that_does_not_is_named_with_what_it_is_asked_for_and_nothing_of_it_rendered():
    files = _files(DB)
    assert not any("landing-zone/dba" in p for p in files)
    assert not any('resource "google_sql_database_instance" "db_dba"' in text for text in files.values())
    assert ("# db-dba: kept by dba, not rendered here (" in files["terraform/main.tf"]
            and "google_sql_database_instance.db_dba" in files["terraform/main.tf"])


def test_a_landing_zone_whose_keeper_takes_none_is_named_too():
    taken, asked = _files(GUARDRAIL), _files(GUARDRAIL, lz_takes=None)
    assert "google_org_policy_policy" in taken["terraform/landing-zone/main.tf"]
    assert not any(p.startswith("terraform/landing-zone/") for p in asked)
    assert "# The landing zone: kept by lz, not rendered here (" in asked["terraform/main.tf"]


def test_a_disk_follows_a_schedule_another_root_writes_through_an_input():
    from network_fixtures import BETA
    volume = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
                   ciamVolumeKind="data", ciamVolumeSizeGb="200", ciamSnapshotPolicyRole="snapshots-team")
    policy = entry(BETA, "snapshots-team", "ciamSnapshotPolicy", ciamBindingRole="snapshots-team",
                   ciamRetentionDays="7", ciamSnapshotAt="03:00", ciamManagedBy=DBA)
    files = as_text(render_files(model(beta=(volume, policy), tree=_owners(dba_takes="TRUE"))[2], None))
    assert 'resource "google_compute_resource_policy" "snapshots_team"' in files["terraform/landing-zone/dba/main.tf"]
    stack = files["terraform/main.tf"]
    assert 'resource "google_compute_disk_resource_policy_attachment" "ds_1_vol_ds_data"' in stack
    assert "name = var.google_compute_resource_policy_snapshots_team_name" in stack
    assert 'output "google_compute_resource_policy_snapshots_team_name"' in files[
        "terraform/landing-zone/dba/providers.tf"]


def test_a_budget_another_team_keeps_renders_in_their_root_with_the_budget_api_settings():
    from opsdir.core.interchange.ldif import LdifRecord
    billing = LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {}, (
        ("add", "objectClass", ("ciamCloudAccount",)), ("replace", "ciamAccountRef", ("ciam-prod",)),
        ("replace", "ciamBillingAccountRef", ("billingAccounts/0A1B2C-3D4E5F-6A7B8C",))))
    budget = entry(ALPHA, "monthly", "ciamBudget", ciamBindingRole="budget", ciamBudgetAmount="5000",
                   ciamManagedBy=DBA)
    m = model(alpha=(budget,), tree=_owners(dba_takes="TRUE"), changes=(billing,))[1]
    files = as_text(render_files(m, None))
    assert 'resource "google_billing_budget" "monthly"' in files["terraform/landing-zone/dba/main.tf"]
    assert "user_project_override = true" in files["terraform/landing-zone/dba/providers.tf"]
    assert "google_billing_budget" not in files.get("terraform/landing-zone/main.tf", "")

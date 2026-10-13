"""Where the AWS render places what someone else keeps (5.7, decisions 1860, 2732): a keeper that takes generated
infrastructure gets its own complete root (terraform/landing-zone/<party>/, the platform's providers less the account
pin); one that doesn't is named in the stack's main.tf with what it is asked for, and nothing of it is rendered."""
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_aws.terraform import render_files
from network_fixtures import ALPHA, BETA, entry, model

DBA = "cn=dba,ou=owners,dc=ciam-ops"
LZ = "cn=lz,ou=owners,dc=ciam-ops"


def _owners(dba_takes=None, lz_takes="TRUE"):
    def party(dn, cn, takes):
        return (f"dn: {dn}\nobjectClass: top\nobjectClass: ciamParty\ncn: {cn}\nciamOwnerKind: team\n"
                + (f"ciamTakesGeneratedInfra: {takes}\n" if takes else ""))
    return ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
            party(DBA, "dba", dba_takes), party(LZ, "lz", lz_takes))


DB = entry(ALPHA, "db-dba", "ciamDatabase", ciamBindingRole="reports-db", ciamDbEngine="mysql", ciamManagedBy=DBA)
GUARDRAIL = entry(ALPHA, "fence", "ciamGuardrail", ciamBindingRole="fence", ciamDenies="audit-log-disable",
                  ciamOwner=LZ)


def _files(*records, **owners):
    return as_text(render_files(model(alpha=records, tree=_owners(**owners))[1], None))


def test_a_keeper_that_takes_generated_infrastructure_gets_a_complete_root_of_its_own():
    files = _files(DB, dba_takes="TRUE")
    main, providers = files["terraform/landing-zone/dba/main.tf"], files["terraform/landing-zone/dba/providers.tf"]
    assert 'resource "aws_db_instance" "db_dba"' in main and "AWS infrastructure kept by dba" in main
    assert 'resource "aws_db_instance" "db_dba"' not in files["terraform/main.tf"]
    assert 'provider "aws"' in providers and "allowed_account_ids" not in providers and "archive" not in providers


def test_a_keeper_that_does_not_is_named_with_what_it_is_asked_for_and_nothing_of_it_rendered():
    files = _files(DB)
    assert not any("landing-zone/dba" in p for p in files)
    assert not any('resource "aws_db_instance" "db_dba"' in text for text in files.values())
    assert ("# db-dba: kept by dba, not rendered here (aws_security_group.reports_db, aws_db_instance.db_dba): they "
            "take no generated infrastructure, so it is asked of them") in files["terraform/main.tf"]


def test_a_landing_zone_whose_keeper_takes_none_is_named_too():
    taken, asked = _files(GUARDRAIL), _files(GUARDRAIL, lz_takes=None)
    assert 'resource "aws_organizations_policy" "fence"' in taken["terraform/landing-zone/main.tf"]
    assert not any(p.startswith("terraform/landing-zone/") for p in asked)
    assert ("# The landing zone: kept by lz, not rendered here (aws_organizations_policy.fence"
            in asked["terraform/main.tf"])


def test_a_server_s_volume_someone_else_keeps_goes_to_their_root_with_its_attachment_reading_the_instance():
    volume = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
                   ciamVolumeKind="data", ciamVolumeSizeGb="200", ciamManagedBy=DBA)
    files = as_text(render_files(model(beta=(volume,), tree=_owners(dba_takes="TRUE"))[2], None))
    main, providers = files["terraform/landing-zone/dba/main.tf"], files["terraform/landing-zone/dba/providers.tf"]
    assert 'resource "aws_ebs_volume" "ds_1_vol_ds_data"' in main
    assert "instance_id = var.aws_instance_ds_1_id" in main and 'variable "aws_instance_ds_1_id"' in providers
    assert 'output "aws_instance_ds_1_id"' in files["terraform/providers.tf"]
    assert "aws_ebs_volume" not in files["terraform/main.tf"]


def _backup(vault_ref=None):
    vault = entry(BETA, "vault-dba", "ciamBackupVault", ciamBindingRole="vault-dba", ciamManagedBy=DBA,
                  **({"ciamProviderRef": vault_ref} if vault_ref else {}))
    plan = entry(BETA, "backup-ds", "ciamBackupPlan", ciamBindingRole="backup-ds", ciamProtectsRole="ds",
                 ciamBackupVaultRole="vault-dba", ciamRetentionDays="7")
    return vault, plan


def test_a_plan_targets_a_vault_another_root_writes_through_an_input_or_an_asked_one_by_its_name():
    files = as_text(render_files(model(beta=_backup(), tree=_owners(dba_takes="TRUE"))[2], None))
    assert 'resource "aws_backup_vault" "vault_dba"' in files["terraform/landing-zone/dba/main.tf"]
    assert "target_vault_name = var.aws_backup_vault_vault_dba_name" in files["terraform/main.tf"]
    arn = "arn:aws:backup:us-east-1:111122223333:backup-vault:dba-vault"
    asked = as_text(render_files(model(beta=_backup(arn), tree=_owners())[2], None))
    assert 'target_vault_name = "dba-vault"' in asked["terraform/main.tf"]
    assert "# vault-dba: kept by dba, not rendered here (aws_backup_vault.vault_dba" in asked["terraform/main.tf"]


def test_an_organization_trail_the_landing_zone_keeps_renders_in_its_root():
    bucket = entry(ALPHA, "audit-logs", "ciamObjectStore", ciamBindingRole="audit-logs",
                   ciamStorageRef="s3://example-ciam-audit")
    trail = entry(ALPHA, "org-trail", "ciamAuditTrail", ciamBindingRole="org-trail", ciamAuditScope="organization",
                  ciamLogDestinationRole="audit-logs", ciamManagedBy=LZ)
    from opsdir.core.interchange.ldif import LdifRecord
    management = LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {}, (
        ("add", "objectClass", ("ciamCloudAccount",)), ("replace", "ciamManagementRef", ("999988887777",))))
    files = as_text(render_files(model(alpha=(GUARDRAIL, bucket, trail), tree=_owners(),
                                       changes=(management,))[1], None))
    lz = files["terraform/landing-zone/main.tf"]
    assert 'resource "aws_cloudtrail" "org_trail"' in lz and "is_organization_trail         = true" in lz
    assert "provider                      = aws.management" in lz and 'alias               = "management"' in \
        files["terraform/landing-zone/providers.tf"]
    assert "aws_cloudtrail" not in files["terraform/main.tf"]
    assert "# org-trail: organization-wide: enabled for every account by" in files["terraform/main.tf"]


def test_a_log_group_another_team_keeps_renders_in_their_root():
    group = entry(ALPHA, "app-logs", "ciamLogDestination", ciamBindingRole="app-logs", ciamDestinationKind="log-group",
                  ciamProviderRef="arn:aws:logs:us-east-1:111122223333:log-group:/ciam/app:*", ciamRetentionDays="30",
                  ciamManagedBy=DBA)
    files = _files(group, dba_takes="TRUE")
    assert 'resource "aws_cloudwatch_log_group" "app_logs"' in files["terraform/landing-zone/dba/main.tf"]
    assert "aws_cloudwatch_log_group" not in files["terraform/main.tf"]


def _scoped(scope, *records, **owners):
    m = model(alpha=records, tree=_owners(**owners))[1]._replace(scope=scope)
    return as_text(render_files(m, None))


def test_a_keeper_scoped_render_gives_its_complete_root_whatever_it_takes():
    from opsdir.core.environment import Scope
    files = _scoped(Scope("keeper", (DBA,)), DB)                     # dba takes no generated infrastructure
    assert sorted(files) == ["terraform/landing-zone/dba/main.tf", "terraform/landing-zone/dba/providers.tf"]
    assert 'resource "aws_db_instance" "db_dba"' in files["terraform/landing-zone/dba/main.tf"]


def test_a_class_or_bindings_scope_is_its_own_root_reading_the_rest_through_inputs():
    from opsdir.core.environment import Scope
    volume = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
                   ciamVolumeKind="data", ciamVolumeSizeGb="200")
    m = model(beta=(volume,), tree=_owners())[2]
    files = as_text(render_files(m._replace(scope=Scope("class", ("ciamVolume",))), None))
    assert sorted(files) == ["terraform/slice/main.tf", "terraform/slice/providers.tf"]
    assert "instance_id = var.aws_instance_ds_1_id" in files["terraform/slice/main.tf"]
    assert "a slice rendered on request" in files["terraform/slice/main.tf"]
    same = as_text(render_files(m._replace(scope=Scope("bindings", (f"cn=vol-ds-data,ou=bindings,{BETA}",))), None))
    assert same["terraform/slice/main.tf"].split("\n", 3)[3] == files["terraform/slice/main.tf"].split("\n", 3)[3]

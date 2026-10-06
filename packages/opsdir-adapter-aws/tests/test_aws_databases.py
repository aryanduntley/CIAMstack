"""Managed databases on AWS: rendered as an RDS instance or an Aurora cluster with its subnet group, security group,
parameter group (TLS where it isn't the engine's default) and key, its master password kept by RDS (never in the
Terraform or the record), adopted when it exists; one someone else keeps is named. Read back from Terraform state and
the CLI: engine, edition, version, endpoint, availability, TLS, backups, parameters, and its subnets, key and master
secret as roles; the password is never read."""
import json
import re

from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.databases import (aws_engine, database_resources, neutral_engine, parameter_family,
                                          render_databases)
from opsdir_adapter_aws.inventory import state_resources
from network_fixtures import ALPHA, entry, model

ARN = "arn:aws:rds:us-east-1:111122223333:db:db-grants"
SECRET_ARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds!db-1"
KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/k-1"
DB = dict(ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql", ciamDbEngineVersion="16.4",
          ciamInstanceSize="db.r6g.large", ciamDbStorageGb="100", ciamPort="5432",
          ciamDbHighAvailability="zone-redundant", ciamDbTlsRequired="TRUE", ciamRetentionDays="14",
          ciamDbPointInTime="TRUE", ciamDbDeletionProtection="TRUE", ciamEncryptedByRole="db-key",
          ciamDbParameter="log_min_duration_statement=500", ciamSubnetRole="subnet-ds")
KEY = entry(ALPHA, "key-db", "ciamKeyRef", ciamBindingRole="db-key", ciamRefUri=f"aws-kms://{KEY_ARN}")


def _render(*records):
    return "\n\n".join(render_databases(model(alpha=records)[1]))


def test_engine_names_and_parameter_families():
    assert [aws_engine(e, ed, s) for e, ed, s in (("postgresql", None, None), ("postgresql", None, "aurora"),
                                                    ("sqlserver", "enterprise", "rds"), ("oracle", None, "rds"))] == \
        ["postgres", "aurora-postgresql", "sqlserver-ee", "oracle-se2"]
    assert [neutral_engine(n) for n in ("postgres", "aurora-mysql", "sqlserver-ex", "oracle-ee", "db2-se")] == [
        ("postgresql", None, "rds"), ("mysql", None, "aurora"), ("sqlserver", "express", "rds"),
        ("oracle", "enterprise", "rds"), (None, None, None)]
    assert [parameter_family(n, v) for n, v in (("postgres", "16.4"), ("aurora-postgresql", "16.2"),
                                                ("mysql", "8.0.35"), ("sqlserver-se", "15.00.4365.2.v1"),
                                                ("oracle-ee", "19.0.0.0.ru-2024-01"))] == \
        ["postgres16", "aurora-postgresql16", "mysql8.0", "sqlserver-se-15.0", "oracle-ee-19"]


def test_an_rds_instance_with_its_groups_key_and_no_password():
    out = _render(KEY, entry(ALPHA, "db-grants", "ciamDatabase", **DB, ciamProviderRef=ARN))
    assert 'variable "db_grants_admin_username"' in out
    assert 'resource "aws_db_subnet_group" "db_grants"' in out and "[data.aws_subnet.subnet_ds.id]" in out
    assert 'resource "aws_security_group" "pf_grants_db"' in out and 'name        = "ciam-prod-pf-grants-db"' in out
    assert 'family = "postgres16"' in out and 'name  = "log_min_duration_statement"' in out
    assert "rds.force_ssl" not in out                       # PostgreSQL 16 on RDS requires TLS by default
    for line in ('engine                      = "postgres"', 'engine_version              = "16.4"',
                 'instance_class              = "db.r6g.large"', "allocated_storage           = 100",
                 "multi_az                    = true", "manage_master_user_password = true",
                 f'kms_key_id                  = "{KEY_ARN}"', "backup_retention_period     = 14",
                 "deletion_protection         = true", "publicly_accessible         = false",
                 "username                    = var.db_grants_admin_username"):
        assert line in out, line
    assert not re.search(r"\n\s+(password|master_password)\s+=", out) and "availability_zone" not in out
    assert 'import {\n  to = aws_db_instance.db_grants\n  id = "db-grants"\n}' in out


def test_tls_off_on_postgresql_16_and_on_for_mysql_are_parameters():
    off = _render(entry(ALPHA, "db-a", "ciamDatabase", ciamBindingRole="a", ciamDbEngine="postgresql",
                        ciamDbEngineVersion="16.4", ciamDbTlsRequired="FALSE"))
    assert 'name  = "rds.force_ssl"\n    value = "0"' in off and "import {" not in off
    on = _render(entry(ALPHA, "db-b", "ciamDatabase", ciamBindingRole="b", ciamDbEngine="mysql",
                       ciamDbEngineVersion="8.0.35", ciamDbTlsRequired="TRUE", ciamZone="zone-a"))
    assert 'family = "mysql8.0"' in on and 'name  = "require_secure_transport"\n    value = "1"' in on
    assert 'availability_zone           = "zone-a"' in on and "multi_az                    = false" in on


def test_aurora_is_a_cluster_with_an_instance_in_each_zone_and_others_keep_theirs():
    out = _render(entry(ALPHA, "db-sess", "ciamDatabase", ciamBindingRole="sessions-db", ciamDbEngine="postgresql",
                        ciamDbService="aurora", ciamDbEngineVersion="16.2", ciamInstanceSize="db.r6g.large",
                        ciamDbHighAvailability="zone-redundant", ciamDbParameter="work_mem=64MB"),
                  entry(ALPHA, "db-dba", "ciamDatabase", ciamBindingRole="reports-db", ciamDbEngine="mysql",
                        ciamManagedBy="cn=dba,ou=parties,dc=ciam-ops"))
    assert 'resource "aws_rds_cluster" "db_sess"' in out and 'engine                          = "aurora-postgresql"' in out
    assert "master_username                 = var.db_sess_admin_username" in out
    assert 'resource "aws_rds_cluster_parameter_group" "db_sess"' in out and 'family = "aurora-postgresql16"' in out
    assert "db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.db_sess.name" in out
    assert out.count('resource "aws_rds_cluster_instance"') == 2 and 'identifier         = "db-sess-2"' in out
    assert "# Database 'db-dba' (role reports-db) is kept by cn=dba,ou=parties,dc=ciam-ops: not rendered here" in out
    assert "reports" not in out.split("not rendered here", 1)[1]


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


INSTANCE = {"arn": ARN, "identifier": "db-grants", "engine": "postgres", "engine_version": "16",
            "engine_version_actual": "16.4", "instance_class": "db.r6g.large", "allocated_storage": 100,
            "multi_az": True, "availability_zone": "us-east-1a", "address": "db-grants.c1.us-east-1.rds.amazonaws.com",
            "port": 5432, "storage_encrypted": True, "kms_key_id": KEY_ARN, "backup_retention_period": 14,
            "deletion_protection": True, "db_subnet_group_name": "db-grants", "parameter_group_name": "db-grants",
            "master_user_secret": [{"secret_arn": SECRET_ARN, "secret_status": "active"}],
            "password": "never-read-this", "username": "ciam_admin",
            "tags": {"Name": "db-grants", "Role": "pf-grants-db"}}
GROUPS = (("aws_db_subnet_group", "g", {"name": "db-grants", "subnet_ids": ["subnet-1", "subnet-2"]}),
          ("aws_db_parameter_group", "p", {"name": "db-grants", "family": "postgres16", "parameter": [
              {"name": "log_min_duration_statement", "value": "500", "apply_method": "immediate"},
              {"name": "rds.force_ssl", "value": "0", "apply_method": "pending-reboot"}]}))


def test_an_instance_is_read_back_from_state_without_its_password():
    resources, notices = state_resources(_state(("aws_db_instance", "grants", INSTANCE), *GROUPS))
    (db,) = (r for r in resources if r.kind == "database")
    assert (db.ref, db.name, db.role) == (ARN, "db-grants", "pf-grants-db")
    assert db.attrs == {
        "ciamDbEngine": ("postgresql",), "ciamDbEngineVersion": ("16.4",), "ciamDbService": ("rds",),
        "ciamFqdn": ("db-grants.c1.us-east-1.rds.amazonaws.com",), "ciamPort": ("5432",),
        "ciamInstanceSize": ("db.r6g.large",), "ciamDbStorageGb": ("100",),
        "ciamDbHighAvailability": ("zone-redundant",), "ciamDbTlsRequired": ("FALSE",), "ciamRetentionDays": ("14",),
        "ciamDbPointInTime": ("TRUE",), "ciamDbDeletionProtection": ("TRUE",),
        "ciamDbParameter": ("log_min_duration_statement=500",)}
    assert db.links == {"ciamSubnetRole": ("subnet-1", "subnet-2"), "ciamEncryptedByRole": KEY_ARN,
                        "ciamDbCredentialRole": SECRET_ARN}
    assert "never-read-this" not in repr(resources) and "ciam_admin" not in repr(resources)
    assert not any("aws_db_instance" in n for n in notices)


def test_the_ranges_it_admits_are_ingress_rules_on_its_security_group():
    out = _render(KEY, entry(ALPHA, "db-grants", "ciamDatabase", **DB, ciamSourceCidr=("10.1.4.0/24", "10.1.5.0/24")))
    assert 'resource "aws_vpc_security_group_ingress_rule" "pf_grants_db_1"' in out
    for line in ("security_group_id = aws_security_group.pf_grants_db.id", 'cidr_ipv4         = "10.1.5.0/24"',
                 "from_port         = 5432", 'description       = "clients of database db-grants (pf-grants-db)"'):
        assert line in out, line
    mysql = _render(entry(ALPHA, "db-m", "ciamDatabase", ciamBindingRole="m-db", ciamDbEngine="mysql",
                          ciamSourceCidr="10.1.4.0/24"))
    assert "from_port         = 3306" in mysql                  # the engine's default port


def test_the_rules_on_its_security_group_are_its_ranges_not_firewall_rules():
    group = ("aws_security_group", "db", {"id": "sg-db", "name": "ciam-prod-pf-grants-db", "ingress": []})
    rule = ("aws_vpc_security_group_ingress_rule", "db", {
        "security_group_rule_id": "sgr-1", "security_group_id": "sg-db", "cidr_ipv4": "10.1.4.0/24",
        "from_port": 5432, "to_port": 5432, "ip_protocol": "tcp", "description": "clients of database db-grants"})
    instance = {**INSTANCE, "vpc_security_group_ids": ["sg-db"]}
    resources, _ = state_resources(_state(("aws_db_instance", "grants", instance), *GROUPS, group, rule))
    (db,) = (r for r in resources if r.kind == "database")
    assert db.attrs["ciamSourceCidr"] == ("10.1.4.0/24",)
    assert not [r for r in resources if r.kind == "firewall"]


def test_an_aurora_cluster_is_read_with_its_members():
    cluster = {"arn": "arn:aws:rds:us-east-1:1:cluster:db-sess", "cluster_identifier": "db-sess",
               "engine": "aurora-postgresql", "engine_version": "16.2", "endpoint": "db-sess.cluster-c1.rds.test",
               "port": 5432, "storage_encrypted": True, "backup_retention_period": 1, "deletion_protection": False,
               "master_password": "never-read-this", "tags": {"Role": "sessions-db"}}
    members = [("aws_rds_cluster_instance", f"m{i}", {"identifier": f"db-sess-{i}", "cluster_identifier": "db-sess",
                                                       "instance_class": "db.r6g.large",
                                                       "availability_zone": f"us-east-1{z}"})
               for i, z in ((1, "a"), (2, "b"))]
    resources, _ = state_resources(_state(("aws_rds_cluster", "sess", cluster), *members))
    (db,) = (r for r in resources if r.kind == "database")
    assert (db.attrs["ciamDbService"], db.attrs["ciamDbHighAvailability"], db.attrs["ciamInstanceSize"],
            db.attrs["ciamDbTlsRequired"], db.attrs["ciamDbDeletionProtection"]) == (
        ("aurora",), ("zone-redundant",), ("db.r6g.large",), ("TRUE",), ("FALSE",))
    assert "ciamZone" not in db.attrs and "never-read-this" not in repr(resources)


def test_the_cli_outputs_read_the_same_and_ssm_parameters_are_not_read():
    texts = {
        "vpcs.json": json.dumps({"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}]}),
        "rds-instances.json": json.dumps({"DBInstances": [
            {"DBInstanceIdentifier": "db-grants", "DBInstanceArn": ARN, "Engine": "postgres", "EngineVersion": "16.4",
             "DBInstanceClass": "db.r6g.large", "AllocatedStorage": 100, "MultiAZ": True,
             "AvailabilityZone": "us-east-1a", "Endpoint": {"Address": "db-grants.c1.rds.test", "Port": 5432},
             "StorageEncrypted": True, "KmsKeyId": KEY_ARN, "BackupRetentionPeriod": 14, "DeletionProtection": True,
             "DBSubnetGroup": {"DBSubnetGroupName": "db-grants", "VpcId": "vpc-1",
                               "Subnets": [{"SubnetIdentifier": "subnet-1"}]},
             "DBParameterGroups": [{"DBParameterGroupName": "db-grants"}],
             "MasterUserSecret": {"SecretArn": SECRET_ARN}, "TagList": [{"Key": "Role", "Value": "pf-grants-db"}],
             "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-db", "Status": "active"}]},
            {"DBInstanceIdentifier": "elsewhere", "DBInstanceArn": "arn:x", "Engine": "mysql",
             "DBSubnetGroup": {"DBSubnetGroupName": "other", "VpcId": "vpc-9"}}]}),
        "rds-subnet-groups.json": json.dumps({"DBSubnetGroups": [
            {"DBSubnetGroupName": "db-grants", "VpcId": "vpc-1",
             "Subnets": [{"SubnetIdentifier": "subnet-1"}, {"SubnetIdentifier": "subnet-2"}]}]}),
        "db-parameters/db-grants.json": json.dumps({"Parameters": [
            {"ParameterName": "log_min_duration_statement", "ParameterValue": "500", "Source": "user"},
            {"ParameterName": "rds.force_ssl", "ParameterValue": "1", "Source": "system"},
            {"ParameterName": "max_connections", "ParameterValue": "LEAST(...)", "Source": "engine-default"}]}),
        "security-groups.json": json.dumps({"SecurityGroups": [
            {"GroupId": "sg-db", "GroupName": "ciam-prod-pf-grants-db", "VpcId": "vpc-1", "IpPermissions": []}]}),
        "security-group-rules.json": json.dumps({"SecurityGroupRules": [
            {"SecurityGroupRuleId": "sgr-1", "GroupId": "sg-db", "IsEgress": False, "IpProtocol": "tcp",
             "FromPort": 5432, "ToPort": 5432, "CidrIpv4": "10.1.4.0/24"}]}),
        "ssm.json": json.dumps({"Parameters": [{"Name": "/x", "Value": "s3cr3t"}]})}
    resources, notices = cli_resources(texts)
    (db,) = (r for r in resources if r.kind == "database")
    assert db.attrs["ciamSourceCidr"] == ("10.1.4.0/24",) and not [r for r in resources if r.kind == "firewall"]
    assert (db.ref, db.attrs["ciamDbTlsRequired"], db.attrs["ciamDbParameter"]) == (
        ARN, ("TRUE",), ("log_min_duration_statement=500",))
    assert db.links["ciamSubnetRole"] == ("subnet-1", "subnet-2")
    assert "ssm.json: a Parameters output outside db-parameters/ and db-cluster-parameters/ (it could be SSM's); " \
           "not read" in notices
    assert "aws_db_instance (1): outside the listed VPCs (vpc-1); not read" in notices
    assert "s3cr3t" not in repr(resources)


def test_what_it_renders_reads_back_as_recorded():
    """The attributes a render sets, as a state would hold them, read back to the record's values."""
    resources, _ = state_resources(_state(
        ("aws_db_instance", "grants", {**INSTANCE, "availability_zone": None}),
        ("aws_db_subnet_group", "g", {"name": "db-grants", "subnet_ids": ["subnet-ds"]}),
        ("aws_db_parameter_group", "p", {"name": "db-grants", "parameter": [
            {"name": "log_min_duration_statement", "value": "500"}]})))
    (db,) = (r for r in resources if r.kind == "database")
    recorded = {k: (v,) if isinstance(v, str) else v for k, v in DB.items()
                if k not in ("ciamBindingRole", "ciamEncryptedByRole", "ciamSubnetRole")}
    assert {k: db.attrs[k] for k in recorded} == recorded

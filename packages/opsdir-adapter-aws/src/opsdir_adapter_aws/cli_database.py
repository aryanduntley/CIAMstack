"""The RDS outputs of the AWS CLI, normalized to the attribute names of the matching Terraform resources
(opsdir_adapter_aws.databases reads both). Pure.

  rds describe-db-instances             DBInstances       -> aws_db_instance; an Aurora cluster's member (it names
                                                             DBClusterIdentifier) -> aws_rds_cluster_instance; its
                                                             DBInstanceAutomatedBackupsReplications -> aws_db_instance_
                                                             automated_backups_replication (the copy's region)
  rds describe-db-clusters              DBClusters        -> aws_rds_cluster
  rds describe-db-subnet-groups         DBSubnetGroups    -> aws_db_subnet_group
  rds describe-db-parameters            Parameters        -> aws_db_parameter_group: its user-set parameters; the
                                                             output doesn't name its group: save it as
                                                             db-parameters/<group>.json
  rds describe-db-cluster-parameters    Parameters        -> aws_rds_cluster_parameter_group, saved as
                                                             db-cluster-parameters/<group>.json
A Parameters output anywhere else is not read: SSM's get-parameters has the same key, and holds values. Each database
carries the VPC of its subnet group (an Aurora cluster its members'), so the importer reads only the listed VPCs'.
The master password is never in these outputs; MasterUserSecret names the secret RDS keeps it in. VpcSecurityGroups
names the security groups whose rules (ec2 describe-security-group-rules) admit its clients.
"""
from .cli_outputs import documents, items, stem, tags_of

KEYS = ("DBInstances", "DBClusters", "DBSubnetGroups", "Parameters")
FOLDERS = (("db-parameters/", "aws_db_parameter_group"), ("db-cluster-parameters/", "aws_rds_cluster_parameter_group"))


def _secret(o):
    arn = (o.get("MasterUserSecret") or {}).get("SecretArn")
    return [{"secret_arn": arn}] if arn else []


def _instance(i):
    endpoint, group = i.get("Endpoint") or {}, i.get("DBSubnetGroup") or {}
    if i.get("DBClusterIdentifier"):
        return "aws_rds_cluster_instance", {
            "identifier": i.get("DBInstanceIdentifier"), "cluster_identifier": i.get("DBClusterIdentifier"),
            "instance_class": i.get("DBInstanceClass"), "availability_zone": i.get("AvailabilityZone"),
            "vpc_id": group.get("VpcId")}
    return "aws_db_instance", {
        "arn": i.get("DBInstanceArn"), "identifier": i.get("DBInstanceIdentifier"), "engine": i.get("Engine"),
        "engine_version": i.get("EngineVersion"), "instance_class": i.get("DBInstanceClass"),
        "allocated_storage": i.get("AllocatedStorage"), "multi_az": i.get("MultiAZ"),
        "availability_zone": i.get("AvailabilityZone"), "address": endpoint.get("Address"),
        "port": endpoint.get("Port"), "storage_encrypted": i.get("StorageEncrypted"), "kms_key_id": i.get("KmsKeyId"),
        "backup_retention_period": i.get("BackupRetentionPeriod"), "deletion_protection": i.get("DeletionProtection"),
        "db_subnet_group_name": group.get("DBSubnetGroupName"),
        "parameter_group_name": next((g.get("DBParameterGroupName") for g in i.get("DBParameterGroups") or ()), None),
        "master_user_secret": _secret(i), "tags": tags_of(i.get("TagList")), "vpc_id": group.get("VpcId"),
        "vpc_security_group_ids": _groups(i)}


def _groups(d):
    return [g.get("VpcSecurityGroupId") for g in d.get("VpcSecurityGroups") or () if g.get("VpcSecurityGroupId")]


def _cluster(c, vpcs):
    return "aws_rds_cluster", {
        "arn": c.get("DBClusterArn"), "cluster_identifier": c.get("DBClusterIdentifier"), "engine": c.get("Engine"),
        "engine_version": c.get("EngineVersion"), "endpoint": c.get("Endpoint"), "port": c.get("Port"),
        "storage_encrypted": c.get("StorageEncrypted"), "kms_key_id": c.get("KmsKeyId"),
        "backup_retention_period": c.get("BackupRetentionPeriod"), "deletion_protection": c.get("DeletionProtection"),
        "db_subnet_group_name": c.get("DBSubnetGroup"),
        "db_cluster_parameter_group_name": c.get("DBClusterParameterGroup"), "master_user_secret": _secret(c),
        "tags": tags_of(c.get("TagList")), "vpc_security_group_ids": _groups(c),
        "vpc_id": vpcs.get(("cluster", c.get("DBClusterIdentifier"))) or vpcs.get(("group", c.get("DBSubnetGroup")))}


def _parameters(outs):
    """(pairs, notices) of the parameter outputs: those under a parameter folder, user-set values only."""
    found = [(path, next((t for folder, t in FOLDERS if path.startswith(folder) or f"/{folder}" in path), None), doc)
             for path, doc in documents(outs, "Parameters")]
    return ([(t, {"name": stem(path), "parameter": [
                {"name": p.get("ParameterName"), "value": p.get("ParameterValue")} for p in doc.get("Parameters") or ()
                if p.get("Source") == "user" and p.get("ParameterValue") is not None]})
             for path, t, doc in found if t],
            tuple(f"{path}: a Parameters output outside db-parameters/ and db-cluster-parameters/ (it could be SSM's); "
                  "not read" for path, t, _ in found if not t))


def database_pairs(outs):
    """(pairs, notices) of the RDS outputs among the recognized CLI outputs ((path, key, document), ...)."""
    instances = [_instance(i) for i in items(outs, "DBInstances")]
    groups = items(outs, "DBSubnetGroups")
    vpcs = {**{("group", g.get("DBSubnetGroupName")): g.get("VpcId") for g in groups},
            **{("cluster", a.get("cluster_identifier")): a.get("vpc_id") for t, a in instances
               if t == "aws_rds_cluster_instance" and a.get("vpc_id")}}
    params, notices = _parameters(outs)
    copies = [("aws_db_instance_automated_backups_replication", {
                  "id": r.get("DBInstanceAutomatedBackupsArn"), "source_db_instance_arn": i.get("DBInstanceArn")})
              for i in items(outs, "DBInstances") for r in i.get("DBInstanceAutomatedBackupsReplications") or ()
              if r.get("DBInstanceAutomatedBackupsArn")]
    return ([*instances, *copies, *(_cluster(c, vpcs) for c in items(outs, "DBClusters")),
             *(("aws_db_subnet_group", {"name": g.get("DBSubnetGroupName"), "vpc_id": g.get("VpcId"),
                                        "subnet_ids": [s.get("SubnetIdentifier") for s in g.get("Subnets") or ()]})
               for g in groups), *params], notices)

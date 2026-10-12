"""The data stores CloudFormation stacks declare, normalized to the Terraform attribute names the shared mapping reads
(opsdir_adapter_aws.databases.database_resources, discovery.discovery_resources). Properties come resolved (Ref to
physical IDs, Fn::GetAtt where it follows from one). Pure.

  AWS::RDS::DBInstance (an Aurora member when it names DBClusterIdentifier)  -> aws_db_instance,
                                                                               aws_rds_cluster_instance
  AWS::RDS::DBCluster                                                       -> aws_rds_cluster
  AWS::RDS::DBSubnetGroup                                                   -> aws_db_subnet_group
  AWS::RDS::DBParameterGroup, DBClusterParameterGroup                       -> their parameters
  AWS::Macie::CustomDataIdentifier                                          -> aws_macie2_custom_data_identifier
"""
from .cloudformation_values import number, tag_map, truth

DATA_TYPES = ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::RDS::DBSubnetGroup", "AWS::RDS::DBParameterGroup",
              "AWS::RDS::DBClusterParameterGroup", "AWS::Macie::CustomDataIdentifier")


def _of(declared, type_):
    return [(lid, p, pid) for lid, t, p, _, pid in declared if t == type_]


def _instance(lid, p, pid, names):
    if p.get("DBClusterIdentifier"):
        return "aws_rds_cluster_instance", {"identifier": p.get("DBInstanceIdentifier") or pid,
                                            "cluster_identifier": p.get("DBClusterIdentifier"),
                                            "instance_class": p.get("DBInstanceClass"),
                                            "availability_zone": p.get("AvailabilityZone")}
    return "aws_db_instance", {
        "arn": names.get(f"{lid}.DBInstanceArn"), "identifier": p.get("DBInstanceIdentifier") or pid,
        "engine": p.get("Engine"), "engine_version": p.get("EngineVersion"),
        "instance_class": p.get("DBInstanceClass"), "allocated_storage": number(p.get("AllocatedStorage")),
        "multi_az": truth(p.get("MultiAZ")), "availability_zone": p.get("AvailabilityZone"),
        "port": number(p.get("Port")), "storage_encrypted": truth(p.get("StorageEncrypted")),
        "kms_key_id": p.get("KmsKeyId"), "backup_retention_period": number(p.get("BackupRetentionPeriod")),
        "deletion_protection": truth(p.get("DeletionProtection")), "db_subnet_group_name": p.get("DBSubnetGroupName"),
        "parameter_group_name": p.get("DBParameterGroupName"), "tags": tag_map(p.get("Tags")),
        "vpc_security_group_ids": list(p.get("VPCSecurityGroups") or ())}


def _cluster(lid, p, pid, names):
    return "aws_rds_cluster", {
        "arn": names.get(f"{lid}.DBClusterArn"), "cluster_identifier": p.get("DBClusterIdentifier") or pid,
        "engine": p.get("Engine"), "engine_version": p.get("EngineVersion"), "port": number(p.get("Port")),
        "storage_encrypted": truth(p.get("StorageEncrypted")), "kms_key_id": p.get("KmsKeyId"),
        "backup_retention_period": number(p.get("BackupRetentionPeriod")),
        "deletion_protection": truth(p.get("DeletionProtection")), "db_subnet_group_name": p.get("DBSubnetGroupName"),
        "db_cluster_parameter_group_name": p.get("DBClusterParameterGroupName"), "tags": tag_map(p.get("Tags")),
        "vpc_security_group_ids": list(p.get("VpcSecurityGroupIds") or ())}


def _parameter_groups(declared):
    def parameters(p):
        return [{"name": k, "value": str(v)} for k, v in (p.get("Parameters") or {}).items()]
    return [*(("aws_db_parameter_group", {"name": p.get("DBParameterGroupName") or pid, "parameter": parameters(p)})
              for _, p, pid in _of(declared, "AWS::RDS::DBParameterGroup")),
            *(("aws_rds_cluster_parameter_group", {"name": p.get("DBClusterParameterGroupName") or pid,
                                                   "parameter": parameters(p)})
              for _, p, pid in _of(declared, "AWS::RDS::DBClusterParameterGroup"))]


def data_stack_pairs(declared, names):
    """(Terraform resource type, attributes) pairs of the data stores among a stack's declared resources ((logical ID,
    type, resolved properties, raw properties, physical ID), ...); names: what references resolve to (the Fn::GetAtt
    attributes)."""
    return [*(_instance(lid, p, pid, names) for lid, p, pid in _of(declared, "AWS::RDS::DBInstance")),
            *(_cluster(lid, p, pid, names) for lid, p, pid in _of(declared, "AWS::RDS::DBCluster")),
            *(("aws_db_subnet_group", {"name": p.get("DBSubnetGroupName") or pid,
                                       "subnet_ids": list(p.get("SubnetIds") or ())})
              for _, p, pid in _of(declared, "AWS::RDS::DBSubnetGroup")),
            *_parameter_groups(declared),
            *(("aws_macie2_custom_data_identifier", {"id": pid, "name": p.get("Name"), "regex": p.get("Regex")})
              for _, p, pid in _of(declared, "AWS::Macie::CustomDataIdentifier"))]

"""AWS CLI outputs read into an environment's servers and bindings: outputs that match the record change nothing; what
the CLI says replaces the record's values and adds facts Terraform state lacks (a secret's last rotation, rotation off);
resources outside the listed VPC are counted, not read; target health and zone records are placed by their file names;
account-wide listings count what the record doesn't have instead of listing it; AWS managed keys and unknown files are
named; a secret's value never appears."""
import json

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.cli import cli_resources, generalized_time, read_cli_inventory
from support import SUPERS

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"
VPC, SUBNET, NAT = "vpc-0a1b2c3d4e5f67890", "subnet-0a11b22c33d44e55a", "nat-0123456789abcdef0"
SECRET = "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/ds-root-password"
KEY = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234"
LB = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/ciam-prod-svc-ldaps/0a1b"
TG = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/ciam-prod-svc-ldaps-1636/0c1d"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return make_directory((), SUPERS, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="aws",
             ciamRegion="us-east-1"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=vpc,{B}", ("ciamNetwork",), cn="vpc", ciamBindingRole="network", ciamCidr="10.20.0.0/16",
             ciamProviderRef=VPC),
        _row(f"cn=subnet-ds-a,{B}", ("ciamSubnetBinding",), cn="subnet-ds-a", ciamBindingRole="subnet-ds",
             ciamCidr="10.20.1.0/24", ciamProviderRef=SUBNET, ciamZone="us-east-1a"),
        _row(f"cn=ds-1,{ENV}", ("ciamServer",), cn="ds-1", ciamServerRole="ds", ciamHostname="ds-1.internal.test",
             ciamSubnet=f"cn=subnet-ds-a,{B}", ciamPrivateIp="10.20.1.11", ciamZone="us-east-1a",
             ciamInstanceSize="m6i.xlarge", ciamImageRef="ami-0abc", ciamProductVersion="PingDS 7.5.1"),
        _row(f"cn=svc-ldaps,{B}", ("ciamServiceName",), cn="svc-ldaps", ciamBindingRole="ds-ldaps-service",
             ciamFqdn="ldap.example.test", ciamTargetRole="ds", ciamPort="1636", ciamFrontendIp="10.20.1.100",
             ciamDnsZoneRef="Z0PRIVATE", ciamEdgeFact="tls-mode passthrough", ciamTtlSeconds="60"),
        _row(f"cn=fw-app,{B}", ("ciamFirewallRule",), cn="fw-app", ciamBindingRole="fw-consumer-app",
             ciamSourceCidr=["10.30.0.0/24"], ciamPort="1636", ciamProtocol="tcp", ciamTargetRole="ds"),
        _row(f"cn=secret-root,{B}", ("ciamSecretRef",), cn="secret-root", ciamBindingRole="ds-root-password",
             ciamRefUri=f"aws-sm://{SECRET}", ciamAutoRotate="FALSE", ciamLastRotated="20260302000000Z"),
        _row(f"cn=key-disk,{B}", ("ciamKeyRef",), cn="key-disk", ciamBindingRole="disk-encryption",
             ciamRefUri=f"aws-kms://{KEY}", ciamAutoRotate="TRUE", ciamProtectionLevel="hsm",
             ciamReplicaRegion="us-west-2"),
        _row(f"cn=backup,{B}", ("ciamBackupTarget",), cn="backup", ciamBindingRole="backup-target",
             ciamStorageRef="s3://ciam-backups"),
        _row(f"cn=egress,{B}", ("ciamEgress",), cn="egress", ciamBindingRole="pf-egress", ciamCidr="203.0.113.10/32",
             ciamProviderRef=NAT, ciamNatAllocation="static")))


def _tags(**kv):
    return [{"Key": k, "Value": v} for k, v in kv.items()]


def _outputs(**over):
    """{path: output} as `aws … --output json` prints it."""
    base = {
        "vpcs.json": {"Vpcs": [{"VpcId": VPC, "CidrBlock": "10.20.0.0/16", "State": "available"}]},
        "subnets.json": {"Subnets": [{"SubnetId": SUBNET, "VpcId": VPC, "CidrBlock": "10.20.1.0/24",
                                      "AvailabilityZone": "us-east-1a"}]},
        "instances.json": {"Reservations": [{"Instances": [
            {"InstanceId": "i-0aaa", "ImageId": "ami-0abc", "InstanceType": "m6i.xlarge", "PrivateIpAddress": "10.20.1.11",
             "PrivateDnsName": "ip-10-20-1-11.ec2.internal", "SubnetId": SUBNET, "VpcId": VPC,
             "Placement": {"AvailabilityZone": "us-east-1a"}, "State": {"Name": "running"},
             "SecurityGroups": [{"GroupId": "sg-0ds", "GroupName": "ciam-prod-ds"}],
             "Tags": _tags(Name="ds-1", Role="ds", Hostname="ds-1.internal.test", Product="PingDS 7.5.1")},
            {"InstanceId": "i-0old", "SubnetId": SUBNET, "VpcId": VPC, "State": {"Name": "terminated"}}]}]},
        "security-groups.json": {"SecurityGroups": [{"GroupId": "sg-0ds", "GroupName": "ciam-prod-ds", "VpcId": VPC,
                                                     "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 1636,
                                                                        "ToPort": 1636, "IpRanges": [
                                                         {"CidrIp": "10.30.0.0/24",
                                                          "Description": "consumer app (fw-app)"}]}]}]},
        "nat-gateways.json": {"NatGateways": [{"NatGatewayId": NAT, "VpcId": VPC, "State": "available",
                                               "NatGatewayAddresses": [{"PublicIp": "203.0.113.10"}]}]},
        "load-balancers.json": {"LoadBalancers": [{
            "LoadBalancerArn": LB, "LoadBalancerName": "ciam-prod-svc-ldaps", "Scheme": "internal", "VpcId": VPC,
            "DNSName": "ciam-prod-svc-ldaps-0a1b.elb.us-east-1.amazonaws.com", "Type": "network",
            "AvailabilityZones": [{"SubnetId": SUBNET, "LoadBalancerAddresses": [{"PrivateIPv4Address": "10.20.1.100"}]}]}]},
        "listeners-svc-ldaps.json": {"Listeners": [{"LoadBalancerArn": LB, "Port": 1636, "Protocol": "TCP",
                                                    "DefaultActions": [{"Type": "forward", "TargetGroupArn": TG}]}]},
        "target-groups.json": {"TargetGroups": [{"TargetGroupArn": TG, "TargetGroupName": "ciam-prod-svc-ldaps-1636",
                                                 "Port": 1636, "LoadBalancerArns": [LB]}]},
        "target-health/ciam-prod-svc-ldaps-1636.json": {"TargetHealthDescriptions": [
            {"Target": {"Id": "i-0aaa", "Port": 1636}, "TargetHealth": {"State": "healthy"}}]},
        "route53/Z0PRIVATE.json": {"ResourceRecordSets": [
            {"Name": "example.test.", "Type": "SOA", "ResourceRecords": [{"Value": "ns-1. hostmaster. 1 7200 900 1 86400"}]},
            {"Name": "ldap.example.test.", "Type": "A", "AliasTarget": {
                "HostedZoneId": "Z26RNL4JYFTOTI", "EvaluateTargetHealth": False,
                "DNSName": "ciam-prod-svc-ldaps-0a1b.elb.us-east-1.amazonaws.com."}}]},
        "secrets.json": {"SecretList": [{"ARN": SECRET, "Name": "ciam/prod/ds-root-password",
                                         "LastRotatedDate": "2026-03-02T00:00:00+00:00", "Tags": []}]},
        "kms/key-mrk-1234.json": {"KeyMetadata": {
            "Arn": KEY, "KeyId": "mrk-1234", "KeyManager": "CUSTOMER", "KeyState": "Enabled", "Origin": "AWS_KMS",
            "MultiRegion": True, "MultiRegionConfiguration": {"MultiRegionKeyType": "PRIMARY", "ReplicaKeys": [
                {"Arn": "arn:aws:kms:us-west-2:111122223333:key/mrk-1234", "Region": "us-west-2"}]}}},
        "kms/rotation-mrk-1234.json": {"KeyRotationEnabled": True},
        "kms/key-aws-ebs.json": {"KeyMetadata": {"Arn": "arn:aws:kms:us-east-1:111122223333:key/0ebs",
                                                 "KeyId": "0ebs", "KeyManager": "AWS", "KeyState": "Enabled"}},
        "buckets.json": {"Buckets": [{"Name": "ciam-backups"}]}}
    return {f"main/prod/{p}": json.dumps(doc) for p, doc in {**base, **over}.items()}


def _after(d, imported):
    scopes = [s.lower() for s, _ in imported.groups]
    kept = {n: e for n, e in d.entries.items() if n not in scopes}
    added = {e.norm: e for e in (*(c for c in imported.containers if c.norm not in d.entries),
                                 *(e for _, es in imported.groups for e in es))}
    return d._replace(entries={**kept, **added})


def test_the_importer_is_registered_on_the_adapter():
    assert [i.name for i in ADAPTER.importers] == ["terraform-state", "cli-inventory", "cloudformation"]


def test_outputs_that_match_the_record_change_nothing():
    d = _record()
    imported = read_cli_inventory(_outputs(), d, ())
    assert len(imported.groups) == 9 and not import_changes(d, imported), imported.notices
    assert imported.notices == ("kms: 1 AWS managed key(s) not read (the record holds customer managed keys)",)


def test_what_the_cli_says_replaces_the_records_values_with_facts_state_lacks():
    d = _record()
    rotated = {"SecretList": [{"ARN": SECRET, "Name": "ciam/prod/ds-root-password", "RotationEnabled": True,
                               "RotationLambdaARN": "arn:aws:lambda:us-east-1:111122223333:function:rotate",
                               "LastRotatedDate": "2026-09-01T12:00:00.123000+00:00"}]}
    after = _after(d, read_cli_inventory(_outputs(**{"secrets.json": rotated,
                                                     "kms/rotation-mrk-1234.json": {"KeyRotationEnabled": False,
                                                                                    "KeyId": KEY}}), d, ()))
    secret = get(after, f"cn=secret-root,{B}")
    assert (one(secret, "ciamAutoRotate"), one(secret, "ciamLastRotated"), one(secret, "ciamRotationFunction")) == \
        ("TRUE", "20260901120000Z", "arn:aws:lambda:us-east-1:111122223333:function:rotate")
    key = get(after, f"cn=key-disk,{B}")
    assert (one(key, "ciamAutoRotate"), one(key, "ciamReplicaRegion"), one(key, "ciamProtectionLevel")) == \
        ("FALSE", "us-west-2", "hsm")


def test_what_lies_outside_the_listed_vpc_is_counted_not_read():
    other = {"Reservations": [{"Instances": [
        {"InstanceId": "i-0zzz", "SubnetId": "subnet-other", "VpcId": "vpc-other", "State": {"Name": "running"},
         "Tags": _tags(Role="ds")}]}]}
    imported = read_cli_inventory({**_outputs(), **{f"main/prod/{p}": json.dumps(o) for p, o in
                                                   {"instances-other.json": other}.items()}}, _record(), ())
    assert "aws_instance (1): outside the listed VPCs (vpc-0a1b2c3d4e5f67890); not read" in imported.notices
    assert not [n for n in imported.notices if "i-0zzz" in n]


def test_account_wide_listings_count_what_the_record_does_not_have():
    many = {"SecretList": [{"ARN": SECRET, "Name": "ciam/prod/ds-root-password"},
                           *({"ARN": f"arn:aws:secretsmanager:us-east-1:111122223333:secret:app/{i}", "Name": f"app/{i}"}
                             for i in range(5))]}
    imported = read_cli_inventory(_outputs(**{"secrets.json": many,
                                              "buckets.json": {"Buckets": [{"Name": "ciam-backups"}, {"Name": "logs"}]}}),
                                  _record(), ())
    assert "main/prod: 5 secret resource(s) not in the record and naming no role, e.g. app/0, app/1, app/2 (tag them " \
           "Role, name them in roles.json, or record them); not imported" in imported.notices
    assert "main/prod: 1 storage resource(s) not in the record and naming no role, e.g. logs (tag them Role, name " \
           "them in roles.json, or record them); not imported" in imported.notices


def test_target_health_and_zone_records_are_placed_by_their_file_names():
    resources = cli_resources({p.split("/", 2)[2]: t for p, t in _outputs().items()})[0]
    (svc,) = [r for r in resources if r.kind == "service"]
    assert (svc.attrs["ciamFqdn"], svc.attrs["ciamDnsZoneRef"], svc.attrs["ciamTargetRole"]) == \
        (("ldap.example.test",), ("Z0PRIVATE",), ("ds",))
    stray = cli_resources({"target-health/unknown-tg.json": json.dumps({"TargetHealthDescriptions": []}),
                           "notes.json": "{}", "vpcs.json": json.dumps({"Vpcs": []})})[1]
    assert "notes.json: not an AWS CLI output this importer reads; not read" in stray
    assert "target-health/unknown-tg.json: no target group named unknown-tg is listed (save describe-target-health " \
           "as target-health/<target group name>.json, with describe-target-groups); not read" in stray


def test_separately_listed_rules_replace_the_groups_inline_permissions():
    rules = {"SecurityGroupRules": [
        {"SecurityGroupRuleId": "sgr-01", "GroupId": "sg-0ds", "IsEgress": False, "IpProtocol": "tcp",
         "FromPort": 1636, "ToPort": 1636, "CidrIpv4": "10.30.0.0/24", "Description": "consumer app (fw-app)"},
        {"SecurityGroupRuleId": "sgr-02", "GroupId": "sg-0ds", "IsEgress": True, "IpProtocol": "-1",
         "CidrIpv4": "0.0.0.0/0"}]}
    d = _record()
    imported = read_cli_inventory(_outputs(**{"security-group-rules.json": rules}), d, ())
    assert not import_changes(d, imported), imported.notices


def test_roles_json_is_never_read_as_an_output_and_a_value_never_appears():
    files = {**_outputs(), "main/prod/roles.json": json.dumps({"ciam/prod/other": "x"})}
    imported = read_cli_inventory(files, _record(), ())
    assert not [n for n in imported.notices if "not an AWS CLI output" in n]
    assert "main/prod/roles.json: ciam/prod/other matches nothing the source reports" in imported.notices
    assert "SecretString" not in str(cli_resources({"secrets.json": json.dumps(
        {"SecretList": [{"ARN": SECRET, "Name": "n", "SecretString": "S3cr3t"}]})}))


def test_timestamps_become_generalized_time():
    assert generalized_time("2026-03-02T00:00:00+00:00") == "20260302000000Z"
    assert generalized_time("2026-03-02T01:00:00-05:00") == "20260302060000Z"
    assert generalized_time(1772409600) == "20260302000000Z"
    assert generalized_time("soon") is None and generalized_time(None) is None

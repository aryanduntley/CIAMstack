"""CloudFormation stacks read into an environment's servers and bindings: two stacks (network and application, YAML with
short tags, parameters, a DNS alias and an Elastic IP linked with Fn::GetAtt) that match the record change nothing;
a changed template replaces the record's values; functions that aren't evaluated are counted and leave the record's
values alone; resources without a physical ID, other resource types and unknown files are named; secret values in a
template are never read."""
import json

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one
from opsdir_adapter_aws.cloudformation import cloudformation_resources, read_cloudformation, read_document, resolve

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"
VPC, SUBNET, NAT = "vpc-0a1b2c3d4e5f67890", "subnet-0a11b22c33d44e55a", "nat-0123456789abcdef0"
SECRET = "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/ds-root-password-AbCdEf"
KEY = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234"
LB = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/ciam-prod-svc-ldaps/0a1b"
TG = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/ciam-prod-svc-ldaps-1636/0c1d"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return make_directory((), {}, (
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
             ciamDnsZoneRef="Z0PRIVATE"),
        _row(f"cn=fw-app,{B}", ("ciamFirewallRule",), cn="fw-app", ciamBindingRole="fw-consumer-app",
             ciamSourceCidr=["10.30.0.0/24"], ciamPort="1636", ciamProtocol="tcp", ciamTargetRole="ds"),
        _row(f"cn=secret-root,{B}", ("ciamSecretRef",), cn="secret-root", ciamBindingRole="ds-root-password",
             ciamRefUri=f"aws-sm://{SECRET}", ciamAutoRotate="TRUE", ciamLastRotated="20260302000000Z"),
        _row(f"cn=key-disk,{B}", ("ciamKeyRef",), cn="key-disk", ciamBindingRole="disk-encryption",
             ciamRefUri=f"aws-kms://{KEY}", ciamAutoRotate="TRUE", ciamProtectionLevel="hsm"),
        _row(f"cn=backup,{B}", ("ciamBackupTarget",), cn="backup", ciamBindingRole="backup-target",
             ciamStorageRef="s3://ciam-backups"),
        _row(f"cn=egress,{B}", ("ciamEgress",), cn="egress", ciamBindingRole="pf-egress", ciamCidr="203.0.113.10/32",
             ciamProviderRef=NAT)))


NETWORK = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  VpcCidr: {Type: String, Default: 10.20.0.0/16}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: !Ref VpcCidr
  SubnetDsA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !Select [0, !Cidr [!Ref VpcCidr, 16, 8]]
      AvailabilityZone: !Sub "${AWS::Region}a"
  NatEip:
    Type: AWS::EC2::EIP
    Properties: {Domain: vpc}
  Nat:
    Type: AWS::EC2::NatGateway
    Properties:
      AllocationId: !GetAtt NatEip.AllocationId
      SubnetId: !Ref SubnetDsA
  Endpoint:
    Type: AWS::EC2::VPCEndpoint
    Properties: {VpcId: !Ref Vpc, ServiceName: com.amazonaws.us-east-1.s3}
"""

APP = """
Parameters:
  Env: {Type: String}
  DsImage: {Type: String}
  RootPassword: {Type: String, NoEcho: true}
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  DsSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: !Sub ciam-${Env}-ds
      GroupDescription: CIAM ds
      VpcId: vpc-0a1b2c3d4e5f67890
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 1636, ToPort: 1636, CidrIp: 10.30.0.0/24, Description: consumer app (fw-app)}
  Ds1:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !Ref DsImage
      InstanceType: m6i.xlarge
      SubnetId: subnet-0a11b22c33d44e55a
      PrivateIpAddress: 10.20.1.11
      AvailabilityZone: us-east-1a
      SecurityGroupIds: [!Ref DsSecurityGroup]
      Monitoring: !If [IsProd, true, false]
      Tags:
        - {Key: Name, Value: ds-1}
        - {Key: Role, Value: ds}
        - {Key: Hostname, Value: ds-1.internal.test}
        - {Key: Product, Value: PingDS 7.5.1}
  LdapsLb:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: network
      Scheme: internal
      SubnetMappings:
        - {SubnetId: subnet-0a11b22c33d44e55a, PrivateIPv4Address: 10.20.1.100}
  LdapsGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      Port: 1636
      Protocol: TCP
      VpcId: vpc-0a1b2c3d4e5f67890
      Targets: [{Id: !Ref Ds1, Port: 1636}]
  LdapsListener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref LdapsLb
      Port: 1636
      Protocol: TCP
      DefaultActions: [{Type: forward, TargetGroupArn: !Ref LdapsGroup}]
  LdapsRecord:
    Type: AWS::Route53::RecordSet
    Properties:
      HostedZoneId: Z0PRIVATE
      Name: ldap.example.test.
      Type: A
      AliasTarget:
        DNSName: !GetAtt LdapsLb.DNSName
        HostedZoneId: !GetAtt LdapsLb.CanonicalHostedZoneID
  RootSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: !Sub ciam/${Env}/ds-root-password
      SecretString: !Ref RootPassword
  RootRotation:
    Type: AWS::SecretsManager::RotationSchedule
    Properties:
      SecretId: !Ref RootSecret
      RotationLambdaARN: !GetAtt RotateFunction.Arn
  RotateFunction:
    Type: AWS::Lambda::Function
    Properties: {Runtime: python3.12}
  DiskKey:
    Type: AWS::KMS::Key
    Properties:
      EnableKeyRotation: true
      MultiRegion: true
  Backups:
    Type: AWS::S3::Bucket
    Properties: {BucketName: ciam-backups}
"""


def _stack(name, params):
    return {"Stacks": [{"StackId": f"arn:aws:cloudformation:us-east-1:111122223333:stack/{name}/0a1b-2c3d",
                        "StackName": name, "StackStatus": "UPDATE_COMPLETE",
                        "Parameters": [{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()]}]}


def _resources(physical, status=None):
    return {"StackResourceSummaries": [{"LogicalResourceId": k, "PhysicalResourceId": v, "ResourceType": "",
                                        "ResourceStatus": (status or {}).get(k, "CREATE_COMPLETE")}
                                       for k, v in physical.items()]}


def _files(app=APP, network=NETWORK, app_status=None):
    """Two stack folders under main/prod/ as the AWS CLI saves them (the app stack's template as get-template output)."""
    net = {"stack.json": _stack("ciam-prod-network", {}),
           "resources.json": _resources({"Vpc": VPC, "SubnetDsA": SUBNET, "NatEip": "203.0.113.10", "Nat": NAT,
                                         "Endpoint": "vpce-0abc"}),
           "template.yaml": network}
    appl = {"stack.json": _stack("ciam-prod-app", {"Env": "prod", "DsImage": "ami-0abc", "RootPassword": "****"}),
            "resources.json": _resources({"DsSecurityGroup": "sg-0ds", "Ds1": "i-0aaa", "LdapsLb": LB,
                                          "LdapsGroup": TG, "LdapsListener": f"{LB}/listener/1", "LdapsRecord": "ldap",
                                          "RootSecret": SECRET, "RootRotation": f"{SECRET}|rotation",
                                          "RotateFunction": "rotate-fn", "DiskKey": "mrk-1234",
                                          "Backups": "ciam-backups"}, app_status),
            "template.json": {"TemplateBody": app}}
    return {**{f"main/prod/network/{p}": t if isinstance(t, str) else json.dumps(t) for p, t in net.items()},
            **{f"main/prod/app/{p}": json.dumps(t) for p, t in appl.items()}}


def _after(d, imported):
    scopes = [s.lower() for s, _ in imported.groups]
    kept = {n: e for n, e in d.entries.items() if n not in scopes}
    added = {e.norm: e for e in (*(c for c in imported.containers if c.norm not in d.entries),
                                 *(e for _, es in imported.groups for e in es))}
    return d._replace(entries={**kept, **added})


def test_stacks_that_match_the_record_change_nothing():
    d = _record()
    imported = read_cloudformation(_files(), d, ())
    assert len(imported.groups) == 9 and not import_changes(d, imported), imported.notices
    assert set(imported.notices) == {
        "ciam-prod-network: Fn::Cidr (1) not evaluated; the attributes computed with them keep the record's values",
        "ciam-prod-network: resource types not read: AWS::EC2::VPCEndpoint (1)",
        "ciam-prod-app: Fn::If (1) not evaluated; the attributes computed with them keep the record's values",
        "main/prod: job rotate-fn (arn:aws:lambda:us-east-1:111122223333:function:rotate-fn) is not in the record and "
        "names no role (tag it Role, name it in roles.json, or record it); not imported"}


def test_a_changed_template_replaces_the_records_values():
    d = _record()
    changed = APP.replace("InstanceType: m6i.xlarge", "InstanceType: m6i.2xlarge") \
        .replace("EnableKeyRotation: true", "EnableKeyRotation: false")
    after = _after(d, read_cloudformation(_files(app=changed), d, ()))
    assert one(get(after, f"cn=ds-1,{ENV}"), "ciamInstanceSize") == "m6i.2xlarge"
    key = get(after, f"cn=key-disk,{B}")
    assert (one(key, "ciamAutoRotate"), one(key, "ciamProtectionLevel")) == ("FALSE", "hsm")


def test_links_through_get_att_and_parameters_resolve():
    resources = {r.kind: r for r in cloudformation_resources({p.split("/", 2)[2]: t for p, t in _files().items()})[0]}
    assert resources["egress"].attrs["ciamCidr"] == ("203.0.113.10/32",)
    assert (resources["service"].attrs["ciamFqdn"], resources["service"].attrs["ciamTargetRole"]) == \
        (("ldap.example.test",), ("ds",))
    assert resources["secret"].attrs["ciamAutoRotate"] == ("TRUE",) and resources["subnet"].attrs["ciamZone"] == \
        ("us-east-1a",)
    assert "ciamCidr" not in resources["subnet"].attrs      # Fn::Cidr isn't evaluated: the record keeps its range


def test_resources_not_created_and_unknown_files_are_named_and_secrets_never_read():
    files = {**_files(app_status={"Backups": "CREATE_FAILED"}), "main/prod/app/notes.json": json.dumps({"a": 1})}
    resources, notices = cloudformation_resources({p.split("/", 2)[2]: t for p, t in files.items()})
    assert "app/notes.json: not a CloudFormation stack output or template; not read" in notices
    assert "ciam-prod-app: 1 resource(s) without a physical ID (not created, or no stack resources listed): Backups" \
        in notices
    assert "****" not in str(resources) and "RootPassword" not in str(resources)


def test_a_folder_without_a_template_is_named():
    files = {"app/stack.json": json.dumps(_stack("x", {}))}
    assert cloudformation_resources(files)[1] == ("app: no template (get-template output or the template file); "
                                                  "stack not read",)


def test_values_resolve_against_parameters_pseudo_parameters_and_physical_ids():
    names = {"Env": "prod", "AWS::Region": "us-east-1", "Vpc": VPC}
    assert resolve({"Fn::Sub": "ciam-${Env}-${AWS::Region}"}, names) == "ciam-prod-us-east-1"
    assert resolve({"Fn::Sub": ["${A}-${Env}", {"A": {"Ref": "Vpc"}}]}, names) == f"{VPC}-prod"
    assert resolve({"Fn::Join": ["/", ["a", {"Ref": "Env"}]]}, names) == "a/prod"
    assert resolve({"Fn::Select": [1, ["a", "b"]]}, names) == "b"
    assert resolve({"Fn::Sub": "${Lb.DNSName}"}, names) is None and resolve({"Ref": "Missing"}, names) is None
    assert resolve({"Refresh": 5}, names) == {"Refresh": 5}
    assert read_document("A: !GetAtt Lb.DNSName\nB: !Ref X\n") == {"A": {"Fn::GetAtt": ["Lb", "DNSName"]},
                                                                  "B": {"Ref": "X"}}

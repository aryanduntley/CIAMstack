"""CloudFormation stacks read into an environment's servers and bindings: two stacks (network and application, YAML with
short tags, parameters, a DNS alias and an Elastic IP linked with Fn::GetAtt) that match the record change nothing;
a changed template replaces the record's values; functions that aren't evaluated are counted and leave the record's
values alone; resources without a physical ID, other resource types and unknown files are named; secret values in a
template are never read."""
import json

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one
from opsdir_adapter_aws.cloudformation import cloudformation_resources, read_cloudformation, read_document, resolve
from support import SUPERS, after_import, imported_directory

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
    return imported_directory((), SUPERS, (
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
             ciamRefUri=f"aws-sm://{SECRET}", ciamAutoRotate="TRUE", ciamLastRotated="20260302000000Z"),
        _row(f"cn=key-disk,{B}", ("ciamKeyRef",), cn="key-disk", ciamBindingRole="disk-encryption",
             ciamRefUri=f"aws-kms://{KEY}", ciamAutoRotate="TRUE", ciamProtectionLevel="hsm"),
        _row(f"cn=backup,{B}", ("ciamBackupTarget",), cn="backup", ciamBindingRole="backup-target",
             ciamStorageRef="s3://ciam-backups"),
        _row(f"cn=egress,{B}", ("ciamEgress",), cn="egress", ciamBindingRole="pf-egress", ciamCidr="203.0.113.10/32",
             ciamProviderRef=NAT, ciamNatAllocation="static")))


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
  Igw:
    Type: AWS::EC2::InternetGateway
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
    """Two stack folders under main/prod/ as the AWS CLI saves them (the app stack's template as get-template
    output)."""
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


def test_stacks_that_match_the_record_change_nothing():
    d = _record()
    imported = read_cloudformation(_files(), d, ())
    assert len(imported.groups) == 9 and not import_changes(d, imported), imported.notices
    assert set(imported.notices) == {
        "ciam-prod-network: Fn::Cidr (1) not evaluated; the attributes computed with them keep the record's values",
        "ciam-prod-network: resource types not read: AWS::EC2::InternetGateway (1)",
        "main/prod: private-endpoint vpce-0abc (vpce-0abc) is not in the record and names no role (tag it Role, "
        "name it in roles.json, or record it); not imported",
        "ciam-prod-app: Fn::If (1) not evaluated; the attributes computed with them keep the record's values",
        "main/prod: job rotate-fn (arn:aws:lambda:us-east-1:111122223333:function:rotate-fn) is not in the record and "
        "names no role (tag it Role, name it in roles.json, or record it); not imported"}


def test_a_changed_template_replaces_the_records_values():
    d = _record()
    changed = APP.replace("InstanceType: m6i.xlarge", "InstanceType: m6i.2xlarge") \
        .replace("EnableKeyRotation: true", "EnableKeyRotation: false")
    after = after_import(d, read_cloudformation(_files(app=changed), d, ()))
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


def test_the_terraform_root_kept_beside_the_stacks_is_read_with_them():
    """What a CloudFormation render keeps in Terraform (its side root, applied as a state) is read in the same import
    as the stacks: the environment's resources are both parts' together."""
    stacks = {p.split("/", 2)[2]: t for p, t in _files().items()}
    state = _state_of((("aws_s3_bucket", {"id": "ciam-audit", "bucket": "ciam-audit", "tags": {"Role": "audit"}}),))
    alone, _ = cloudformation_resources(stacks)
    side, _ = cloudformation_resources({"terraform/main.tfstate": state})
    both, _ = cloudformation_resources({**stacks, "terraform/main.tfstate": state})
    assert sorted(map(repr, both)) == sorted(map(repr, (*alone, *side))) and side


ACCOUNT = "111122223333"
OIDC = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
GRANT = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"],
                                                  "Resource": [SECRET]}]}
TRUST = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": {"Federated": {"Ref": "Oidc"}},
    "Condition": {"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:example/ops:environment:prod"}}}]}
SCP = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "kms:ScheduleKeyDeletion",
                                               "Resource": "*"}]}
IAM_TEMPLATE = {"Resources": {
    "Oidc": {"Type": "AWS::IAM::OIDCProvider", "Properties": {"Url": "https://token.actions.githubusercontent.com",
                                                              "ClientIdList": ["sts.amazonaws.com"]}},
    "Deploy": {"Type": "AWS::IAM::Role", "Properties": {
        "RoleName": "ciam-prod-deploy", "AssumeRolePolicyDocument": TRUST,
        "Policies": [{"PolicyName": "deploy", "PolicyDocument": GRANT}],
        "Tags": [{"Key": "Role", "Value": "identity-ci"}]}},
    "Extra": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {"ManagedPolicyName": "extra", "PolicyDocument": {
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": KEY}]},
        "Roles": [{"Ref": "Deploy"}]}},
    "Guardrails": {"Type": "AWS::Organizations::Policy", "Properties": {
        "Name": "guardrails", "Type": "SERVICE_CONTROL_POLICY", "Content": SCP,
        "Tags": [{"Key": "Role", "Value": "org-guardrails"}]}},
    "Admins": {"Type": "AWS::SSO::PermissionSet", "Properties": {
        "Name": "ciam-admins", "InstanceArn": "arn:aws:sso:::instance/ssoins-1", "InlinePolicy": GRANT,
        "Tags": [{"Key": "Role", "Value": "identity-admins"}]}},
    "AdminsAssignment": {"Type": "AWS::SSO::Assignment", "Properties": {
        "InstanceArn": "arn:aws:sso:::instance/ssoins-1", "PrincipalId": "group-1", "PrincipalType": "GROUP",
        "PermissionSetArn": {"Fn::GetAtt": ["Admins", "PermissionSetArn"]}, "TargetId": ACCOUNT,
        "TargetType": "AWS_ACCOUNT"}}}}
IAM_PHYSICAL = {"Oidc": OIDC, "Deploy": "ciam-prod-deploy", "Extra": f"arn:aws:iam::{ACCOUNT}:policy/extra",
                "Guardrails": f"arn:aws:organizations::{ACCOUNT}:policy/o-1/service_control_policy/p-1",
                "Admins": "arn:aws:sso:::permissionSet/ssoins-1/ps-1", "AdminsAssignment": "a-1"}


def _state_of(pairs):
    """A Terraform state (format 4) holding the (type, attributes) pairs, one instance each."""
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "serial": 1, "lineage": "l", "outputs": {},
                       "resources": [{"mode": "managed", "type": t, "name": f"r{i}",
                                      "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                                      "instances": [{"schema_version": 0, "attributes": a,
                                                     "sensitive_attributes": []}]}
                                     for i, (t, a) in enumerate(pairs)]})


def test_iam_organizations_and_identity_center_read_as_their_state_does():
    """A stack's roles (trust, inline and attached policies), OIDC providers, control policies, permission sets and
    their assignments read to the same identities and guardrails as the Terraform state of the same resources."""
    stack = {"stack.json": _stack("ciam-prod-iam", {}), "resources.json": _resources(IAM_PHYSICAL),
             "template.json": IAM_TEMPLATE}
    texts = {f"iam/{p}": json.dumps(t) for p, t in stack.items()}
    state = _state_of((
        ("aws_iam_openid_connect_provider", {"arn": OIDC, "url": "https://token.actions.githubusercontent.com"}),
        ("aws_iam_role", {"name": "ciam-prod-deploy", "arn": f"arn:aws:iam::{ACCOUNT}:role/ciam-prod-deploy",
                          "assume_role_policy": json.dumps({**TRUST, "Statement": [{
                              **TRUST["Statement"][0], "Principal": {"Federated": OIDC}}]}),
                          "inline_policy": [{"name": "deploy", "policy": json.dumps(GRANT)}],
                          "tags": {"Role": "identity-ci"}}),
        ("aws_iam_policy", {"arn": IAM_PHYSICAL["Extra"], "name": "extra",
                            "policy": json.dumps(IAM_TEMPLATE["Resources"]["Extra"]["Properties"]["PolicyDocument"])}),
        ("aws_iam_role_policy_attachment", {"role": "ciam-prod-deploy", "policy_arn": IAM_PHYSICAL["Extra"]}),
        ("aws_organizations_policy", {"arn": IAM_PHYSICAL["Guardrails"], "id": "p-1", "name": "guardrails",
                                      "type": "SERVICE_CONTROL_POLICY", "content": json.dumps(SCP),
                                      "tags": {"Role": "org-guardrails"}}),
        ("aws_ssoadmin_permission_set", {"arn": IAM_PHYSICAL["Admins"], "name": "ciam-admins",
                                         "tags": {"Role": "identity-admins"}}),
        ("aws_ssoadmin_permission_set_inline_policy", {"permission_set_arn": IAM_PHYSICAL["Admins"],
                                                       "inline_policy": json.dumps(GRANT)}),
        ("aws_ssoadmin_account_assignment", {"permission_set_arn": IAM_PHYSICAL["Admins"], "principal_id": "group-1",
                                             "principal_type": "GROUP", "target_id": ACCOUNT})))
    stacked, _ = cloudformation_resources(texts)
    from_state, _ = cloudformation_resources({"terraform.tfstate": state})
    kinds = ("identity", "guardrail")
    assert sorted(map(repr, (r for r in stacked if r.kind in kinds))) == \
        sorted(map(repr, (r for r in from_state if r.kind in kinds)))
    deploy = next(r for r in stacked if r.kind == "identity" and r.name == "ciam-prod-deploy")
    assert deploy.attrs["ciamTrustedBy"] == ("https://token.actions.githubusercontent.com "
                                             "repo:example/ops:environment:prod",)
    assert {g.split(" on ")[0] for g in deploy.attrs["ciamGrant"]} == {"secretsmanager:GetSecretValue",
                                                                         "kms:Decrypt"}


ALB = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/ciam-prod-svc-sso/0abc"
ACL = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:regional/webacl/sso/1"
RATE_RULE = {"Name": "login", "Priority": 1, "Action": {"Block": {}},
             "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                  "MetricName": "login"},
             "Statement": {"RateBasedStatement": {"Limit": 300, "EvaluationWindowSec": 300,
                                                  "AggregateKeyType": "IP"}}}
EDGE_TEMPLATE = {"Resources": {
    "Sso": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {
        "Name": "ciam-prod-svc-sso", "Type": "application", "Scheme": "internet-facing", "Subnets": [SUBNET],
        "LoadBalancerAttributes": [{"Key": "idle_timeout.timeout_seconds", "Value": "120"}],
        "Tags": [{"Key": "Role", "Value": "pf-sso-service"}]}},
    "SsoAcl": {"Type": "AWS::WAFv2::WebACL", "Properties": {
        "Name": "sso", "Scope": "REGIONAL", "DefaultAction": {"Allow": {}}, "Rules": [RATE_RULE]}},
    "SsoAclAssociation": {"Type": "AWS::WAFv2::WebACLAssociation", "Properties": {
        "WebACLArn": {"Fn::GetAtt": ["SsoAcl", "Arn"]}, "ResourceArn": {"Ref": "Sso"}}},
    "SsoShield": {"Type": "AWS::Shield::Protection", "Properties": {"Name": "sso", "ResourceArn": {"Ref": "Sso"}}},
    "Forward": {"Type": "AWS::Route53Resolver::ResolverRule", "Properties": {
        "Name": "corp", "RuleType": "FORWARD", "DomainName": "corp.example.",
        "TargetIps": [{"Ip": "10.9.0.2", "Port": 53}]}}}}
EDGE_PHYSICAL = {"Sso": ALB, "SsoAcl": "sso|1|REGIONAL", "SsoAclAssociation": "assoc-1",
                 "SsoShield": f"arn:aws:shield::{ACCOUNT}:protection/p-1", "Forward": "rslvr-rr-1"}


def test_the_edge_reads_as_its_state_does():
    """A stack's web ACL (its rules, the load balancer it protects), Shield protection and forwarding rule read to the
    same edge and DNS resources as the Terraform state of the same resources; a web ACL's ARN follows from Ref's
    'name|id|scope'."""
    texts = {f"edge/{p}": json.dumps(t) for p, t in {
        "stack.json": _stack("ciam-prod-edge", {}), "resources.json": _resources(EDGE_PHYSICAL),
        "template.json": EDGE_TEMPLATE}.items()}
    state = _state_of((
        ("aws_lb", {"arn": ALB, "name": "ciam-prod-svc-sso", "load_balancer_type": "application", "internal": False,
                    "idle_timeout": "120", "subnet_mapping": [{"subnet_id": SUBNET}], "security_groups": [],
                    "dns_name": "cfn:Sso", "tags": {"Role": "pf-sso-service"}}),
        ("aws_wafv2_web_acl", {"arn": ACL, "name": "sso", "rule": [{
            "name": "login", "priority": 1, "action": [{"block": [{}]}],
            "visibility_config": [{"sampled_requests_enabled": True, "cloud_watch_metrics_enabled": True,
                                   "metric_name": "login"}],
            "statement": [{"rate_based_statement": [{"limit": 300, "evaluation_window_sec": 300,
                                                     "aggregate_key_type": "IP"}]}]}]}),
        ("aws_wafv2_web_acl_association", {"web_acl_arn": ACL, "resource_arn": ALB}),
        ("aws_shield_protection", {"id": EDGE_PHYSICAL["SsoShield"], "arn": EDGE_PHYSICAL["SsoShield"], "name": "sso",
                                   "resource_arn": ALB}),
        ("aws_route53_resolver_rule", {"id": "rslvr-rr-1", "name": "corp", "rule_type": "FORWARD",
                                       "domain_name": "corp.example.", "target_ip": [{"ip": "10.9.0.2", "port": 53}]})))
    stacked, _ = cloudformation_resources(texts)
    from_state, _ = cloudformation_resources({"terraform.tfstate": state})
    assert sorted(map(repr, stacked)) == sorted(map(repr, from_state))
    edge = {r.attrs["ciamEdgeKind"][0]: r for r in stacked if r.kind == "edge"}
    assert edge["waf"].attrs["ciamEdgeSetting"] == ("rate-based rule login: 300/300s per ip",)
    assert edge["ddos"].attrs["ciamEdgeFact"] == ("ddos network-advanced",)


def _same(template, physical, pairs, kinds):
    """The resources of kinds a one-stack template (its resources' physical ids given) reads to, and those the state
    of pairs reads to."""
    texts = {f"s/{p}": json.dumps(t) for p, t in {"stack.json": _stack("ciam-prod-s", {}),
                                                  "resources.json": _resources(physical),
                                                  "template.json": template}.items()}
    stacked, _ = cloudformation_resources(texts)
    from_state, _ = cloudformation_resources({"terraform.tfstate": _state_of(pairs)})
    return (sorted(map(repr, (r for r in stacked if r.kind in kinds))),
            sorted(map(repr, (r for r in from_state if r.kind in kinds))))


def test_dns_records_with_their_routing_read_as_their_state_does():
    template = {"Resources": {
        "Mx": {"Type": "AWS::Route53::RecordSet", "Properties": {
            "HostedZoneId": "Z1", "Name": "example.test.", "Type": "MX", "TTL": "300",
            "ResourceRecords": ["10 mail1.example.test", "20 mail2.example.test"]}},
        "Txt": {"Type": "AWS::Route53::RecordSet", "Properties": {
            "HostedZoneId": "Z1", "Name": "_verify.example.test", "Type": "TXT", "TTL": "120",
            "ResourceRecords": ['"token=abc"']}},
        "Api": {"Type": "AWS::Route53::RecordSet", "Properties": {
            "HostedZoneId": "Z1", "Name": "api.example.test", "Type": "A", "TTL": "60", "SetIdentifier": "a",
            "Weight": "3", "ResourceRecords": ["198.51.100.11"]}}}}
    pairs = (("aws_route53_record", {"name": "example.test", "zone_id": "Z1", "type": "MX", "ttl": 300,
                                     "records": ["10 mail1.example.test", "20 mail2.example.test"]}),
             ("aws_route53_record", {"name": "_verify.example.test", "zone_id": "Z1", "type": "TXT", "ttl": 120,
                                     "records": ["token=abc"]}),
             ("aws_route53_record", {"name": "api.example.test", "zone_id": "Z1", "type": "A", "ttl": 60,
                                     "set_identifier": "a", "records": ["198.51.100.11"],
                                     "weighted_routing_policy": [{"weight": 3}]}))
    stacked, state = _same(template, {"Mx": "mx", "Txt": "txt", "Api": "api"}, pairs, ("record",))
    assert stacked == state and len(stacked) == 3


def test_an_aurora_cluster_log_group_and_suppressions_read_as_their_state_does():
    cluster_params = {"log_min_duration_statement": "500"}
    template = {"Resources": {
        "Grants": {"Type": "AWS::RDS::DBCluster", "Properties": {
            "DBClusterIdentifier": "db-grants", "Engine": "aurora-postgresql", "EngineVersion": "16.4",
            "StorageEncrypted": "true", "KmsKeyId": KEY, "BackupRetentionPeriod": "14", "DeletionProtection": "true",
            "DBSubnetGroupName": {"Ref": "Subnets"}, "DBClusterParameterGroupName": {"Ref": "Params"},
            "Tags": [{"Key": "Role", "Value": "pf-grants-db"}]}},
        "Member": {"Type": "AWS::RDS::DBInstance", "Properties": {
            "DBInstanceIdentifier": "db-grants-1", "DBClusterIdentifier": {"Ref": "Grants"},
            "DBInstanceClass": "db.r6g.large", "Engine": "aurora-postgresql"}},
        "Subnets": {"Type": "AWS::RDS::DBSubnetGroup", "Properties": {
            "DBSubnetGroupName": "db-grants", "SubnetIds": [SUBNET], "DBSubnetGroupDescription": "db"}},
        "Params": {"Type": "AWS::RDS::DBClusterParameterGroup", "Properties": {
            "DBClusterParameterGroupName": "db-grants", "Family": "aurora-postgresql16",
            "Parameters": cluster_params}},
        "Audit": {"Type": "AWS::Logs::LogGroup", "Properties": {
            "LogGroupName": "/ciam/audit", "RetentionInDays": 400, "Tags": [{"Key": "Role", "Value": "audit-logs"}]}},
        "Rule": {"Type": "AWS::SecurityHub::AutomationRule", "Properties": {
            "RuleName": "exc-EXC-7", "RuleStatus": "ENABLED", "RuleOrder": 1, "Description": "EXC-7",
            "Criteria": {"ComplianceSecurityControlId": [{"Value": "IAM.6", "Comparison": "EQUALS"}]},
            "Actions": [{"Type": "FINDING_FIELDS_UPDATE",
                         "FindingFieldsUpdate": {"Workflow": {"Status": "SUPPRESSED"}}}]}},
        "Filter": {"Type": "AWS::GuardDuty::Filter", "Properties": {
            "Name": "exc-EXC-7", "Action": "ARCHIVE", "Rank": 1, "DetectorId": "d-1",
            "FindingCriteria": {"Criterion": {"type": {"Equals": ["Recon:EC2/PortProbeUnprotectedPort"]}}}}}}}
    physical = {"Grants": "db-grants", "Member": "db-grants-1", "Subnets": "db-grants", "Params": "db-grants",
                "Audit": "/ciam/audit", "Rule": f"arn:aws:securityhub:us-east-1:{ACCOUNT}:automation-rule/r-1",
                "Filter": "exc-EXC-7"}
    pairs = (("aws_rds_cluster", {"arn": f"arn:aws:rds:us-east-1:{ACCOUNT}:cluster:db-grants",
                                  "cluster_identifier": "db-grants", "engine": "aurora-postgresql",
                                  "engine_version": "16.4", "storage_encrypted": True, "kms_key_id": KEY,
                                  "backup_retention_period": 14, "deletion_protection": True,
                                  "db_subnet_group_name": "db-grants", "db_cluster_parameter_group_name": "db-grants",
                                  "tags": {"Role": "pf-grants-db"}, "vpc_security_group_ids": []}),
             ("aws_rds_cluster_instance", {"identifier": "db-grants-1", "cluster_identifier": "db-grants",
                                           "instance_class": "db.r6g.large"}),
             ("aws_db_subnet_group", {"name": "db-grants", "subnet_ids": [SUBNET]}),
             ("aws_rds_cluster_parameter_group", {"name": "db-grants", "parameter": [
                 {"name": k, "value": v} for k, v in cluster_params.items()]}),
             ("aws_cloudwatch_log_group", {"arn": f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/ciam/audit",
                                           "name": "/ciam/audit", "retention_in_days": 400,
                                           "tags": {"Role": "audit-logs"}}),
             ("aws_securityhub_automation_rule", {
                 "arn": physical["Rule"], "rule_name": "exc-EXC-7",
                 "criteria": [{"compliance_security_control_id": [{"value": "IAM.6", "comparison": "EQUALS"}]}],
                 "actions": [{"type": "FINDING_FIELDS_UPDATE",
                              "finding_fields_update": [{"workflow": [{"status": "SUPPRESSED"}]}]}]}),
             ("aws_guardduty_filter", {"id": "exc-EXC-7", "name": "exc-EXC-7", "action": "ARCHIVE",
                                       "finding_criteria": [{"criterion": [
                                           {"field": "type", "equals": ["Recon:EC2/PortProbeUnprotectedPort"]}]}]}))
    stacked, state = _same(template, physical, pairs, ("database", "logs", "suppression"))
    assert stacked == state and len(stacked) == 3


def test_volumes_snapshot_policies_backups_alarms_and_canaries_read_as_their_state_does():
    """A server's data disk (its attachment, its Lifecycle Manager policy), a backup vault with its lock, a plan and
    its selection by tag, a metric alarm and a Synthetics canary read to the same resources as their state."""
    tags = [{"Key": "Volume", "Value": "vol-data"}, {"Key": "Role", "Value": "volume-data"},
            {"Key": "SnapshotPolicy", "Value": "daily"}]
    template = {"Resources": {
        "Ds": {"Type": "AWS::EC2::Instance", "Properties": {
            "ImageId": "ami-1", "InstanceType": "m6i.large",
            "Tags": [{"Key": "Name", "Value": "ds-1"}, {"Key": "Role", "Value": "ds"}]}},
        "Disk": {"Type": "AWS::EC2::Volume", "Properties": {
            "AvailabilityZone": "us-east-1a", "Size": "500", "VolumeType": "io2", "Iops": 6000, "Encrypted": "true",
            "KmsKeyId": KEY, "Tags": tags}},
        "Attach": {"Type": "AWS::EC2::VolumeAttachment", "Properties": {
            "Device": "/dev/sdf", "VolumeId": {"Ref": "Disk"}, "InstanceId": {"Ref": "Ds"}}},
        "Daily": {"Type": "AWS::DLM::LifecyclePolicy", "Properties": {
            "Description": "daily", "State": "ENABLED", "Tags": [{"Key": "Name", "Value": "daily"}],
            "PolicyDetails": {"ResourceTypes": ["VOLUME"], "TargetTags": [{"Key": "SnapshotPolicy", "Value": "daily"}],
                              "Schedules": [{"Name": "daily", "CopyTags": True,
                                             "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS",
                                                            "Times": ["03:00"]},
                                             "RetainRule": {"Interval": 7, "IntervalUnit": "DAYS"},
                                             "CrossRegionCopyRules": [{"Target": "us-west-2", "Encrypted": True,
                                                                       "RetainRule": {"Interval": 7,
                                                                                      "IntervalUnit": "DAYS"}}]}]}}},
        "Vault": {"Type": "AWS::Backup::BackupVault", "Properties": {
            "BackupVaultName": "ciam-backups", "EncryptionKeyArn": KEY,
            "LockConfiguration": {"MinRetentionDays": 35, "ChangeableForDays": 3},
            "BackupVaultTags": {"Name": "ciam-backups", "Role": "backup-vault"}}},
        "Plan": {"Type": "AWS::Backup::BackupPlan", "Properties": {
            "BackupPlan": {"BackupPlanName": "backup-daily", "BackupPlanRule": [{
                "RuleName": "daily", "TargetBackupVault": {"Ref": "Vault"}, "ScheduleExpression": "cron(0 5 ? * * *)",
                "StartWindowMinutes": 120, "Lifecycle": {"DeleteAfterDays": 35}}]},
            "BackupPlanTags": {"Name": "backup-daily", "Role": "backup-daily"}}},
        "Selection": {"Type": "AWS::Backup::BackupSelection", "Properties": {
            "BackupPlanId": {"Ref": "Plan"}, "BackupSelection": {
                "SelectionName": "backup-daily", "IamRoleArn": "arn:aws:iam::111122223333:role/backup",
                "ListOfTags": [{"ConditionType": "STRINGEQUALS", "ConditionKey": "Role",
                                "ConditionValue": "volume-data"}]}}},
        "Lag": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
            "AlarmName": "ds-lag", "Namespace": "CIAM/DS", "MetricName": "ReplicationDelay", "Statistic": "Average",
            "Period": 60, "EvaluationPeriods": 5, "ComparisonOperator": "GreaterThanThreshold", "Threshold": 5000,
            "AlarmActions": ["arn:aws:sns:us-east-1:111122223333:page"],
            "Tags": [{"Key": "Realizes", "Value": "replication-lag"}, {"Key": "BindingRole", "Value": "alarm-lag"}]}},
        "Login": {"Type": "AWS::Synthetics::Canary", "Properties": {
            "Name": "sso-login", "RuntimeVersion": "syn-python-selenium-12.0", "Code": {"Handler": "canary.handler"},
            "ArtifactS3Location": "s3://canaries/sso-login/", "Schedule": {"Expression": "rate(5 minutes)"},
            "Tags": [{"Key": "Realizes", "Value": "sso-login"}, {"Key": "BindingRole", "Value": "canary-sso"}]}}}}
    physical = {"Ds": "i-1", "Disk": "vol-1", "Attach": "vol-1-i-1", "Daily": "policy-1", "Vault": "ciam-backups",
                "Plan": "p-1", "Selection": "s-1", "Lag": "ds-lag", "Login": "sso-login"}
    vault = f"arn:aws:backup:us-east-1:{ACCOUNT}:backup-vault:ciam-backups"
    retain = [{"interval": 7, "interval_unit": "DAYS"}]
    pairs = (("aws_instance", {"id": "i-1", "ami": "ami-1", "instance_type": "m6i.large",
                               "tags": {"Name": "ds-1", "Role": "ds"}}),
             ("aws_ebs_volume", {"id": "vol-1", "availability_zone": "us-east-1a", "size": 500, "type": "io2",
                                 "iops": 6000, "encrypted": True, "kms_key_id": KEY,
                                 "tags": {t["Key"]: t["Value"] for t in tags}}),
             ("aws_volume_attachment", {"id": "vol-1-i-1", "volume_id": "vol-1", "instance_id": "i-1",
                                        "device_name": "/dev/sdf"}),
             ("aws_dlm_lifecycle_policy", {
                 "id": "policy-1", "arn": f"arn:aws:dlm:us-east-1:{ACCOUNT}:policy/policy-1", "state": "ENABLED",
                 "tags": {"Name": "daily"}, "policy_details": [{
                     "resource_types": ["VOLUME"], "target_tags": {"SnapshotPolicy": "daily"}, "schedule": [{
                         "name": "daily", "copy_tags": True,
                         "create_rule": [{"interval": 24, "interval_unit": "HOURS", "times": ["03:00"]}],
                         "retain_rule": retain, "cross_region_copy_rule": [{"target": "us-west-2", "encrypted": True,
                                                                            "retain_rule": retain}]}]}]}),
             ("aws_backup_vault", {"arn": vault, "name": "ciam-backups", "kms_key_arn": KEY,
                                   "tags": {"Name": "ciam-backups", "Role": "backup-vault"}}),
             ("aws_backup_vault_lock_configuration", {"backup_vault_name": "ciam-backups", "min_retention_days": 35,
                                                      "changeable_for_days": 3}),
             ("aws_backup_plan", {"id": "p-1", "arn": f"arn:aws:backup:us-east-1:{ACCOUNT}:backup-plan:p-1",
                                  "name": "backup-daily", "tags": {"Name": "backup-daily", "Role": "backup-daily"},
                                  "rule": [{"rule_name": "daily", "target_vault_name": "ciam-backups",
                                            "schedule": "cron(0 5 ? * * *)", "start_window": 120,
                                            "lifecycle": [{"delete_after": 35}]}]}),
             ("aws_backup_selection", {"id": "s-1", "plan_id": "p-1", "name": "backup-daily",
                                       "selection_tag": [{"type": "STRINGEQUALS", "key": "Role",
                                                          "value": "volume-data"}]}),
             ("aws_cloudwatch_metric_alarm", {
                 "arn": f"arn:aws:cloudwatch:us-east-1:{ACCOUNT}:alarm:ds-lag", "alarm_name": "ds-lag",
                 "namespace": "CIAM/DS", "metric_name": "ReplicationDelay",
                 "alarm_actions": ["arn:aws:sns:us-east-1:111122223333:page"],
                 "tags": {"Realizes": "replication-lag", "BindingRole": "alarm-lag"}}),
             ("aws_synthetics_canary", {"arn": f"arn:aws:synthetics:us-east-1:{ACCOUNT}:canary:sso-login",
                                        "name": "sso-login", "schedule": [{"expression": "rate(5 minutes)"}],
                                        "artifact_s3_location": "s3://canaries/sso-login/",
                                        "tags": {"Realizes": "sso-login", "BindingRole": "canary-sso"}}))
    kinds = ("volume", "snapshot-policy", "backup-vault", "backup-plan", "alarm", "canary")
    stacked, state = _same(template, physical, pairs, kinds)
    assert stacked == state and len(stacked) == len(kinds)

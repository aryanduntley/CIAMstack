"""AWS Terraform state read into an environment's servers and bindings: a state that matches the record changes
nothing; what the cloud says replaces the record's values (a resized instance); a new tagged resource is added and an
untagged one named; firewall rules are grouped by their names; secret values and sensitive attributes are never read;
an overlay leaves what it inherits to its base; only AWS environments laid out as <cloud>/<env>/ are imported."""
import json

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one, values
from opsdir_adapter_aws.inventory import read_terraform_state, state_resources
from opsdir_format_terraform.state import read_state
from support import SUPERS

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
STAGE = "env=stage,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"
VPC, SUBNET, NAT = "vpc-0a1b2c3d4e5f67890", "subnet-0a11b22c33d44e55a", "nat-0123456789abcdef0"
SECRET = "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/ds-root-password"
KEY = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record(*extra):
    return make_directory((), SUPERS, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="aws",
             ciamRegion="us-east-1"),
        _row("cloud=other,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="other", ciamCloudProvider="azure",
             ciamRegion="eastus2"),
        _row("env=prod,cloud=other,ou=environments,dc=ciam-ops", ("ciamEnvironment",), env="prod"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=vpc,{B}", ("ciamNetwork",), cn="vpc", ciamBindingRole="network", ciamCidr="10.20.0.0/16",
             ciamProviderRef=VPC, ciamOwner="cn=netsec,ou=owners,dc=ciam-ops"),
        _row(f"cn=subnet-ds-a,{B}", ("ciamSubnetBinding",), cn="subnet-ds-a", ciamBindingRole="subnet-ds",
             ciamCidr="10.20.1.0/24", ciamProviderRef=SUBNET, ciamZone="us-east-1a"),
        _row(f"cn=ds-1,{ENV}", ("ciamServer",), cn="ds-1", ciamServerRole="ds", ciamHostname="ds-1.internal.test",
             ciamSubnet=f"cn=subnet-ds-a,{B}", ciamPrivateIp="10.20.1.11", ciamZone="us-east-1a",
             ciamInstanceSize="m6i.xlarge", ciamImageRef="ami-0abc", ciamProductVersion="PingDS 7.5.1"),
        _row(f"cn=svc-ldaps,{B}", ("ciamServiceName",), cn="svc-ldaps", ciamBindingRole="ds-ldaps-service",
             ciamFqdn="ldap.example.test", ciamTargetRole="ds", ciamPort="1636", ciamFrontendIp="10.20.1.100",
             ciamDnsZoneRef="Z0PRIVATE", ciamEdgeFact="tls-mode passthrough", ciamTtlSeconds="60"),
        _row(f"cn=fw-app,{B}", ("ciamFirewallRule",), cn="fw-app", ciamBindingRole="fw-consumer-app",
             ciamSourceCidr=["10.30.0.0/24"], ciamPort="1636", ciamProtocol="tcp", ciamTargetRole="ds",
             ciamAllowsConsumer="cn=app,ou=consumers,dc=ciam-ops"),
        _row(f"cn=secret-root,{B}", ("ciamSecretRef",), cn="secret-root", ciamBindingRole="ds-root-password",
             ciamRefUri=f"aws-sm://{SECRET}", ciamLastRotated="20260302000000Z"),
        _row(f"cn=key-disk,{B}", ("ciamKeyRef",), cn="key-disk", ciamBindingRole="disk-encryption",
             ciamRefUri=f"aws-kms://{KEY}", ciamAutoRotate="TRUE", ciamProtectionLevel="hsm"),
        _row(f"cn=backup,{B}", ("ciamBackupTarget",), cn="backup", ciamBindingRole="backup-target",
             ciamStorageRef="s3://ciam-backups", ciamRetentionDays="35"),
        _row(f"cn=egress,{B}", ("ciamEgress",), cn="egress", ciamBindingRole="pf-egress", ciamCidr="203.0.113.10/32",
             ciamProviderRef=NAT, ciamNatAllocation="static"),
        *extra))


def _res(mode, type_, name, attrs, sensitive=()):
    return {"mode": mode, "type": type_, "name": name, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
            "instances": [{"schema_version": 1, "attributes": attrs,
                           "sensitive_attributes": [[{"type": "get_attr", "value": s}] for s in sensitive]}]}


def _state(*changes):
    lb = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/ciam-prod-svc-ldaps/0a1b"
    tg = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/ciam-prod-svc-ldaps-1636/0c1d"
    resources = [
        _res("data", "aws_vpc", "main", {"id": VPC, "cidr_block": "10.20.0.0/16"}),
        _res("data", "aws_subnet", "subnet_ds_a", {"id": SUBNET, "cidr_block": "10.20.1.0/24",
                                                    "availability_zone": "us-east-1a"}),
        _res("managed", "aws_instance", "ds_1", {
            "id": "i-0aaa", "ami": "ami-0abc", "instance_type": "m6i.xlarge", "private_ip": "10.20.1.11",
            "availability_zone": "us-east-1a", "subnet_id": SUBNET, "password_data": "not-for-anyone",
            "tags": {"Name": "ds-1", "Role": "ds", "Hostname": "ds-1.internal.test", "Product": "PingDS 7.5.1"}},
             sensitive=("password_data",)),
        _res("managed", "aws_security_group", "ds", {"id": "sg-0ds", "name": "ciam-prod-ds", "ingress": []}),
        _res("managed", "aws_vpc_security_group_ingress_rule", "fw_app_0_1636", {
            "security_group_rule_id": "sgr-01", "security_group_id": "sg-0ds", "cidr_ipv4": "10.30.0.0/24",
            "from_port": 1636, "to_port": 1636, "ip_protocol": "tcp", "description": "consumer app (fw-app)"}),
        _res("managed", "aws_lb", "svc_ldaps", {"arn": lb, "name": "ciam-prod-svc-ldaps", "internal": True,
                                                "dns_name": "ciam-prod-svc-ldaps-0a1b.elb.us-east-1.amazonaws.com",
                                                "subnet_mapping": [{"subnet_id": SUBNET,
                                                                    "private_ipv4_address": "10.20.1.100"}]}),
        _res("managed", "aws_lb_target_group", "svc_ldaps_1636", {"arn": tg, "port": 1636}),
        _res("managed", "aws_lb_listener", "svc_ldaps_1636", {"load_balancer_arn": lb, "port": 1636, "default_action": [
            {"type": "forward", "target_group_arn": tg}]}),
        _res("managed", "aws_lb_target_group_attachment", "svc_ldaps_1636_ds_1", {"target_group_arn": tg,
                                                                                 "target_id": "i-0aaa"}),
        _res("managed", "aws_route53_record", "svc_ldaps", {"name": "ldap.example.test", "zone_id": "Z0PRIVATE",
                                                            "type": "A", "alias": [{
                                                                "name": "ciam-prod-svc-ldaps-0a1b.elb.us-east-1.amazonaws.com",
                                                                "zone_id": "Z26RNL4JYFTOTI"}]}),
        _res("data", "aws_secretsmanager_secret", "ds_root_password", {"arn": SECRET, "name": "ciam/prod/ds-root-password"}),
        _res("managed", "aws_secretsmanager_secret_version", "ds_root_password", {
            "secret_id": SECRET, "secret_string": "S3cr3t-Passw0rd!"}, sensitive=("secret_string",)),
        _res("managed", "aws_kms_key", "disk", {"arn": KEY, "key_id": "mrk-1234", "enable_key_rotation": True}),
        _res("data", "aws_s3_bucket", "ds_backups", {"bucket": "ciam-backups", "arn": "arn:aws:s3:::ciam-backups"}),
        _res("data", "aws_nat_gateway", "pf_egress", {"id": NAT, "public_ip": "203.0.113.10"}),
        *changes]
    return json.dumps({"version": 4, "terraform_version": "1.9.5", "serial": 12, "lineage": "0a1b", "outputs": {},
                       "resources": resources})


def _after(d, imported):
    scopes = [s.lower() for s, _ in imported.groups]
    kept = {n: e for n, e in d.entries.items() if n not in scopes}
    added = {e.norm: e for e in (*(c for c in imported.containers if c.norm not in d.entries),
                                 *(e for _, es in imported.groups for e in es))}
    return d._replace(entries={**kept, **added})


def test_a_state_that_matches_the_record_changes_nothing():
    d = _record()
    imported = read_terraform_state({"main/prod/terraform.tfstate": _state()}, d, ())
    assert not import_changes(d, imported)
    assert "aws_secretsmanager_secret_version (1): not read (holds secret values, or isn't modeled yet)" \
        in imported.notices


def test_what_the_cloud_says_replaces_the_records_values_and_keeps_the_rest():
    d = _record()
    resized = _state().replace('"instance_type": "m6i.xlarge"', '"instance_type": "m6i.2xlarge"') \
        .replace('"enable_key_rotation": true', '"enable_key_rotation": false')
    after = _after(d, read_terraform_state({"main/prod/terraform.tfstate": resized}, d, ()))
    assert one(get(after, f"cn=ds-1,{ENV}"), "ciamInstanceSize") == "m6i.2xlarge"
    key = get(after, f"cn=key-disk,{B}")
    assert (one(key, "ciamAutoRotate"), one(key, "ciamProtectionLevel")) == ("FALSE", "hsm")


def test_a_new_tagged_resource_is_added_and_an_untagged_one_named():
    d = _record()
    extra = (_res("managed", "aws_instance", "ds_2", {
                 "id": "i-0bbb", "ami": "ami-0abc", "instance_type": "m6i.xlarge", "private_ip": "10.20.1.12",
                 "availability_zone": "us-east-1a", "subnet_id": SUBNET,
                 "tags": {"Name": "ds-2", "Role": "ds", "Hostname": "ds-2.internal.test"}}),
             _res("managed", "aws_instance", "jump", {
                 "id": "i-0ccc", "ami": "ami-0zzz", "instance_type": "t3.micro", "private_ip": "10.20.1.50",
                 "subnet_id": SUBNET, "private_dns": "ip-10-20-1-50.ec2.internal"}),
             _res("managed", "aws_vpc_security_group_ingress_rule", "debug", {
                 "security_group_rule_id": "sgr-99", "security_group_id": "sg-0ds", "cidr_ipv4": "0.0.0.0/0",
                 "from_port": 1636, "to_port": 1636, "ip_protocol": "tcp", "description": "temporary debug"}))
    imported = read_terraform_state({"main/prod/terraform.tfstate": _state(*extra)}, d, ())
    after = _after(d, imported)
    ds2 = get(after, f"cn=ds-2,{ENV}")
    assert (one(ds2, "ciamServerRole"), one(ds2, "ciamSubnet"), one(ds2, "ciamHostname")) == \
        ("ds", f"cn=subnet-ds-a,{B}", "ds-2.internal.test")
    assert get(after, f"cn=i-0ccc,{ENV}") is None
    assert "main/prod: server i-0ccc (ciamPrivateIp 10.20.1.50) is not in the record and names no role (tag it Role, " \
           "name it in roles.json, or record it); not imported" in imported.notices
    assert "main/prod: firewall sgr-99 (ciamSourceCidr 0.0.0.0/0, ciamPort 1636) is not in the record and names no " \
           "role (tag it Role, name it in roles.json, or record it); not imported" in imported.notices
    assert "main/prod: server ds-2 added (role ds)" in imported.notices


def test_secret_values_and_sensitive_attributes_are_never_read():
    (instance,) = [r for r in read_state(_state())[0] if r.type == "aws_instance"]
    assert "password_data" not in instance.attributes
    dump = str([r for r in state_resources(_state())[0]])
    assert "S3cr3t" not in dump and "not-for-anyone" not in dump


def test_an_overlay_leaves_what_it_inherits_to_its_base():
    d = _record(_row(STAGE, ("ciamEnvironment",), env="stage", ciamOverlayOf=ENV))
    imported = read_terraform_state({"main/stage/terraform.tfstate": json.dumps({"version": 4, "resources": [
        _res("data", "aws_vpc", "main", {"id": VPC, "cidr_block": "10.20.0.0/16"})]})}, d, ())
    assert imported.groups == () and imported.notices == (
        "main/stage: network vpc-0a1b2c3d4e5f67890 is inherited from main/prod; unchanged here",)


def test_only_aws_environments_laid_out_by_cloud_and_environment_are_imported():
    d = _record()
    imported = read_terraform_state({"other/prod/terraform.tfstate": _state(), "terraform.tfstate": _state(),
                                     "main/test/terraform.tfstate": _state()}, d, ())
    assert imported.groups == ()
    assert set(imported.notices) >= {
        "other/prod: not an AWS environment in the record; not imported",
        "terraform.tfstate: put each environment's Terraform state under <cloud>/<env>/ (e.g. "
        "source/prod/terraform.tfstate); not imported",
        "main/test: no such environment in the record; nothing imported"}


def test_a_new_binding_keeps_the_providers_reference_so_it_is_found_again():
    d = _record()
    extra = (_res("managed", "aws_subnet", "ds_b", {"id": "subnet-0b", "cidr_block": "10.20.2.0/24",
                                                     "availability_zone": "us-east-1b", "tags": {"Role": "subnet-ds"}}),)
    files = {"main/prod/terraform.tfstate": _state(*extra)}
    after = _after(d, read_terraform_state(files, d, ()))
    assert one(get(after, f"cn=subnet-0b,{B}"), "ciamProviderRef") == "subnet-0b"
    assert not import_changes(after, read_terraform_state(files, after, ()))


def test_a_security_groups_role_is_that_of_its_instances():
    extra = (_res("managed", "aws_instance", "pf_1", {
                 "id": "i-0pf", "ami": "ami-0pf", "instance_type": "m6i.large", "private_ip": "10.20.4.21",
                 "subnet_id": SUBNET, "vpc_security_group_ids": ["sg-0pf"],
                 "tags": {"Name": "pf-engine-1", "Role": "pf-engine", "Hostname": "pf-engine-1.internal.test"}}),
             _res("managed", "aws_security_group", "pf_engine", {"id": "sg-0pf", "name": "ciam-prod-pf-engine"}),
             _res("managed", "aws_vpc_security_group_ingress_rule", "fw_sso_public_0_443", {
                 "security_group_rule_id": "sgr-02", "security_group_id": "sg-0pf", "cidr_ipv4": "0.0.0.0/0",
                 "from_port": 443, "to_port": 443, "ip_protocol": "tcp", "description": "fw-sso-public (fw-sso-public)"}))
    (rule,) = [r for r in state_resources(_state(*extra))[0] if r.kind == "firewall" and r.name == "fw-sso-public"]
    assert rule.attrs["ciamTargetRole"] == ("pf-engine",)

"""The AWS render's Terraform types as CloudFormation (5.6): one row per resource type the renderers write (cfn_render
translates by it), what the data sources Terraform reads are natively, and the types CloudFormation has no form for.
Property names follow AWS's resource schemas (cfn-lint checks every rendered template against them). Pure data and
small pure converters.
"""
from opsdir_format_cloudformation.template import ACCOUNT_ID, PARTITION, REGION, URL_SUFFIX, Parameter, ref, sub
from .cfn_render import (Attribute, Computed, Custom, Derived, Merge, Native, Nest, Pseudo, concat, json_document,
                         obj, object_key, one, own, pascal, tag_list, translated, translation, trim_prefix)

# Types CloudFormation has no resource type for: they stay in the Terraform root beside the template (research 2564;
# AWS's resource schemas as cfn-lint ships them: no Service Quotas or Macie classification job type, and a VPC's
# default route table, which exists with the VPC, has none to adopt it).
NO_NATIVE = frozenset({"aws_inspector2_enabler", "aws_config_retention_configuration",
                       "aws_macie2_classification_export_configuration", "aws_macie2_classification_job",
                       "aws_servicequotas_service_quota", "aws_default_route_table",
                       # organization-wide security services (5.7b): no CloudFormation type in cfn-lint's schemas
                       "aws_guardduty_organization_admin_account", "aws_guardduty_organization_configuration",
                       "aws_guardduty_organization_configuration_feature", "aws_inspector2_delegated_admin_account",
                       "aws_inspector2_organization_configuration", "aws_organizations_delegated_administrator",
                       # a managed directory (flow 76): its CloudFormation stack (already a template, its password a
                       # dynamic reference), and the region and forwarders on it, which have no CloudFormation type
                       "aws_cloudformation_stack", "aws_directory_service_region",
                       "aws_directory_service_conditional_forwarder"})
# Types whose CloudFormation type AWS's GovCloud resource specification doesn't have (cfn-lint's us-gov-west-1
# schemas): in a GovCloud template they stay Terraform too.
NOT_IN_GOVCLOUD = frozenset({"aws_macie2_account", "aws_macie2_custom_data_identifier", "aws_shield_protection",
                             "aws_budgets_budget", "aws_cloudfront_distribution"})


def unavailable(type_, region):
    """Whether a type has no CloudFormation form in a region (beyond NO_NATIVE)."""
    return bool(region) and region.startswith("us-gov-") and type_ in NOT_IN_GOVCLOUD


# ------------------------------------------------------------------ helpers

def _set(name, spec):
    """Merge.into: the merged block as one object under name."""
    return lambda props, f, cx: {**props, name: obj(own(f), cx, spec)}


def _append(name, spec):
    """Merge.into: the merged block appended to the list under name."""
    return lambda props, f, cx: {**props, name: [*props.get(name, []), obj(own(f), cx, spec)]}


# Terraform's default for the descriptions CloudFormation requires (they can't change in place: another value would
# replace a group Terraform made).
TERRAFORM_DESCRIPTION = "Managed by Terraform"


def _defaults(spec, **defaults):
    """Properties by spec, with CloudFormation's required ones defaulted as Terraform defaults them."""
    def properties(f, cx):
        return {**defaults, **obj(own(f), cx, spec)}
    return properties


def _number(v, cx):
    value = cx.value(v)
    return float(value) if isinstance(value, str) and value.replace(".", "", 1).isdigit() else value


def _attributes(pairs):
    """[{Key, Value}] of an ELB's attributes, values as strings."""
    return [{"Key": k, "Value": str(v).lower() if isinstance(v, bool) else str(v)} for k, v in pairs]


def _as_string(name):
    return Custom(lambda v, cx: {name: str(cx.value(v)) if isinstance(v, (int, float)) else cx.value(v)})


def _flag(name, yes, no):
    return Custom(lambda v, cx: {name: yes if v else no})


def _arn_sub(pattern):
    """A reference form building an ARN the type has no attribute for: pattern with {id} for the resource's Ref."""
    return lambda lid: sub(pattern.replace("{id}", "${" + lid + "}"))


# ------------------------------------------------------------------ backup

BACKUP_LIFECYCLE = {"delete_after": "DeleteAfterDays", "cold_storage_after": "MoveToColdStorageAfterDays",
                    "opt_in_to_archive_for_supported_resources": "OptInToArchiveForSupportedResources"}
BACKUP_RULE = {"rule_name": "RuleName", "target_vault_name": "TargetBackupVault", "schedule": "ScheduleExpression",
               "schedule_expression_timezone": "ScheduleExpressionTimezone", "start_window": "StartWindowMinutes",
               "completion_window": "CompletionWindowMinutes", "enable_continuous_backup": "EnableContinuousBackup",
               "recovery_point_tags": "RecoveryPointTags", "lifecycle": Nest("Lifecycle", BACKUP_LIFECYCLE),
               "copy_action": Nest("CopyActions", {"destination_vault_arn": "DestinationBackupVaultArn",
                                                   "lifecycle": Nest("Lifecycle", BACKUP_LIFECYCLE)}, True)}


def _backup_plan(f, cx):
    return {"BackupPlan": obj(own(f), cx, {"name": "BackupPlanName",
                                           "rule": Nest("BackupPlanRule", BACKUP_RULE, True)})}


def _backup_selection(f, cx):
    rest = {k: v for k, v in own(f).items() if k != "plan_id"}
    return {"BackupPlanId": cx.value(f["plan_id"]), "BackupSelection": obj(rest, cx, {
        "name": "SelectionName", "iam_role_arn": "IamRoleArn", "resources": "Resources",
        "not_resources": "NotResources",
        "selection_tag": Nest("ListOfTags", {"type": "ConditionType", "key": "ConditionKey",
                                             "value": "ConditionValue"}, True)})}


# ------------------------------------------------------------------ budgets

def _budget(f, cx):
    f = own(f)
    notifications = [{"Notification": obj({k: v for k, v in n.items()
                                           if k not in ("subscriber_sns_topic_arns", "subscriber_email_addresses")},
                                          cx, {"comparison_operator": "ComparisonOperator",
                                               "notification_type": "NotificationType", "threshold": "Threshold",
                                               "threshold_type": "ThresholdType"}),
                      "Subscribers": [*({"SubscriptionType": "SNS", "Address": a}
                                        for a in cx.value(n.get("subscriber_sns_topic_arns", ()))),
                                      *({"SubscriptionType": "EMAIL", "Address": a}
                                        for a in cx.value(n.get("subscriber_email_addresses", ())))]}
                     for n in f.get("notification", ())]
    budget = obj({k: v for k, v in f.items() if k != "notification"}, cx, {
        "name": "BudgetName", "budget_type": "BudgetType", "time_unit": "TimeUnit",
        "limit_amount": Custom(lambda v, c: {"BudgetLimit": {"Amount": _number(v, c),
                                                             "Unit": c.value(f["limit_unit"])}}),
        "limit_unit": None,
        "cost_filter": Custom(lambda v, c: {"CostFilters": {b["name"]: c.value(b["values"]) for b in v}})})
    return {"Budget": budget, **({"NotificationsWithSubscribers": notifications} if notifications else {})}


# ------------------------------------------------------------------ Security Hub organization-wide (5.7b)
def _first_block(f, name):
    found = f.get(name) or ()
    return found[0] if found else {}


def _hub_organization(f, cx):
    f = own(f)
    kind = _first_block(f, "organization_configuration").get("configuration_type")
    return {"AutoEnable": cx.value(f.get("auto_enable", False)),
            **({"AutoEnableStandards": cx.value(f["auto_enable_standards"])} if "auto_enable_standards" in f else {}),
            **({"ConfigurationType": cx.value(kind)} if kind is not None else {})}


def _hub_policy(f, cx):
    f = own(f)
    p = _first_block(f, "configuration_policy")
    controls = _first_block(p, "security_controls_configuration")
    return {"Name": cx.value(f["name"]), **({"Description": cx.value(f["description"])} if "description" in f else {}),
            "ConfigurationPolicy": {"SecurityHub": {
                "ServiceEnabled": cx.value(p.get("service_enabled", True)),
                "EnabledStandardIdentifiers": cx.value(p.get("enabled_standard_arns", [])),
                "SecurityControlsConfiguration": {
                    "DisabledSecurityControlIdentifiers": cx.value(controls.get("disabled_control_identifiers", []))}}}}


def _hub_association(f, cx):
    """A configuration policy's association: with the organization's root (what the render associates it with)."""
    f = own(f)
    return {"TargetId": cx.value(f["target_id"]), "TargetType": "ROOT",
            "ConfigurationPolicyId": cx.value(f["policy_id"])}


# ------------------------------------------------------------------ IAM

def _firehose_s3(b, c):
    return {"BucketARN": c.value(b["bucket_arn"]), "RoleARN": c.value(b["role_arn"]),
            **({"Prefix": c.value(b["prefix"])} if "prefix" in b else {})}


def _firehose_secret(b, c):
    return {"Enabled": c.value(b.get("enabled", True)), "SecretARN": c.value(b["secret_arn"]),
            "RoleARN": c.value(b["role_arn"])}


def _firehose_processing(b, c):
    return {"Enabled": c.value(b.get("enabled", True)), "Processors": [
        {"Type": c.value(p["type"]), "Parameters": [{"ParameterName": c.value(x["parameter_name"]),
                                                     "ParameterValue": c.value(x["parameter_value"])}
                                                    for x in p.get("parameters", [])]}
        for p in b.get("processors", [])]}


def _splunk_destination(v, c):
    """A Firehose stream's splunk_configuration as SplunkDestinationConfiguration (no HECToken: the secret holds it)."""
    b = v[0]
    return {"SplunkDestinationConfiguration": {
        "HECEndpoint": c.value(b["hec_endpoint"]), "HECEndpointType": c.value(b["hec_endpoint_type"]),
        "S3BackupMode": c.value(b["s3_backup_mode"]), "S3Configuration": _firehose_s3(b["s3_configuration"][0], c),
        "SecretsManagerConfiguration": _firehose_secret(b["secrets_manager_configuration"][0], c),
        **({"ProcessingConfiguration": _firehose_processing(b["processing_configuration"][0], c)}
           if "processing_configuration" in b else {})}}


def _http_destination(v, c):
    """A Firehose stream's http_endpoint_configuration as HttpEndpointDestinationConfiguration (no AccessKey)."""
    b = v[0]
    return {"HttpEndpointDestinationConfiguration": {
        "EndpointConfiguration": {"Url": c.value(b["url"]), "Name": c.value(b["name"])},
        "RoleARN": c.value(b["role_arn"]), "S3BackupMode": c.value(b["s3_backup_mode"]),
        "S3Configuration": _firehose_s3(b["s3_configuration"][0], c),
        "SecretsManagerConfiguration": _firehose_secret(b["secrets_manager_configuration"][0], c),
        **({"RequestConfiguration": {"ContentEncoding": c.value(b["request_configuration"][0]["content_encoding"])}}
           if "request_configuration" in b else {})}}


def _role_policy(props, f, cx):
    return {**props, "Policies": [*props.get("Policies", []), obj(own(f), cx, {
        "role": None, "name": "PolicyName", "policy": "PolicyDocument"})]}


def _attached_policy(props, f, cx):
    return {**props, "ManagedPolicyArns": [*props.get("ManagedPolicyArns", []), cx.value(own(f)["policy_arn"])]}


def _instance_profile(f, cx):
    return obj(own(f), cx, {"name": "InstanceProfileName", "path": "Path",
                            "role": Custom(lambda v, c: {"Roles": [c.value(v)]})})


# ------------------------------------------------------------------ EC2 and networking

PROTOCOLS = {"-1": -1, "all": -1, "tcp": 6, "udp": 17, "icmp": 1, "6": 6, "17": 17, "1": 1}


def _acl_entries(lid, f, cx):
    """A network ACL's rules and subnet associations, each its own resource natively."""
    def entry(rule, egress):
        protocol = PROTOCOLS.get(str(rule["protocol"]).lower(), rule["protocol"])
        ports = {"PortRange": {"From": rule["from_port"], "To": rule["to_port"]}} if protocol in (6, 17) else {}
        icmp = {"Icmp": {"Type": rule.get("icmp_type", -1), "Code": rule.get("icmp_code", -1)}} if protocol == 1 else {}
        known = {"rule_no", "action", "protocol", "cidr_block", "ipv6_cidr_block", "from_port", "to_port",
                 "icmp_type", "icmp_code"}
        unknown = sorted(set(rule) - known)
        if unknown:
            raise SystemExit(f"{cx.where}: no CloudFormation form for {', '.join(unknown)} of a rule")
        address = ({"CidrBlock": cx.value(rule["cidr_block"])} if "cidr_block" in rule else
                   {"Ipv6CidrBlock": cx.value(rule["ipv6_cidr_block"])})
        return (f"{'Egress' if egress else 'Ingress'}{rule['rule_no']}", "AWS::EC2::NetworkAclEntry",
                {"NetworkAclId": ref(lid), "RuleNumber": rule["rule_no"], "Protocol": protocol,
                 "RuleAction": cx.value(rule["action"]), "Egress": egress, **address, **ports, **icmp})
    subnets = cx.value(f.get("subnet_ids", ()))
    return (*(entry(r, False) for r in f.get("ingress", ())), *(entry(r, True) for r in f.get("egress", ())),
            *((f"Subnet{i}", "AWS::EC2::SubnetNetworkAclAssociation", {"NetworkAclId": ref(lid), "SubnetId": s})
              for i, s in enumerate(subnets)))


ROUTE_TARGETS = {"gateway_id": "GatewayId", "nat_gateway_id": "NatGatewayId", "transit_gateway_id": "TransitGatewayId",
                 "vpc_peering_connection_id": "VpcPeeringConnectionId", "vpc_endpoint_id": "VpcEndpointId",
                 "network_interface_id": "NetworkInterfaceId", "egress_only_gateway_id": "EgressOnlyInternetGatewayId",
                 "carrier_gateway_id": "CarrierGatewayId", "local_gateway_id": "LocalGatewayId",
                 "core_network_arn": "CoreNetworkArn"}
ROUTE = {"cidr_block": "DestinationCidrBlock", "ipv6_cidr_block": "DestinationIpv6CidrBlock",
         "destination_prefix_list_id": "DestinationPrefixListId", **ROUTE_TARGETS}


def _routes(lid, f, cx):
    """A route table's inline routes, each an AWS::EC2::Route natively (imported with an adopted table by its id and
    destination, the route's identifier in AWS's schema)."""
    def route(i, r):
        props = obj(r, cx, ROUTE, f"{cx.where}.route")
        destination = r.get("cidr_block")
        imported = ((lambda table: {"RouteTableId": table, "CidrBlock": destination}),) if destination else ()
        return (f"Route{i}", "AWS::EC2::Route", {"RouteTableId": ref(lid), **props}, *imported)
    return tuple(route(i, r) for i, r in enumerate(f.get("route", ())))


def _routes_adoptable(f):
    """Why an adopted route table can't be imported with its routes: a route without an IPv4 destination (an IPv6
    one, a prefix list's), which AWS's Route schema can't identify (it names a route by table and IPv4 CIDR)."""
    other = [str(r.get("ipv6_cidr_block") or r.get("destination_prefix_list_id")) for r in f.get("route", ())
             if "cidr_block" not in r]
    return (f"CloudFormation imports a route by its table and IPv4 CIDR, which route {', '.join(other)} hasn't"
            if other else None)


# The one outbound rule a security group without egress rules gets: AWS's documented way to remove the allow-all egress
# a new group otherwise keeps in CloudFormation (Terraform removes it), loopback being no traffic.
NO_EGRESS = {"IpProtocol": "-1", "CidrIp": "127.0.0.1/32",
             "Description": "No outbound traffic (as Terraform leaves the group: AWS's allow-all egress removed)"}


def _no_default_egress(props):
    return props if props.get("SecurityGroupEgress") else {**props, "SecurityGroupEgress": [NO_EGRESS]}


METADATA_OPTIONS = Nest("MetadataOptions", {
    "http_tokens": "HttpTokens", "http_endpoint": "HttpEndpoint",
    "http_put_response_hop_limit": "HttpPutResponseHopLimit", "instance_metadata_tags": "InstanceMetadataTags"})


def _instance(f, cx):
    """An instance; its root_block_device as the AMI's root device mapping (the root device name a parameter: Terraform
    asks the AMI for it, CloudFormation can't)."""
    root = f.get("root_block_device")
    rest = {k: v for k, v in own(f).items() if k != "root_block_device"}
    props = obj(rest, cx, {"ami": "ImageId", "instance_type": "InstanceType", "subnet_id": "SubnetId",
                           "private_ip": "PrivateIpAddress", "iam_instance_profile": "IamInstanceProfile",
                           "vpc_security_group_ids": "SecurityGroupIds", "key_name": "KeyName",
                           "availability_zone": "AvailabilityZone", "user_data": "UserData",
                           "ebs_optimized": "EbsOptimized", "monitoring": "Monitoring",
                           "disable_api_termination": "DisableApiTermination",
                           "metadata_options": METADATA_OPTIONS})
    if not root:
        return props
    ebs = obj(root[0], cx, {"encrypted": "Encrypted", "kms_key_id": "KmsKeyId", "volume_size": "VolumeSize",
                            "volume_type": "VolumeType", "iops": "Iops", "throughput": "Throughput",
                            "delete_on_termination": "DeleteOnTermination"}, f"{cx.where}.root_block_device")
    return {**props, "BlockDeviceMappings": [{"DeviceName": cx.param(_root_device_id(f["ami"])), "Ebs": ebs}]}


def _root_device_id(ami):
    return "RootDevice" + "".join(c for c in str(ami).title() if c.isalnum())


def _root_device(f, cx):
    if not f.get("root_block_device"):
        return ()
    return (Parameter(_root_device_id(f["ami"]), "String", None,
                      f"The root device name of AMI {f['ami']} (its RootDeviceName: /dev/xvda on Amazon Linux, "
                      "/dev/sda1 on most others), which Terraform reads from the AMI"),)


def _ami_of(f):
    """The image a data aws_ami looks up by its image-id filter (what compute_groups writes), else None."""
    return next((v[0] for b in f.get("filter") or () if b.get("name") == "image-id" for v in (b.get("values"),)
                 if v), None)


def _ami(f, a):
    """A data aws_ami's root device name: a parameter (Terraform asks the AMI for it, CloudFormation can't)."""
    return Parameter(_root_device_id(_ami_of(f)), "String", None,
                     f"The root device name of AMI {_ami_of(f)} (its RootDeviceName: /dev/xvda on Amazon Linux, "
                     "/dev/sda1 on most others), which Terraform reads from the AMI") \
        if a == "root_device_name" else None


EBS = {"encrypted": "Encrypted", "kms_key_id": "KmsKeyId", "volume_size": "VolumeSize", "volume_type": "VolumeType",
       "iops": "Iops", "throughput": "Throughput", "delete_on_termination": "DeleteOnTermination",
       "snapshot_id": "SnapshotId"}


def _launch_template(f, cx):
    """A launch template: its name, and the rest as its LaunchTemplateData (disks, instance and volume tag
    specifications); its own tags are the template's (launch-template) tag specification (the engine's)."""
    data = obj({k: v for k, v in own(f).items() if k != "name"}, cx, {
        "image_id": "ImageId", "instance_type": "InstanceType", "key_name": "KeyName", "user_data": "UserData",
        "ebs_optimized": "EbsOptimized", "vpc_security_group_ids": "SecurityGroupIds",
        "iam_instance_profile": Nest("IamInstanceProfile", {"name": "Name", "arn": "Arn"}),
        "metadata_options": METADATA_OPTIONS,
        "block_device_mappings": Nest("BlockDeviceMappings", {"device_name": "DeviceName",
                                                              "ebs": Nest("Ebs", EBS)}, True),
        "tag_specifications": Nest("TagSpecifications", {
            "resource_type": "ResourceType", "tags": Custom(lambda v, cx_: {"Tags": tag_list(cx_.value(v))})}, True)})
    return {**({"LaunchTemplateName": cx.value(f["name"])} if f.get("name") else {}), "LaunchTemplateData": data}


def _template_tags(tags):
    return [{"ResourceType": "launch-template", "Tags": tag_list(tags)}]


AUTOSCALING_GROUP = {
    "name": "AutoScalingGroupName", "min_size": "MinSize", "max_size": "MaxSize", "desired_capacity": "DesiredCapacity",
    "vpc_zone_identifier": "VPCZoneIdentifier", "target_group_arns": "TargetGroupARNs",
    "health_check_type": "HealthCheckType", "health_check_grace_period": "HealthCheckGracePeriod",
    "launch_template": Nest("LaunchTemplate", {"id": "LaunchTemplateId", "name": "LaunchTemplateName",
                                               "version": "Version"}),
    # an autoscaling group's tags are its tag blocks, each saying whether instances take it (Terraform's default tags
    # don't reach them, nor CloudFormation's here)
    "tag": Custom(lambda v, cx: {"Tags": [{"Key": cx.value(t["key"]), "Value": cx.value(t["value"]),
                                           "PropagateAtLaunch": cx.value(t["propagate_at_launch"])} for t in v]})}


SG_RULE = {"security_group_id": "GroupId", "cidr_ipv4": "CidrIp", "cidr_ipv6": "CidrIpv6", "description": "Description",
           "from_port": "FromPort", "to_port": "ToPort",
           "ip_protocol": Custom(lambda v, cx: {"IpProtocol": str(cx.value(v))})}


def _load_balancer(f, cx):
    attributes = (("drop_invalid_header_fields", "routing.http.drop_invalid_header_fields.enabled"),
                  ("enable_deletion_protection", "deletion_protection.enabled"),
                  ("idle_timeout", "idle_timeout.timeout_seconds"),
                  ("enable_cross_zone_load_balancing", "load_balancing.cross_zone.enabled"),
                  ("enable_http2", "routing.http2.enabled"))
    names = dict(attributes)
    rest = {k: v for k, v in own(f).items() if k not in names}
    props = obj(rest, cx, {"name": "Name", "load_balancer_type": "Type", "security_groups": "SecurityGroups",
                           "subnets": "Subnets", "ip_address_type": "IpAddressType",
                           "internal": _flag("Scheme", "internal", "internet-facing"),
                           "subnet_mapping": Nest("SubnetMappings", {"subnet_id": "SubnetId",
                                                                     "allocation_id": "AllocationId",
                                                                     "private_ipv4_address": "PrivateIPv4Address"},
                                                  True)})
    found = _attributes((key, cx.value(f[tf])) for tf, key in attributes if tf in f)
    return {**props, **({"LoadBalancerAttributes": found} if found else {})}


def _target_group(f, cx):
    rest = {k: v for k, v in own(f).items() if k not in ("health_check", "stickiness")}
    props = obj(rest, cx, {"name": "Name", "port": "Port", "protocol": "Protocol", "vpc_id": "VpcId",
                           "target_type": "TargetType", "protocol_version": "ProtocolVersion",
                           "deregistration_delay": None})
    health = obj(one(f, "health_check"), cx, {
        "protocol": "HealthCheckProtocol", "path": "HealthCheckPath", "port": _as_string("HealthCheckPort"),
        "interval": "HealthCheckIntervalSeconds", "timeout": "HealthCheckTimeoutSeconds",
        "healthy_threshold": "HealthyThresholdCount", "unhealthy_threshold": "UnhealthyThresholdCount",
        "enabled": "HealthCheckEnabled", "matcher": Custom(lambda v, c: {"Matcher": {"HttpCode": c.value(v)}})},
        f"{cx.where}.health_check")
    sticky = one(f, "stickiness")
    unknown = sorted(set(sticky) - {"type", "enabled", "cookie_duration", "cookie_name"})
    if unknown:
        raise SystemExit(f"{cx.where}.stickiness: no CloudFormation form for {', '.join(unknown)}")
    pairs = ((("stickiness.enabled", sticky.get("enabled", True)), ("stickiness.type", sticky["type"]),
              *((("stickiness.lb_cookie.duration_seconds", sticky["cookie_duration"]),)
                if "cookie_duration" in sticky and sticky["type"] == "lb_cookie" else ()),
              *((("stickiness.app_cookie.cookie_name", sticky["cookie_name"]),) if "cookie_name" in sticky else ()))
             if sticky else ())
    delay = ((("deregistration_delay.timeout_seconds", f["deregistration_delay"]),)
             if "deregistration_delay" in f else ())
    attributes = _attributes((k, cx.value(v)) for k, v in (*pairs, *delay))
    return {**props, **health, **({"TargetGroupAttributes": attributes} if attributes else {})}


def _listener(f, cx):
    action = {"type": "Type", "target_group_arn": "TargetGroupArn", "order": "Order",
              "redirect": Nest("RedirectConfig", {"port": "Port", "protocol": "Protocol",
                                                  "status_code": "StatusCode", "host": "Host", "path": "Path",
                                                  "query": "Query"}),
              "fixed_response": Nest("FixedResponseConfig", {"content_type": "ContentType",
                                                             "message_body": "MessageBody",
                                                             "status_code": "StatusCode"})}
    return obj(own(f), cx, {"load_balancer_arn": "LoadBalancerArn", "port": "Port", "protocol": "Protocol",
                            "ssl_policy": "SslPolicy", "alpn_policy": Custom(lambda v, c: {"AlpnPolicy": [c.value(v)]}),
                            "certificate_arn": Custom(lambda v, c: {"Certificates": [{"CertificateArn": c.value(v)}]}),
                            "default_action": Nest("DefaultActions", action, True)})


def _sets(v, cx, inner):
    """A Network Firewall rule group's IP or port sets: {key: {Definition: [...]}}."""
    return {b["key"]: {"Definition": cx.value(b[inner][0]["definition"])} for b in v}


def _endpoint_service_permissions(lid, f, cx):
    principals = f.get("allowed_principals")
    return (("Permissions", "AWS::EC2::VPCEndpointServicePermissions",
             {"ServiceId": ref(lid), "AllowedPrincipals": cx.value(principals)}),) if principals else ()


# ------------------------------------------------------------------ S3 (the bucket's settings merge into it)

LIFECYCLE_RULE = {
    "id": "Id", "status": "Status",
    "filter": Custom(lambda v, cx: {"Prefix": cx.value(v[0]["prefix"])} if v and "prefix" in v[0] else
                     _empty_filter(v, cx)),
    "transition": Nest("Transitions", {"days": "TransitionInDays", "storage_class": "StorageClass",
                                        "date": "TransitionDate"}, True),
    "expiration": Custom(lambda v, cx: obj(v[0], cx, {"days": "ExpirationInDays", "date": "ExpirationDate",
                                                      "expired_object_delete_marker": "ExpiredObjectDeleteMarker"})),
    "noncurrent_version_expiration": Nest("NoncurrentVersionExpiration", {
        "noncurrent_days": "NoncurrentDays", "newer_noncurrent_versions": "NewerNoncurrentVersions"}),
    "noncurrent_version_transition": Nest("NoncurrentVersionTransitions", {
        "noncurrent_days": "TransitionInDays", "storage_class": "StorageClass"}, True),
    "abort_incomplete_multipart_upload": Nest("AbortIncompleteMultipartUpload", {
        "days_after_initiation": "DaysAfterInitiation"})}


def _empty_filter(v, cx):
    if v and v[0]:
        raise SystemExit(f"{cx.where}: no CloudFormation form for filter {', '.join(v[0])}")
    return {}


REPLICATION_RULE = {
    "id": "Id", "status": "Status", "priority": "Priority",
    "filter": Custom(lambda v, cx: {"Filter": {"Prefix": cx.value(v[0].get("prefix", ""))}}),
    "delete_marker_replication": Nest("DeleteMarkerReplication", {"status": "Status"}),
    "source_selection_criteria": Nest("SourceSelectionCriteria", {
        "sse_kms_encrypted_objects": Nest("SseKmsEncryptedObjects", {"status": "Status"}),
        "replica_modifications": Nest("ReplicaModifications", {"status": "Status"})}),
    "destination": Nest("Destination", {"bucket": "Bucket", "storage_class": "StorageClass", "account": "Account",
                                        "encryption_configuration": Nest("EncryptionConfiguration", {
                                            "replica_kms_key_id": "ReplicaKmsKeyID"})})}

SSE_RULE = {"bucket_key_enabled": "BucketKeyEnabled",
            "apply_server_side_encryption_by_default": Nest("ServerSideEncryptionByDefault", {
                "sse_algorithm": "SSEAlgorithm", "kms_master_key_id": "KMSMasterKeyID"})}


def _bucket_setting(name, spec, wrap=lambda o: o):
    """Merge.into for one of a bucket's settings resources: its attributes (bucket aside) as the property."""
    def into(props, f, cx):
        return {**props, name: wrap(obj({k: v for k, v in own(f).items() if k != "bucket"}, cx, spec))}
    return into


def _object_lock(o):
    return {"ObjectLockEnabled": "Enabled", **o}


S3_BUCKET_REFS = {"id": "Ref", "bucket": "Ref", "arn": "Arn", "bucket_domain_name": "DomainName",
                  "bucket_regional_domain_name": "RegionalDomainName"}

# ------------------------------------------------------------------ WAF


WAF_LISTS = {"rule": "Rules", "text_transformation": "TextTransformations",
             "managed_rule_group_configs": "ManagedRuleGroupConfigs", "rule_action_override": "RuleActionOverrides",
             "excluded_rule": "ExcludedRules", "custom_key": "CustomKeys"}
WAF_NAMES = {"aws_managed_rules_bot_control_rule_set": "AWSManagedRulesBotControlRuleSet",
             "aws_managed_rules_acfp_rule_set": "AWSManagedRulesACFPRuleSet",
             "aws_managed_rules_atp_rule_set": "AWSManagedRulesATPRuleSet",
             "cloudwatch_metrics_enabled": "CloudWatchMetricsEnabled",
             "ip_set_reference_statement": "IPSetReferenceStatement", "forwarded_ip_config": "ForwardedIPConfig",
             "country_codes": "CountryCodes", "evaluation_window_sec": "EvaluationWindowSec"}


def _waf(f, cx, parent=""):
    """A WAFv2 web ACL's nested blocks as CloudFormation's (their names PascalCase, a few spelled AWS's way; statement
    a list under or/and statements, one elsewhere)."""

    def name(k):
        if k == "statement":
            return ("Statements", True) if parent in ("or_statement", "and_statement") else ("Statement", False)
        if k in WAF_LISTS:
            return WAF_LISTS[k], True
        return WAF_NAMES.get(k, pascal(k)), False

    def value(k, v):
        if isinstance(v, tuple) and all(isinstance(x, dict) for x in v) and v:
            items = [_waf(x, cx, k) for x in v]
            return items if name(k)[1] else items[0]
        return cx.value(v)
    return {name(k)[0]: value(k, v) for k, v in f.items()}


def _web_acl(f, cx):
    rest = own(f)
    unknown = sorted(set(rest) - {"name", "scope", "description", "default_action", "rule", "visibility_config",
                                  "custom_response_body", "token_domains"})
    if unknown:
        raise SystemExit(f"{cx.where}: no CloudFormation form for {', '.join(unknown)}")
    return _waf(rest, cx)


# ------------------------------------------------------------------ CDN

# The Route 53 hosted zone of every CloudFront distribution (an alias record's zone_id), AWS's fixed one.
CLOUDFRONT_ZONE = "Z2FDTNDATAQYW2"
CF_ORIGIN = {"domain_name": "DomainName", "origin_id": "Id", "origin_path": "OriginPath",
             "custom_origin_config": Nest("CustomOriginConfig", {
                 "http_port": "HTTPPort", "https_port": "HTTPSPort", "origin_protocol_policy": "OriginProtocolPolicy",
                 "origin_ssl_protocols": "OriginSSLProtocols", "origin_read_timeout": "OriginReadTimeout",
                 "origin_keepalive_timeout": "OriginKeepaliveTimeout"})}
CF_BEHAVIOR = {"target_origin_id": "TargetOriginId", "viewer_protocol_policy": "ViewerProtocolPolicy",
               "allowed_methods": "AllowedMethods", "cached_methods": "CachedMethods", "compress": "Compress",
               "cache_policy_id": "CachePolicyId", "origin_request_policy_id": "OriginRequestPolicyId",
               "response_headers_policy_id": "ResponseHeadersPolicyId"}


def _distribution(f, cx):
    """A CloudFront distribution: its settings under DistributionConfig (its tags the engine's)."""
    return {"DistributionConfig": obj(own(f), cx, {
        "enabled": "Enabled", "comment": "Comment", "aliases": "Aliases", "http_version": "HttpVersion",
        "web_acl_id": "WebACLId", "price_class": "PriceClass", "is_ipv6_enabled": "IPV6Enabled",
        "default_root_object": "DefaultRootObject", "origin": Nest("Origins", CF_ORIGIN, True),
        "default_cache_behavior": Nest("DefaultCacheBehavior", CF_BEHAVIOR),
        "restrictions": Nest("Restrictions", {"geo_restriction": Nest("GeoRestriction", {
            "restriction_type": "RestrictionType", "locations": "Locations"})}),
        "viewer_certificate": Nest("ViewerCertificate", {
            "acm_certificate_arn": "AcmCertificateArn", "ssl_support_method": "SslSupportMethod",
            "minimum_protocol_version": "MinimumProtocolVersion",
            "cloudfront_default_certificate": "CloudFrontDefaultCertificate"})})}


# CloudFront's managed policies by name -> their IDs (fixed by AWS, the same in every account).
MANAGED_CACHE_POLICIES = {"Managed-CachingDisabled": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"}
MANAGED_ORIGIN_REQUEST_POLICIES = {"Managed-AllViewer": "216adef6-5c7f-47e4-b989-5492eafa07d3"}


def _managed_policy(known, kind):
    """The data table's answer for a CloudFront managed policy's id: the ID AWS fixes for the name, else a
    parameter."""
    return lambda f, a: (known.get(f.get("name")) or Parameter("", "String", None, f"The ID of CloudFront {kind} "
                                                                                    f"{f.get('name')}")
                         if a == "id" else None)


# ------------------------------------------------------------------ interconnects

def _vpn_attachment(lid, f, cx):
    """A VPN gateway's attachment to the VPC Terraform names in vpc_id (its own resource natively)."""
    return (("Attachment", "AWS::EC2::VPCGatewayAttachment", {"VpcId": cx.value(f["vpc_id"]),
                                                              "VpnGatewayId": ref(lid)}),) if "vpc_id" in f else ()


# ------------------------------------------------------------------ DNS

RECORD_SET = {"zone_id": "HostedZoneId", "name": "Name", "type": "Type", "ttl": _as_string("TTL"),
              "records": "ResourceRecords", "set_identifier": "SetIdentifier", "health_check_id": "HealthCheckId",
              "alias": Nest("AliasTarget", {"name": "DNSName", "zone_id": "HostedZoneId",
                                            "evaluate_target_health": "EvaluateTargetHealth"}),
              "weighted_routing_policy": Custom(lambda v, cx: {"Weight": cx.value(v[0]["weight"])}),
              "failover_routing_policy": Custom(lambda v, cx: {"Failover": cx.value(v[0]["type"])}),
              "allow_overwrite": None}


def _record_set(f, cx):
    """A Route 53 record; TXT and SPF values quoted as Route 53 takes them (Terraform's provider adds the quotes
    around each value, its long values' inner "" splits included; CloudFormation passes values as given)."""
    props = obj(own(f), cx, RECORD_SET)
    if f.get("type") not in ("TXT", "SPF") or "ResourceRecords" not in props:
        return props
    if not isinstance(props["ResourceRecords"], list):
        raise SystemExit(f"{cx.where}: no CloudFormation form for TXT values computed as a whole list")
    return {**props, "ResourceRecords": [concat('"', v, '"') for v in props["ResourceRecords"]]}


# ------------------------------------------------------------------ databases and DNS health

DB_PARAMETERS = Custom(lambda v, cx: {"Parameters": {b["name"]: cx.value(b["value"]) for b in v}})
RDS_CLUSTER = {
    "cluster_identifier": "DBClusterIdentifier", "engine": "Engine", "engine_version": "EngineVersion",
    "engine_mode": "EngineMode", "db_subnet_group_name": "DBSubnetGroupName",
    "vpc_security_group_ids": "VpcSecurityGroupIds", "db_cluster_parameter_group_name": "DBClusterParameterGroupName",
    "master_username": "MasterUsername", "manage_master_user_password": "ManageMasterUserPassword",
    "master_user_secret_kms_key_id": Custom(lambda v, cx: {"MasterUserSecret": {"KmsKeyId": cx.value(v)}}),
    "port": "Port", "storage_encrypted": "StorageEncrypted", "kms_key_id": "KmsKeyId",
    "backup_retention_period": "BackupRetentionPeriod", "preferred_backup_window": "PreferredBackupWindow",
    "preferred_maintenance_window": "PreferredMaintenanceWindow", "deletion_protection": "DeletionProtection",
    "copy_tags_to_snapshot": "CopyTagsToSnapshot", "database_name": "DatabaseName",
    "enabled_cloudwatch_logs_exports": "EnableCloudwatchLogsExports",
    "iam_database_authentication_enabled": "EnableIAMDatabaseAuthentication"}
# An Aurora member instance: its engine version is the cluster's (CloudFormation's DBInstance takes none for one)
RDS_CLUSTER_INSTANCE = {
    "identifier": "DBInstanceIdentifier", "cluster_identifier": "DBClusterIdentifier",
    "instance_class": "DBInstanceClass", "engine": "Engine", "engine_version": None,
    "availability_zone": "AvailabilityZone", "publicly_accessible": "PubliclyAccessible",
    "db_parameter_group_name": "DBParameterGroupName", "auto_minor_version_upgrade": "AutoMinorVersionUpgrade",
    "promotion_tier": "PromotionTier", "monitoring_interval": "MonitoringInterval",
    "monitoring_role_arn": "MonitoringRoleArn", "performance_insights_enabled": "EnablePerformanceInsights"}
HEALTH_CHECK = {"type": "Type", "ip_address": "IPAddress", "port": "Port", "fqdn": "FullyQualifiedDomainName",
                "resource_path": "ResourcePath", "failure_threshold": "FailureThreshold",
                "request_interval": "RequestInterval", "search_string": "SearchString",
                "measure_latency": "MeasureLatency", "invert_healthcheck": "Inverted", "enable_sni": "EnableSNI",
                "regions": "Regions"}


# ------------------------------------------------------------------ security services

# A GuardDuty filter criterion's conditions, Terraform's names to CloudFormation's
GUARDDUTY_CONDITIONS = {"equals": "Equals", "not_equals": "NotEquals", "greater_than": "GreaterThan",
                        "greater_than_or_equal": "GreaterThanOrEqual", "less_than": "LessThan",
                        "less_than_or_equal": "LessThanOrEqual"}


def _finding_criteria(v, cx):
    """A GuardDuty filter's finding_criteria: {Criterion: {field: {condition: value}}}."""
    def criterion(blocks, c):
        return {"Criterion": {c.value(b["field"]): obj({k: x for k, x in b.items() if k != "field"}, c,
                                                        GUARDDUTY_CONDITIONS, f"{c.where}.finding_criteria.criterion")
                              for b in blocks}}
    return {"FindingCriteria": obj(v[0], cx, {"criterion": Custom(criterion)}, f"{cx.where}.finding_criteria")}


def _automatic_response(props, f, cx):
    """Shield Advanced's automatic application layer response, on the resource's protection."""
    action = obj(own(f), cx, {"resource_arn": None, "action": Custom(lambda v, c: {"Action": {
        {"BLOCK": "Block", "COUNT": "Count"}[c.value(v)]: {}}})})
    return {**props, "ApplicationLayerAutomaticResponseConfiguration": {**action, "Status": "ENABLED"}}


# ------------------------------------------------------------------ the table

TYPES = {
    # backup
    "aws_backup_vault": Native("AWS::Backup::BackupVault", {"name": "BackupVaultName",
                                                             "kms_key_arn": "EncryptionKeyArn", "force_destroy": None},
                               {"id": "Ref", "name": "Ref", "arn": "BackupVaultArn"}, "BackupVaultName", "map",
                               tags_key="BackupVaultTags"),
    "aws_backup_vault_lock_configuration": Native(None, merge=Merge("backup_vault_name", _set("LockConfiguration", {
        "backup_vault_name": None, "min_retention_days": "MinRetentionDays", "max_retention_days": "MaxRetentionDays",
        "changeable_for_days": "ChangeableForDays"}))),
    "aws_backup_plan": Native("AWS::Backup::BackupPlan", _backup_plan, {"id": "Ref", "arn": "BackupPlanArn"},
                              "BackupPlanId", "map", tags_key="BackupPlanTags"),
    "aws_backup_selection": Native("AWS::Backup::BackupSelection", _backup_selection, {"id": "SelectionId"}),
    # billing
    "aws_budgets_budget": Native("AWS::Budgets::Budget", _budget, {}, None, "list", tags_key="ResourceTags"),
    # audit and logs
    "aws_cloudtrail": Native("AWS::CloudTrail::Trail", _defaults({
        "name": "TrailName", "s3_bucket_name": "S3BucketName", "s3_key_prefix": "S3KeyPrefix",
        "is_multi_region_trail": "IsMultiRegionTrail", "include_global_service_events": "IncludeGlobalServiceEvents",
        "enable_log_file_validation": "EnableLogFileValidation", "is_organization_trail": "IsOrganizationTrail",
        "kms_key_id": "KMSKeyId", "cloud_watch_logs_group_arn": "CloudWatchLogsLogGroupArn",
        "cloud_watch_logs_role_arn": "CloudWatchLogsRoleArn", "sns_topic_name": "SnsTopicName",
        "enable_logging": "IsLogging",
        "advanced_event_selector": Nest("AdvancedEventSelectors", {"name": "Name", "field_selector": Nest(
            "FieldSelectors", {"field": "Field", "equals": "Equals", "starts_with": "StartsWith",
                               "ends_with": "EndsWith", "not_equals": "NotEquals",
                               "not_starts_with": "NotStartsWith", "not_ends_with": "NotEndsWith"}, True)}, True)},
        IsLogging=True), {"arn": "Arn", "id": "Ref", "name": "Ref"}, "TrailName", "list"),
    "aws_config_configuration_aggregator": Native("AWS::Config::ConfigurationAggregator", {
        "name": "ConfigurationAggregatorName",
        "organization_aggregation_source": Nest("OrganizationAggregationSource", {
            "all_regions": "AllAwsRegions", "regions": "AwsRegions", "role_arn": "RoleArn"})},
        {"id": "Ref", "name": "Ref", "arn": "ConfigurationAggregatorArn"}, "ConfigurationAggregatorName", "list"),
    "aws_cloudwatch_log_group": Native("AWS::Logs::LogGroup", {
        "name": "LogGroupName", "retention_in_days": "RetentionInDays", "kms_key_id": "KmsKeyId",
        "log_group_class": "LogGroupClass"},
        {"name": "Ref", "id": "Ref",
         "arn": _arn_sub("arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:{id}")},
        "LogGroupName", "list"),
    # a log group forwarded on to a SIEM (siem_forwarding.py): the subscription and the Firehose stream
    "aws_cloudwatch_log_subscription_filter": Native("AWS::Logs::SubscriptionFilter", {
        "name": "FilterName", "log_group_name": "LogGroupName", "filter_pattern": "FilterPattern",
        "destination_arn": "DestinationArn", "role_arn": "RoleArn"}, {"id": "Ref"}, "FilterName"),
    "aws_kinesis_firehose_delivery_stream": Native("AWS::KinesisFirehose::DeliveryStream", {
        "name": "DeliveryStreamName", "destination": Custom(lambda v, c: {"DeliveryStreamType": "DirectPut"}),
        "splunk_configuration": Custom(_splunk_destination),
        "http_endpoint_configuration": Custom(_http_destination)},
        {"id": "Ref", "name": "Ref", "arn": "Arn"}, "DeliveryStreamName", "list"),
    "aws_cloudwatch_metric_alarm": Native("AWS::CloudWatch::Alarm", {
        "alarm_name": "AlarmName", "alarm_description": "AlarmDescription", "namespace": "Namespace",
        "metric_name": "MetricName", "statistic": "Statistic", "extended_statistic": "ExtendedStatistic",
        "period": "Period", "evaluation_periods": "EvaluationPeriods", "datapoints_to_alarm": "DatapointsToAlarm",
        "comparison_operator": "ComparisonOperator", "threshold": "Threshold", "unit": "Unit",
        "alarm_actions": "AlarmActions", "ok_actions": "OKActions",
        "insufficient_data_actions": "InsufficientDataActions", "treat_missing_data": "TreatMissingData",
        "actions_enabled": "ActionsEnabled",
        "dimensions": Custom(lambda v, cx: {"Dimensions": [{"Name": k, "Value": x} for k, x in cx.value(v).items()]})},
        {"arn": "Arn", "id": "Ref", "alarm_name": "Ref"}, "AlarmName", "list"),
    "aws_cloudwatch_event_rule": Native("AWS::Events::Rule", {
        "name": "Name", "description": "Description", "event_pattern": "EventPattern",
        "schedule_expression": "ScheduleExpression", "event_bus_name": "EventBusName", "role_arn": "RoleArn",
        "state": "State", "is_enabled": _flag("State", "ENABLED", "DISABLED")}, {"arn": "Arn"}, None, "list"),
    "aws_cloudwatch_event_target": Native(None, merge=Merge("rule", lambda props, f, cx: {
        **props, "Targets": [*props.get("Targets", []), {
            "Id": cx.value(f.get("target_id", f"T{len(props.get('Targets', []))}")),
            **obj({k: v for k, v in own(f).items() if k not in ("rule", "target_id", "event_bus_name")}, cx, {
                "arn": "Arn", "role_arn": "RoleArn", "input": "Input", "input_path": "InputPath"})}]})),
    # config
    "aws_config_configuration_recorder": Native("AWS::Config::ConfigurationRecorder", {
        "name": "Name", "role_arn": "RoleARN",
        "recording_group": Nest("RecordingGroup", {"all_supported": "AllSupported",
                                                   "include_global_resource_types": "IncludeGlobalResourceTypes",
                                                   "resource_types": "ResourceTypes"})},
        {"name": "Ref", "id": "Ref"}, "Name"),
    # CloudFormation starts a recorder once its delivery channel exists (research 2581): is_enabled = true is the native
    # default; a stopped recorder has no native form
    "aws_config_configuration_recorder_status": Native(None, merge=Merge("name", lambda props, f, cx: (
        props if f.get("is_enabled") is True and set(own(f)) <= {"name", "is_enabled"} else _refuse(
            cx, "a stopped recorder (is_enabled = false) has no CloudFormation form")), ordering=False)),
    "aws_config_delivery_channel": Native("AWS::Config::DeliveryChannel", {
        "name": "Name", "s3_bucket_name": "S3BucketName", "s3_key_prefix": "S3KeyPrefix",
        "sns_topic_arn": "SnsTopicARN", "s3_kms_key_arn": "S3KmsKeyArn"}, {"name": "Ref", "id": "Ref"}, "Name"),
    # databases
    "aws_db_instance": Native("AWS::RDS::DBInstance", {
        "identifier": "DBInstanceIdentifier", "engine": "Engine", "engine_version": "EngineVersion",
        "instance_class": "DBInstanceClass", "allocated_storage": _as_string("AllocatedStorage"),
        "max_allocated_storage": "MaxAllocatedStorage", "storage_type": "StorageType", "iops": "Iops",
        "db_subnet_group_name": "DBSubnetGroupName", "vpc_security_group_ids": "VPCSecurityGroups",
        "parameter_group_name": "DBParameterGroupName", "username": "MasterUsername", "multi_az": "MultiAZ",
        "availability_zone": "AvailabilityZone", "publicly_accessible": "PubliclyAccessible",
        "manage_master_user_password": "ManageMasterUserPassword",
        "master_user_secret_kms_key_id": Custom(lambda v, cx: {"MasterUserSecret": {"KmsKeyId": cx.value(v)}}),
        "port": _as_string("Port"), "storage_encrypted": "StorageEncrypted", "kms_key_id": "KmsKeyId",
        "backup_retention_period": "BackupRetentionPeriod", "backup_window": "PreferredBackupWindow",
        "maintenance_window": "PreferredMaintenanceWindow", "deletion_protection": "DeletionProtection",
        "copy_tags_to_snapshot": "CopyTagsToSnapshot", "db_name": "DBName",
        "enabled_cloudwatch_logs_exports": "EnableCloudwatchLogsExports",
        "iam_database_authentication_enabled": "EnableIAMDatabaseAuthentication",
        "ca_cert_identifier": "CACertificateIdentifier", "auto_minor_version_upgrade": "AutoMinorVersionUpgrade",
        "monitoring_interval": "MonitoringInterval", "monitoring_role_arn": "MonitoringRoleArn",
        "performance_insights_enabled": "EnablePerformanceInsights",
        "performance_insights_kms_key_id": "PerformanceInsightsKMSKeyId",
        "delete_automated_backups": "DeleteAutomatedBackups"},
        {"id": "Ref", "identifier": "Ref", "arn": "DBInstanceArn", "address": "Endpoint.Address",
         "port": "Endpoint.Port", "resource_id": "DbiResourceId"}, "DBInstanceIdentifier", "list"),
    "aws_db_instance_automated_backups_replication": Native(None, merge=Merge(
        "source_db_instance_arn", lambda props, f, cx: {**props, **obj(own(f), cx, {
            "source_db_instance_arn": None,
            "kms_key_id": "AutomaticBackupReplicationKmsKeyId",
            "retention_period": "AutomaticBackupReplicationRetentionPeriod"}),
            "AutomaticBackupReplicationRegion": _copy_region(f, cx)})),
    "aws_db_parameter_group": Native("AWS::RDS::DBParameterGroup", _defaults({
        "name": "DBParameterGroupName", "family": "Family", "description": "Description", "parameter": DB_PARAMETERS},
        Description=TERRAFORM_DESCRIPTION),
        {"id": "Ref", "name": "Ref", "arn": "DBParameterGroupArn"}, "DBParameterGroupName", "list"),
    "aws_rds_cluster": Native("AWS::RDS::DBCluster", RDS_CLUSTER, {
        "id": "Ref", "cluster_identifier": "Ref", "arn": "DBClusterArn", "endpoint": "Endpoint.Address",
        "reader_endpoint": "ReadEndpoint.Address", "port": "Endpoint.Port",
        "cluster_resource_id": "DBClusterResourceId",
        "engine": Attribute("engine"), "engine_version": Attribute("engine_version")},
        "DBClusterIdentifier", "list"),
    "aws_rds_cluster_instance": Native("AWS::RDS::DBInstance", RDS_CLUSTER_INSTANCE, {
        "id": "Ref", "identifier": "Ref", "arn": "DBInstanceArn", "endpoint": "Endpoint.Address"},
        "DBInstanceIdentifier", "list"),
    "aws_rds_cluster_parameter_group": Native("AWS::RDS::DBClusterParameterGroup", _defaults({
        "name": "DBClusterParameterGroupName", "family": "Family", "description": "Description",
        "parameter": DB_PARAMETERS}, Description=TERRAFORM_DESCRIPTION),
        {"id": "Ref", "name": "Ref"}, "DBClusterParameterGroupName", "list"),
    "aws_db_subnet_group": Native("AWS::RDS::DBSubnetGroup", _defaults({
        "name": "DBSubnetGroupName", "description": "DBSubnetGroupDescription", "subnet_ids": "SubnetIds"},
        DBSubnetGroupDescription=TERRAFORM_DESCRIPTION),
        {"id": "Ref", "name": "Ref", "arn": "DBSubnetGroupArn"}, "DBSubnetGroupName", "list"),
    # managed identity: Cognito user pools (cognito.py; property names, Ref and attributes as cfn-lint's schemas have
    # them, the same in the GovCloud regions)
    "aws_cognito_user_pool": Native("AWS::Cognito::UserPool", {
        "name": "UserPoolName", "deletion_protection": "DeletionProtection", "mfa_configuration": "MfaConfiguration",
        "software_token_mfa_configuration": Custom(lambda v, cx: {"EnabledMfas": ["SOFTWARE_TOKEN_MFA"]} if any(
            cx.value(b.get("enabled")) is True for b in v) else {})},
        {"id": "Ref", "arn": "Arn"}, "UserPoolId", "map", tags_key="UserPoolTags"),
    "aws_cognito_user_pool_domain": Native("AWS::Cognito::UserPoolDomain", {
        "domain": "Domain", "user_pool_id": "UserPoolId",
        "certificate_arn": Custom(lambda v, cx: {"CustomDomainConfig": {"CertificateArn": cx.value(v)}})}, {}),
    "aws_cognito_user_pool_client": Native("AWS::Cognito::UserPoolClient", {
        "name": "ClientName", "user_pool_id": "UserPoolId", "generate_secret": "GenerateSecret",
        "allowed_oauth_flows": "AllowedOAuthFlows", "allowed_oauth_flows_user_pool_client":
        "AllowedOAuthFlowsUserPoolClient", "allowed_oauth_scopes": "AllowedOAuthScopes",
        "callback_urls": "CallbackURLs", "logout_urls": "LogoutURLs",
        "supported_identity_providers": "SupportedIdentityProviders",
        "enable_token_revocation": "EnableTokenRevocation",
        "prevent_user_existence_errors": "PreventUserExistenceErrors"}, {}),
    "aws_cognito_resource_server": Native("AWS::Cognito::UserPoolResourceServer", {
        "identifier": "Identifier", "name": "Name", "user_pool_id": "UserPoolId",
        "scope": Nest("Scopes", {"scope_name": "ScopeName", "scope_description": "ScopeDescription"}, True)}, {}),
    "aws_cognito_identity_provider": Native("AWS::Cognito::UserPoolIdentityProvider", {
        "user_pool_id": "UserPoolId", "provider_name": "ProviderName", "provider_type": "ProviderType",
        "provider_details": "ProviderDetails", "attribute_mapping": "AttributeMapping"}, {}),
    # volumes
    "aws_ebs_volume": Native("AWS::EC2::Volume", {
        "availability_zone": "AvailabilityZone", "size": "Size", "type": "VolumeType", "iops": "Iops",
        "throughput": "Throughput", "encrypted": "Encrypted", "kms_key_id": "KmsKeyId", "snapshot_id": "SnapshotId",
        "multi_attach_enabled": "MultiAttachEnabled"}, {"id": "Ref"}, "VolumeId", "list"),
    "aws_volume_attachment": Native("AWS::EC2::VolumeAttachment", {
        "device_name": "Device", "volume_id": "VolumeId", "instance_id": "InstanceId"}, {}),
    "aws_dlm_lifecycle_policy": Native("AWS::DLM::LifecyclePolicy", {
        "description": "Description", "execution_role_arn": "ExecutionRoleArn", "state": "State",
        "policy_details": Nest("PolicyDetails", {
            "resource_types": "ResourceTypes", "policy_type": "PolicyType",
            "target_tags": Custom(lambda v, cx: {"TargetTags": tag_list(cx.value(v))}),
            "schedule": Nest("Schedules", {
                "name": "Name", "copy_tags": "CopyTags",
                "tags_to_add": Custom(lambda v, cx: {"TagsToAdd": tag_list(cx.value(v))}),
                "create_rule": Nest("CreateRule", {"interval": "Interval", "interval_unit": "IntervalUnit",
                                                   "times": "Times", "cron_expression": "CronExpression",
                                                   "location": "Location"}),
                "retain_rule": Nest("RetainRule", {"count": "Count", "interval": "Interval",
                                                   "interval_unit": "IntervalUnit"}),
                "cross_region_copy_rule": Nest("CrossRegionCopyRules", {
                    "target": "Target", "encrypted": "Encrypted", "cmk_arn": "CmkArn", "copy_tags": "CopyTags",
                    "retain_rule": Nest("RetainRule", {"interval": "Interval", "interval_unit": "IntervalUnit"})},
                    True)}, True)})},
        {"id": "Ref", "arn": "Arn"}, "PolicyId", "list"),
    # network
    "aws_flow_log": Native("AWS::EC2::FlowLog", {
        "vpc_id": Custom(lambda v, cx: {"ResourceId": cx.value(v), "ResourceType": "VPC"}),
        "subnet_id": Custom(lambda v, cx: {"ResourceId": cx.value(v), "ResourceType": "Subnet"}),
        "traffic_type": "TrafficType", "log_destination_type": "LogDestinationType",
        "log_destination": "LogDestination", "iam_role_arn": "DeliverLogsPermissionArn",
        "log_format": "LogFormat", "max_aggregation_interval": "MaxAggregationInterval"},
        {"id": "Ref"}, "Id", "list"),
    "aws_nat_gateway": Native("AWS::EC2::NatGateway", {
        "allocation_id": "AllocationId", "connectivity_type": "ConnectivityType", "subnet_id": "SubnetId",
        "private_ip": "PrivateIpAddress", "secondary_allocation_ids": "SecondaryAllocationIds"},
        {"id": "Ref"}, "NatGatewayId", "list"),
    # an adopted ACL stays Terraform: CloudFormation can't import its entries by what Terraform holds
    "aws_network_acl": Native("AWS::EC2::NetworkAcl", {"vpc_id": "VpcId", "subnet_ids": None, "ingress": None,
                                                       "egress": None},
                              {"id": "Ref"}, None, "list", expand=_acl_entries),
    "aws_route_table": Native("AWS::EC2::RouteTable", {"vpc_id": "VpcId", "route": None}, {"id": "Ref"},
                              "RouteTableId", "list", expand=_routes, adoptable=_routes_adoptable),
    # an adopted association stays Terraform: Terraform imports it as subnet/route table, CloudFormation by its id
    "aws_route_table_association": Native("AWS::EC2::SubnetRouteTableAssociation", {
        "subnet_id": "SubnetId", "route_table_id": "RouteTableId"}, {"id": "Ref"}),
    "aws_security_group": Native("AWS::EC2::SecurityGroup", {
        "name": "GroupName", "description": "GroupDescription", "vpc_id": "VpcId"},
        {"id": "GroupId", "arn": _arn_sub("arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:"
                                          "security-group/{id}")}, "Id", "list", finish=_no_default_egress),
    "aws_vpc_security_group_ingress_rule": Native("AWS::EC2::SecurityGroupIngress", {
        **SG_RULE, "referenced_security_group_id": "SourceSecurityGroupId",
        "prefix_list_id": "SourcePrefixListId"}, {"id": "Ref"}),
    # inline on its group: CloudFormation then removes the group's allow-all egress (Terraform's state of it); a
    # cycle of groups' egress rules would be a circular dependency (cfn-lint's E3004 catches it)
    "aws_vpc_security_group_egress_rule": Native(None, merge=Merge("security_group_id", _append(
        "SecurityGroupEgress", {**SG_RULE, "security_group_id": None,
                                "referenced_security_group_id": "DestinationSecurityGroupId",
                                "prefix_list_id": "DestinationPrefixListId"}))),
    "aws_vpc_endpoint": Native("AWS::EC2::VPCEndpoint", {
        "vpc_id": "VpcId", "service_name": "ServiceName", "vpc_endpoint_type": "VpcEndpointType",
        "subnet_ids": "SubnetIds", "security_group_ids": "SecurityGroupIds", "route_table_ids": "RouteTableIds",
        "private_dns_enabled": "PrivateDnsEnabled", "policy": "PolicyDocument",
        "ip_address_type": "IpAddressType"}, {"id": "Ref"}, "Id", "list"),
    "aws_vpc_endpoint_service": Native("AWS::EC2::VPCEndpointService", {
        "acceptance_required": "AcceptanceRequired", "network_load_balancer_arns": "NetworkLoadBalancerArns",
        "gateway_load_balancer_arns": "GatewayLoadBalancerArns", "allowed_principals": None,
        "private_dns_name": "PrivateDnsName", "supported_ip_address_types": "SupportedIpAddressTypes"},
        {"id": "Ref", "service_name": _arn_sub("com.amazonaws.vpce.${AWS::Region}.{id}")}, "ServiceId", "list",
        expand=_endpoint_service_permissions),
    "aws_networkfirewall_rule_group": Native("AWS::NetworkFirewall::RuleGroup", {
        "name": "RuleGroupName", "type": "Type", "capacity": "Capacity", "description": "Description",
        "rule_group": Nest("RuleGroup", {
            "rule_variables": Nest("RuleVariables", {
                "ip_sets": Custom(lambda v, cx: {"IPSets": _sets(v, cx, "ip_set")}),
                "port_sets": Custom(lambda v, cx: {"PortSets": _sets(v, cx, "port_set")})}),
            "rules_source": Nest("RulesSource", {
                "rules_string": "RulesString",
                "rules_source_list": Nest("RulesSourceList", {"generated_rules_type": "GeneratedRulesType",
                                                              "target_types": "TargetTypes",
                                                              "targets": "Targets"})}),
            "stateful_rule_options": Nest("StatefulRuleOptions", {"rule_order": "RuleOrder"})})},
        {"arn": "Ref", "id": "Ref"}, "RuleGroupArn", "list"),
    "aws_route53_record": Native("AWS::Route53::RecordSet", _record_set, {"fqdn": "Ref", "name": "Ref"}),
    "aws_route53_resolver_rule": Native("AWS::Route53Resolver::ResolverRule", {
        "name": "Name", "domain_name": "DomainName", "rule_type": "RuleType",
        "resolver_endpoint_id": "ResolverEndpointId",
        "target_ip": Nest("TargetIps", {"ip": "Ip", "port": _as_string("Port"), "protocol": "Protocol"}, True)},
        {"id": "Ref", "arn": "Arn"}, "ResolverRuleId", "list"),
    "aws_route53_resolver_rule_association": Native("AWS::Route53Resolver::ResolverRuleAssociation", {
        "resolver_rule_id": "ResolverRuleId", "vpc_id": "VPCId", "name": "Name"}, {"id": "Ref"},
        "ResolverRuleAssociationId"),
    "aws_route53_health_check": Native("AWS::Route53::HealthCheck",
                                       lambda f, cx: {"HealthCheckConfig": obj(own(f), cx, HEALTH_CHECK)},
                                       {"id": "Ref"}, "HealthCheckId", "list", tags_key="HealthCheckTags"),
    # interconnects
    "aws_customer_gateway": Native("AWS::EC2::CustomerGateway", {
        "bgp_asn": "BgpAsn", "ip_address": "IpAddress", "type": "Type", "device_name": "DeviceName",
        "certificate_arn": "CertificateArn"}, {"id": "Ref"}, "CustomerGatewayId", "list"),
    # attached to its VPC by a resource of its own natively, which what references the gateway waits for (AWS's
    # DependsOn: whatever requires a gateway depends on its attachment); an adopted gateway's attachment can't be
    # imported by what Terraform holds: the translation refuses it
    "aws_vpn_gateway": Native("AWS::EC2::VPNGateway", _defaults({
        "amazon_side_asn": "AmazonSideAsn", "type": "Type", "vpc_id": None}, Type="ipsec.1"),
        {"id": "Ref"}, "VPNGatewayId", "list", expand=_vpn_attachment, ready="Attachment"),
    "aws_vpn_connection": Native("AWS::EC2::VPNConnection", {
        "customer_gateway_id": "CustomerGatewayId", "vpn_gateway_id": "VpnGatewayId",
        "transit_gateway_id": "TransitGatewayId", "type": "Type", "static_routes_only": "StaticRoutesOnly"},
        {"id": "Ref"}, "VpnConnectionId", "list"),
    "aws_vpn_connection_route": Native("AWS::EC2::VPNConnectionRoute", {
        "destination_cidr_block": "DestinationCidrBlock", "vpn_connection_id": "VpnConnectionId"}, {}),
    "aws_ec2_transit_gateway_vpc_attachment": Native("AWS::EC2::TransitGatewayVpcAttachment", {
        "transit_gateway_id": "TransitGatewayId", "vpc_id": "VpcId", "subnet_ids": "SubnetIds"},
        {"id": "Ref"}, "Id", "list"),
    "aws_vpc_peering_connection": Native("AWS::EC2::VPCPeeringConnection", {
        "vpc_id": "VpcId", "peer_vpc_id": "PeerVpcId", "peer_region": "PeerRegion", "peer_owner_id": "PeerOwnerId"},
        {"id": "Ref"}, "Id", "list"),
    # CDN
    "aws_cloudfront_distribution": Native("AWS::CloudFront::Distribution", _distribution, {
        "id": "Ref", "domain_name": "DomainName", "hosted_zone_id": lambda lid: CLOUDFRONT_ZONE,
        "arn": _arn_sub("arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/{id}")}, "Id", "list"),
    # compute
    "aws_instance": Native("AWS::EC2::Instance", _instance, {"id": "Ref", "private_ip": "PrivateIp"}, "InstanceId",
                           "list", parameters=_root_device),
    "aws_launch_template": Native("AWS::EC2::LaunchTemplate", _launch_template,
                                  {"id": "Ref", "latest_version": "LatestVersionNumber",
                                   "default_version": "DefaultVersionNumber"}, "LaunchTemplateId", _template_tags,
                                  tags_key="TagSpecifications"),
    "aws_autoscaling_group": Native("AWS::AutoScaling::AutoScalingGroup", AUTOSCALING_GROUP,
                                    {"id": "Ref", "name": "Ref"}, "AutoScalingGroupName"),
    "aws_iam_instance_profile": Native("AWS::IAM::InstanceProfile", _instance_profile,
                                       {"name": "Ref", "id": "Ref", "arn": "Arn"}, "InstanceProfileName"),
    "aws_lambda_function": Native("AWS::Lambda::Function", lambda f, cx: _lambda(f, cx),
                                  {"arn": "Arn", "function_name": "Ref", "id": "Ref"}, "FunctionName", "list"),
    "aws_scheduler_schedule": Native("AWS::Scheduler::Schedule", {
        "name": "Name", "schedule_expression": "ScheduleExpression", "description": "Description",
        "schedule_expression_timezone": "ScheduleExpressionTimezone", "state": "State", "group_name": "GroupName",
        "flexible_time_window": Nest("FlexibleTimeWindow", {"mode": "Mode",
                                                             "maximum_window_in_minutes": "MaximumWindowInMinutes"}),
        "target": Nest("Target", {"arn": "Arn", "role_arn": "RoleArn", "input": "Input"})},
        {"arn": "Arn", "name": "Ref", "id": "Ref"}, "Name"),
    "aws_synthetics_canary": Native("AWS::Synthetics::Canary", lambda f, cx: _canary(f, cx),
                                    {"name": "Ref", "id": "Ref"}, "Name", "list",
                                    parameters=lambda f, cx: _canary_code(f)),
    # load balancing
    "aws_lb": Native("AWS::ElasticLoadBalancingV2::LoadBalancer", _load_balancer,
                     {"arn": "Ref", "id": "Ref", "dns_name": "DNSName", "zone_id": "CanonicalHostedZoneID",
                      "arn_suffix": "LoadBalancerFullName", "name": "LoadBalancerName"}, "LoadBalancerArn", "list"),
    "aws_lb_listener": Native("AWS::ElasticLoadBalancingV2::Listener", _listener, {"arn": "Ref", "id": "Ref"},
                              "ListenerArn", "list"),
    "aws_lb_target_group": Native("AWS::ElasticLoadBalancingV2::TargetGroup", _target_group,
                                  {"arn": "Ref", "id": "Ref", "arn_suffix": "TargetGroupFullName",
                                   "name": "TargetGroupName"}, "TargetGroupArn", "list"),
    "aws_lb_target_group_attachment": Native(None, merge=Merge("target_group_arn", _append("Targets", {
        "target_group_arn": None, "target_id": "Id", "port": "Port", "availability_zone": "AvailabilityZone"}))),
    # IAM
    "aws_iam_role": Native("AWS::IAM::Role", {
        "name": "RoleName", "assume_role_policy": "AssumeRolePolicyDocument", "description": "Description",
        "path": "Path", "max_session_duration": "MaxSessionDuration",
        "permissions_boundary": "PermissionsBoundary", "managed_policy_arns": "ManagedPolicyArns"},
        {"id": "Ref", "name": "Ref", "arn": "Arn", "unique_id": "RoleId"}, "RoleName", "list"),
    "aws_iam_role_policy": Native(None, merge=Merge("role", _role_policy)),
    "aws_iam_role_policy_attachment": Native(None, merge=Merge("role", _attached_policy)),
    "aws_iam_openid_connect_provider": Native("AWS::IAM::OIDCProvider", {
        "url": "Url", "client_id_list": "ClientIdList", "thumbprint_list": "ThumbprintList"},
        {"arn": "Ref", "id": "Ref"}, "Arn", "list"),
    "aws_iam_service_linked_role": Native("AWS::IAM::ServiceLinkedRole", {
        "aws_service_name": "AWSServiceName", "custom_suffix": "CustomSuffix", "description": "Description"},
        {"name": "Ref", "id": "Ref",
         "arn": lambda lid: _service_linked_arn(lid)}, "RoleName"),
    "aws_organizations_policy": Native("AWS::Organizations::Policy", {
        "name": "Name", "type": "Type", "description": "Description", "content": "Content"},
        {"id": "Ref", "arn": "Arn"}, "Id", "list"),
    "aws_organizations_policy_attachment": Native(None, merge=Merge("policy_id", lambda props, f, cx: {
        **props, "TargetIds": [*props.get("TargetIds", []), *obj(own(f), cx, {
            "policy_id": None, "target_id": "Id", "skip_destroy": None}).values()]})),
    "aws_ssoadmin_permission_set": Native("AWS::SSO::PermissionSet", {
        "name": "Name", "instance_arn": "InstanceArn", "session_duration": "SessionDuration",
        "description": "Description", "relay_state": "RelayStateType"},
        {"arn": "PermissionSetArn", "id": "PermissionSetArn"}, None, "list"),
    "aws_ssoadmin_permission_set_inline_policy": Native(None, merge=Merge("permission_set_arn", lambda props, f, cx: {
        **props, **obj(own(f), cx, {"permission_set_arn": None, "instance_arn": None,
                                    "inline_policy": "InlinePolicy"})})),
    "aws_ssoadmin_account_assignment": Native("AWS::SSO::Assignment", {
        "instance_arn": "InstanceArn", "permission_set_arn": "PermissionSetArn", "principal_id": "PrincipalId",
        "principal_type": "PrincipalType", "target_id": "TargetId", "target_type": "TargetType"}, {}),
    # security services
    "aws_guardduty_detector": Native("AWS::GuardDuty::Detector", {
        "enable": "Enable", "finding_publishing_frequency": "FindingPublishingFrequency"},
        {"id": "Ref"}, None, "list"),
    "aws_guardduty_detector_feature": Native(None, merge=Merge("detector_id", _append("Features", {
        "detector_id": None, "name": "Name", "status": "Status",
        "additional_configuration": Nest("AdditionalConfiguration", {"name": "Name", "status": "Status"}, True)}))),
    "aws_macie2_account": Native("AWS::Macie::Session", {
        "finding_publishing_frequency": "FindingPublishingFrequency", "status": "Status"}, {"id": "Ref"}),
    "aws_macie2_custom_data_identifier": Native("AWS::Macie::CustomDataIdentifier", {
        "name": "Name", "regex": "Regex", "description": "Description", "keywords": "Keywords",
        "ignore_words": "IgnoreWords", "maximum_match_distance": "MaximumMatchDistance"},
        {"id": "Ref", "arn": "Arn"}, None, "list"),
    "aws_securityhub_account": Native("AWS::SecurityHub::Hub", {
        "enable_default_standards": "EnableDefaultStandards", "auto_enable_controls": "AutoEnableControls",
        "control_finding_generator": "ControlFindingGenerator"}, {"id": "Ref", "arn": "ARN"}),
    "aws_securityhub_standards_subscription": Native("AWS::SecurityHub::Standard", {"standards_arn": "StandardsArn"},
                                                     {"id": "Ref", "arn": "Ref"}),
    "aws_securityhub_finding_aggregator": Native("AWS::SecurityHub::FindingAggregator", {
        "linking_mode": "RegionLinkingMode", "specified_regions": "Regions"}, {"id": "Ref", "arn": "Ref"}),
    # organization-wide (5.7b): the delegated administrator, central configuration, a policy on the root
    "aws_securityhub_organization_admin_account": Native("AWS::SecurityHub::DelegatedAdmin", {
        "admin_account_id": "AdminAccountId"}, {"id": "Ref"}),
    "aws_securityhub_organization_configuration": Native("AWS::SecurityHub::OrganizationConfiguration",
                                                         _hub_organization, {"id": "Ref"}),
    "aws_securityhub_configuration_policy": Native("AWS::SecurityHub::ConfigurationPolicy", _hub_policy,
                                                   {"id": "Id", "arn": "Ref"}),
    "aws_securityhub_configuration_policy_association": Native("AWS::SecurityHub::PolicyAssociation",
                                                               _hub_association, {"id": "Ref"}),
    "aws_securityhub_automation_rule": Native("AWS::SecurityHub::AutomationRule", {
        "rule_name": "RuleName", "rule_order": "RuleOrder", "description": "Description",
        "rule_status": "RuleStatus", "is_terminal": "IsTerminal",
        "criteria": Custom(lambda v, cx: {"Criteria": _criteria(v[0], cx)}),
        "actions": Nest("Actions", {"type": "Type", "finding_fields_update": Nest("FindingFieldsUpdate", {
            "workflow": Nest("Workflow", {"status": "Status"}),
            "note": Nest("Note", {"text": "Text", "updated_by": "UpdatedBy"}),
            "severity": Nest("Severity", {"label": "Label", "product": "Product"}),
            "verification_state": "VerificationState", "confidence": "Confidence", "criticality": "Criticality",
            "types": "Types", "user_defined_fields": "UserDefinedFields"})}, True)},
        {"arn": "Ref", "id": "Ref"}, None, "map"),
    "aws_guardduty_filter": Native("AWS::GuardDuty::Filter", {
        "name": "Name", "description": "Description", "action": "Action", "rank": "Rank",
        "detector_id": "DetectorId", "finding_criteria": Custom(_finding_criteria)}, {}, None, "list"),
    "aws_shield_protection": Native("AWS::Shield::Protection", {"name": "Name", "resource_arn": "ResourceArn"},
                                    {"id": "ProtectionId", "arn": "Ref"}, None, "list"),
    # part of the protection its depends_on names (it names the web ACL's association too: the protection then
    # waits for it, as Shield needs the resource associated first)
    "aws_shield_application_layer_automatic_response": Native(None, merge=Merge(
        "depends_on", _automatic_response, target="aws_shield_protection")),
    "aws_wafv2_web_acl": Native("AWS::WAFv2::WebACL", _web_acl, {"arn": "Arn", "id": "Id"}, None, "list"),
    "aws_wafv2_ip_set": Native("AWS::WAFv2::IPSet", {
        "name": "Name", "scope": "Scope", "ip_address_version": "IPAddressVersion", "addresses": "Addresses",
        "description": "Description"}, {"arn": "Arn", "id": "Id"}, None, "list"),
    "aws_wafv2_web_acl_association": Native("AWS::WAFv2::WebACLAssociation", {
        "resource_arn": "ResourceArn", "web_acl_arn": "WebACLArn"}, {}),
    "aws_s3_bucket": Native("AWS::S3::Bucket", {
        "bucket": "BucketName", "object_lock_enabled": "ObjectLockEnabled", "force_destroy": None},
        S3_BUCKET_REFS, "BucketName", "list"),
    "aws_s3_bucket_policy": Native("AWS::S3::BucketPolicy", {"bucket": "Bucket", "policy": "PolicyDocument"},
                                   {"id": "Ref"}),
    "aws_s3_bucket_versioning": Native(None, merge=Merge("bucket", _bucket_setting("VersioningConfiguration", {
        "versioning_configuration": Custom(lambda v, cx: obj(v[0], cx, {"status": "Status",
                                                                        "mfa_delete": None}))}), S3_BUCKET_REFS)),
    "aws_s3_bucket_lifecycle_configuration": Native(None, merge=Merge("bucket", _bucket_setting(
        "LifecycleConfiguration", {"rule": Nest("Rules", LIFECYCLE_RULE, True)}), S3_BUCKET_REFS)),
    "aws_s3_bucket_object_lock_configuration": Native(None, merge=Merge("bucket", _bucket_setting(
        "ObjectLockConfiguration", {"rule": Nest("Rule", {"default_retention": Nest("DefaultRetention", {
            "mode": "Mode", "days": "Days", "years": "Years"})})}, _object_lock), S3_BUCKET_REFS)),
    "aws_s3_bucket_public_access_block": Native(None, merge=Merge("bucket", _bucket_setting(
        "PublicAccessBlockConfiguration", {"block_public_acls": "BlockPublicAcls",
                                           "block_public_policy": "BlockPublicPolicy",
                                           "ignore_public_acls": "IgnorePublicAcls",
                                           "restrict_public_buckets": "RestrictPublicBuckets"}), S3_BUCKET_REFS)),
    "aws_s3_bucket_replication_configuration": Native(None, merge=Merge("bucket", _bucket_setting(
        "ReplicationConfiguration", {"role": "Role", "rule": Nest("Rules", REPLICATION_RULE, True)}), S3_BUCKET_REFS)),
    "aws_s3_bucket_server_side_encryption_configuration": Native(None, merge=Merge("bucket", _bucket_setting(
        "BucketEncryption", {"rule": Nest("ServerSideEncryptionConfiguration", SSE_RULE, True)}), S3_BUCKET_REFS)),
}


def _refuse(cx, why):
    raise SystemExit(f"{cx.where}: {why}")


def _copy_region(f, cx):
    """The region an RDS instance's automated backups are copied to: the region of the provider the Terraform
    replication resource runs under."""
    provider = f.get("provider")
    alias = str(provider)[2:-1].split(".", 1)[1] if isinstance(provider, str) and "." in provider else None
    return cx.provider_region(alias) if alias else cx.region


def _service_linked_arn(lid):
    return sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/aws-service-role/${" + lid + "}")


def _criteria(f, cx):
    """A Security Hub automation rule's criteria: each filter key's blocks as a list of filters."""
    return {pascal(k): [obj(b, cx, {"comparison": "Comparison", "value": "Value", "key": "Key"},
                            f"{cx.where}.criteria.{k}") for b in v] for k, v in f.items()}


def _lambda(f, cx):
    return obj(own(f), cx, {
        "function_name": "FunctionName", "role": "Role", "runtime": "Runtime", "handler": "Handler",
        "timeout": "Timeout", "memory_size": "MemorySize", "description": "Description",
        "architectures": "Architectures", "kms_key_arn": "KmsKeyArn", "layers": "Layers",
        "reserved_concurrent_executions": "ReservedConcurrentExecutions",
        "filename": "Code", "source_code_hash": None,
        "environment": Nest("Environment", {"variables": "Variables"}),
        "vpc_config": Nest("VpcConfig", {"subnet_ids": "SubnetIds", "security_group_ids": "SecurityGroupIds"}),
        "tracing_config": Nest("TracingConfig", {"mode": "Mode"}),
        "dead_letter_config": Nest("DeadLetterConfig", {"target_arn": "TargetArn"})})


def _canary_code_ids(f):
    from opsdir_format_cloudformation.template import logical_id
    return logical_id("canary", f["name"], "code", "bucket"), logical_id("canary", f["name"], "code", "key")


def _canary_code(f):
    bucket, key = _canary_code_ids(f)
    return (Parameter(bucket, "String", None, f"The S3 bucket canary {f['name']}'s code zip is uploaded to"),
            Parameter(key, "String", None, f"The S3 key of canary {f['name']}'s code zip (the folder beside this "
                      "template its zip_file packages, zipped)"))


def _canary(f, cx):
    bucket, key = _canary_code_ids(f)
    return obj(own(f), cx, {
        "name": "Name", "runtime_version": "RuntimeVersion", "artifact_s3_location": "ArtifactS3Location",
        "execution_role_arn": "ExecutionRoleArn", "start_canary": "StartCanaryAfterCreation",
        "failure_retention_period": "FailureRetentionPeriod", "success_retention_period": "SuccessRetentionPeriod",
        "handler": Custom(lambda v, c: {"Code": {"Handler": c.value(v), "S3Bucket": c.param(bucket),
                                                 "S3Key": c.param(key)}}),
        "zip_file": None,
        "schedule": Nest("Schedule", {"expression": "Expression",
                                      "duration_in_seconds": _as_string("DurationInSeconds")}),
        # AWS::Synthetics::Canary spells it VPCConfig (Lambda's is VpcConfig): cfn-lint's bundled schema
        "vpc_config": Nest("VPCConfig", {"subnet_ids": "SubnetIds", "security_group_ids": "SecurityGroupIds"}),
        "run_config": Nest("RunConfig", {"timeout_in_seconds": "TimeoutInSeconds", "memory_in_mb": "MemoryInMB",
                                         "active_tracing": "ActiveTracing",
                                         "environment_variables": "EnvironmentVariables"})})


# ------------------------------------------------------------------ data sources

def _packaged(f, a):
    """data.archive_file: Terraform zips source_dir at plan time; natively `aws cloudformation package` zips and
    uploads the same folder (beside the template), so output_path reads as that folder."""
    source = str(f.get("source_dir", ""))
    return "./" + source.split("${path.module}/", 1)[1] if a == "output_path" and "${path.module}/" in source else None


STATEMENT = {"sid": "Sid", "effect": "Effect", "actions": "Action", "not_actions": "NotAction",
             "resources": "Resource", "not_resources": "NotResource", "principals": "Principal",
             "not_principals": "NotPrincipal", "condition": "Condition"}


def _statement(s, value):
    """A policy document statement block as IAM's statement (Effect Allow unless it says)."""
    unknown = sorted(set(s) - set(STATEMENT))
    if unknown:
        raise SystemExit(f"data.aws_iam_policy_document: no CloudFormation form for {', '.join(unknown)} of a "
                         "statement")

    def part(k, v):
        if k in ("principals", "not_principals"):
            return {p["type"]: value(p["identifiers"]) for p in v}
        if k == "condition":
            tests = dict.fromkeys(c["test"] for c in v)
            return {t: {object_key(value(c["variable"])): value(c["values"]) for c in v if c["test"] == t}
                    for t in tests}
        return value(v)
    return {"Effect": "Allow", **{STATEMENT[k]: part(k, v) for k, v in s.items()}}


def _policy_document(f, value):
    """data.aws_iam_policy_document's json natively: the document itself (json_document: its JSON text in one
    Fn::Sub where a condition key is computed, as an IRSA trust policy's is)."""
    unknown = sorted(set(own(f)) - {"statement", "version"})
    if unknown:
        raise SystemExit(f"data.aws_iam_policy_document: no CloudFormation form for {', '.join(unknown)}")
    return json_document({"Version": f.get("version", "2012-10-17"),
                          "Statement": [_statement(s, value) for s in f.get("statement", ())]})


def _issuer(f):
    name = f.get("name")
    return Parameter("OidcIssuer", "String", None,
                     f"The OIDC issuer of EKS cluster {name} without https:// (aws eks describe-cluster --name {name} "
                     "--query cluster.identity.oidc.issuer); Terraform looks it up")


def _oidc_provider(f, a):
    """data.aws_iam_openid_connect_provider found by url: its url as given, its ARN built from it (IAM names an OIDC
    provider by its URL without https://)."""
    if a == "url":
        return Computed(lambda f, value: value(f["url"]))
    if a == "arn":
        return Computed(lambda f, value: concat("arn:", ref(PARTITION), ":iam::", ref(ACCOUNT_ID), ":oidc-provider/",
                                                trim_prefix(value(f["url"]), "https://")))
    return None


def _looked_up(what, attributes=("id",)):
    """A data table answer for what Terraform looks up and CloudFormation can't: a parameter the deployer gives."""
    return lambda f, a: (Parameter("", "String", None, f"{what(f)} (Terraform looks it up; CloudFormation can't)")
                         if a in attributes else None)


DATA = {
    "archive_file": _packaged,
    "aws_ami": _ami,
    "aws_cloudfront_cache_policy": _managed_policy(MANAGED_CACHE_POLICIES, "cache policy"),
    "aws_cloudfront_origin_request_policy": _managed_policy(MANAGED_ORIGIN_REQUEST_POLICIES, "origin request policy"),
    "aws_ec2_managed_prefix_list": _looked_up(lambda f: f"The ID of AWS-managed prefix list {f.get('name')} in "
                                                        "this region"),
    "aws_eks_cluster": lambda f, a: (Derived(_issuer(f), lambda r: concat("https://", r))
                                     if a == "identity[0].oidc[0].issuer" else None),
    "aws_guardduty_detector": _looked_up(lambda f: "The account's GuardDuty detector ID in this region"),
    "aws_organizations_organization": _looked_up(lambda f: "The organization's root ID (r-...)", ("roots[0].id",)),
    "aws_iam_openid_connect_provider": _oidc_provider,
    "aws_iam_policy_document": lambda f, a: Computed(_policy_document) if a == "json" else None,
    "aws_internet_gateway": _looked_up(lambda f: "The ID of the internet gateway attached to the VPC"),
    "aws_caller_identity": lambda f, a: Pseudo(ACCOUNT_ID) if a == "account_id" else None,
    "aws_partition": lambda f, a: (Pseudo(PARTITION) if a == "partition" else
                                   Pseudo(URL_SUFFIX) if a == "dns_suffix" else None),
    "aws_region": lambda f, a: Pseudo(REGION) if a in ("region", "name", "id") else None,
    "aws_vpc": lambda f, a: (Parameter("", "AWS::EC2::VPC::Id", f.get("id"), "The VPC (the record's network binding)")
                             if a == "id" else None),
    "aws_subnet": lambda f, a: (Parameter("", "AWS::EC2::Subnet::Id", f.get("id"), "A subnet the record binds")
                                if a == "id" else None),
    "aws_nat_gateway": lambda f, a: (Parameter("", "String", f.get("id"), "A NAT gateway the record binds")
                                     if a == "id" else None),
    "aws_eip": lambda f, a: (Parameter("", "String", None, f"The allocation ID of Elastic IP {f.get('public_ip')} "
                                       "(Terraform looks it up by address; CloudFormation can't)")
                             if a in ("id", "allocation_id") else None),
    "aws_s3_bucket": lambda f, a: (Parameter("", "String", f.get("bucket"), "A bucket the record names")
                                   if a in ("id", "bucket") else
                                   Derived(Parameter("", "String", f.get("bucket"), "A bucket the record names"),
                                           lambda r: sub("arn:${AWS::Partition}:s3:::${Name}", {"Name": r}))
                                   if a == "arn" else None),
    "aws_secretsmanager_secret": lambda f, a: (Parameter("", "String", f.get("arn"), "A secret the record references")
                                               if a in ("arn", "id") else None),
    "aws_ssoadmin_instances": lambda f, a: (
        Parameter("", "String", None, "The ARN of the account's IAM Identity Center instance (Terraform looks it "
                  "up; CloudFormation can't)") if a == "arns[0]" else
        Parameter("IdentityStore", "String", None, "The identity store ID of the account's IAM Identity Center "
                  "instance") if a == "identity_store_ids[0]" else None),
}


def cloudformation_files(m, files, what):
    """{path: TfFile | text} of environment m's CloudFormation from its AWS Terraform render (cfn_render.translated by
    this table)."""
    return translated(m, files, TYPES, NO_NATIVE, DATA, what, unavailable)


def cloudformation_translation(m, files, what):
    """The cfn_render.Translation of environment m's AWS Terraform render by this table (templates, imports, side
    roots, where each Terraform resource went)."""
    return translation(m, files, TYPES, NO_NATIVE, DATA, what, unavailable)

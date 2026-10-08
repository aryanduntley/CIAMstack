# opsdir-adapter-aws

opsdir adapter for Amazon Web Services: Terraform for AWS environments; AWS Terraform state, AWS CLI output and CloudFormation stacks read back into the record; `aws-sm://` secret references.

**Applies to** environments whose cloud has `ciamCloudProvider: aws`, in the commercial partition (`ciamCloudEnvironment: public`). A provider adapter: it renders and reads an environment's infrastructure bindings; products (PingDS, PingFederate, …) are other adapters.

**Depends on** `opsdir`, `opsdir-format-terraform` (HCL formatting, the Terraform state reader) and `pyyaml` (CloudFormation templates).

## What it renders

Per environment, `terraform/providers.tf` (`hashicorp/aws ~> 5.0`; `region` from the cloud's `ciamRegion`; `use_fips_endpoint = true` when the cloud's `ciamFipsEndpoints` is TRUE (core `estate` domain); credentials come from the usual AWS environment, never from the record) and `terraform/main.tf`:

| From the record | Rendered as |
|---|---|
| The `network` binding: `ciamProviderRef` (the VPC ID) | `data aws_vpc` `main`: the landing zone owns the VPC |
| Subnet bindings: `ciamProviderRef` (the subnet ID) | `data aws_subnet` |
| One security group per server role | `aws_security_group` `ciam-<env>-<role>` in the VPC |
| Firewall rules | `aws_vpc_security_group_ingress_rule`, one per source CIDR and port (`ciamSourceCidr` × `ciamPort`), in the target role's group; protocol `ciamProtocol` (default `tcp`); description `<consumer or binding role> (<rule name>)`, the suffix the importers group rules back by |
| Servers | `aws_instance` (AMI `ciamImageRef`, `ciamInstanceSize`, the server's subnet, static `ciamPrivateIp`, its role's security group; encrypted root volume with the `disk-encryption` binding's KMS key, else an `UNBOUND` comment; tags `Name`, `Role`, `Hostname`, `Product`, `ManagedBy`) |
| Service names | Network load balancer, internal when `ciamFrontendIp` is private: one subnet mapping per subnet holding a target, the frontend address pinned in its subnet; a public one takes the Elastic IP allocation named by the service's `ciamProviderRef`. Per `ciamPort`: a TCP target group with a TCP health check, an attachment per server with the target role, a TCP listener. A Route 53 alias A record in `ciamDnsZoneRef` (target health evaluated). A service whose role a traffic or protection policy names (core `edge` domain) is tuned or replaced by it: see [Edge](#edge-traffic-and-protection-policies) |
| Secret references (`aws-sm://<arn>`) | `data aws_secretsmanager_secret` per secret: metadata only, so a missing secret fails the plan and no value enters Terraform state (`aws_secretsmanager_secret_version` is never rendered) |
| The `backup-target` binding; the `pf-egress` binding | `data aws_s3_bucket` `ds_backups`; `data aws_nat_gateway` `pf_egress` (when it has a `ciamProviderRef`) |
| Workload principals (core `access` domain: kind `workload`, `ciamTargetRole` a server role here) | Per principal: `aws_iam_role` EC2 may assume (named by its identity binding's provider ref, else `ciam-<env>-<server role>`), an inline `aws_iam_role_policy` with one statement per permission from the access table below (the binding's resource: a secret's ARN with its six-character suffix `-??????`, a key's ARN, `arn:aws:s3:::<bucket>/<prefix>*` and the bucket, a stream's ARN, a log group's ARN and `:*`), an `aws_iam_instance_profile` set on the role's instances; a permission that can't be granted (role unbound here, or no row) is a `# NOTE` |
| Control-plane audit trails (core `observability`: `ciamAuditTrail`) the platform team keeps | `aws_cloudtrail` into the S3 bucket of the object store its `ciamLogDestinationRole` names: `is_multi_region_trail` and `include_global_service_events` from `ciamAllRegions`, `enable_log_file_validation` from `ciamIntegrityValidation`, `is_organization_trail` for scope `organization`; data events are a comment (event selectors must name the resources). A trail `ciamManagedBy` names someone else keeps (an organization trail the landing zone keeps) is a comment naming its keeper; one delivering to a CloudWatch log group is a `# NOTE` (that delivery also needs a role) |
| Security services (core `estate`: `ciamSecurityService`) the platform team keeps | threat-detection: `aws_guardduty_detector` (its foundational sources watch control-plane, identity and network) and an `aws_guardduty_detector_feature` per further area (storage `S3_DATA_EVENTS`; containers `EKS_AUDIT_LOGS` and `RUNTIME_MONITORING` with the EKS add-on and Fargate agent; compute `EBS_MALWARE_PROTECTION` and `RUNTIME_MONITORING` with the EC2 agent; databases `RDS_LOGIN_EVENTS`; applications `LAMBDA_NETWORK_LOGS`; key-vaults a comment). vulnerability-scanning: `aws_inspector2_enabler` (EC2, ECR, LAMBDA/LAMBDA_CODE from the areas; EC2 and ECR by default). config-recording: `aws_config_configuration_recorder` through AWS Config's service-linked role, its delivery channel to the bucket of the object store its `ciamFindingsRole` names (none: a `# NOTE`), `aws_config_retention_configuration` from `ciamRetentionDays` (30 to 2557), the recorder status. posture: `aws_securityhub_account` (consolidated control findings) and an `aws_securityhub_standards_subscription` per standard Security Hub has (`cis` v5.0.0, `nist-800-53-r5`, `nist-800-171-r2`, `pci-dss`; baselines `aws-foundational`, `aws-resource-tagging`; partition and region from data sources), the rest a comment. Findings of GuardDuty, Inspector and Security Hub go to the SNS topic or log group (`ciamProviderRef`) of the binding `ciamFindingsRole` names through an `aws_cloudwatch_event_rule` and target. Organization scope, every region, and services `ciamManagedBy` names someone else as keeper are comments |
| Required roles without a binding | `# UNBOUND: required role …` |

Not rendered: the VPC, subnets, NAT gateways, buckets, Elastic IPs and Route 53 zones themselves (referenced, the landing zone creates them); KMS keys (referenced by ARN); egress security group rules; key pairs, IAM instance profiles and user data; application load balancers and TLS listeners (services are TCP pass-through).

## Edge: traffic and protection policies

A service name whose role an `edge` traffic or protection policy names (`ou=edge-policies`) is rendered from it; one no policy names renders as above. Health paths, rate-limit targets and exclusions come from the endpoints the product adapters declare (PingFederate, PingAM, PingIDM, PingGateway), unless a policy's `ciamEndpointPath` moves one.

| From the policies | Rendered as |
|---|---|
| TLS mode `passthrough` (or none) | The network load balancer above; its target groups take the policy's health check (`tcp`, `http`, `https` with path, interval, thresholds), `source-ip` stickiness and `ciamDrainSeconds` as `deregistration_delay` |
| TLS mode `terminate` / `reencrypt` | An application load balancer (`drop_invalid_header_fields`, `ciamIdleTimeoutSeconds` as `idle_timeout`) in the targets' subnets, with its own security group: clients in by the firewall rules admitting them to the target role on the service's ports, out to the servers' group, which admits it. Per port: an HTTPS listener with the ELB security policy for (`ciamTlsMinVersion`, `ciamTlsProfile`) and the ACM certificate the environment holds for the service's certificate (an `aws-acm://` certificate reference), an `HTTP` (terminate) or `HTTPS` (reencrypt) target group with the policy's health check (over HTTP/HTTPS), `lb_cookie` stickiness and draining. Its addresses are AWS's: a recorded `ciamFrontendIp` isn't kept (a comment says so) |
| Protection policy with firewall rules, rate limits, address or country rules | A WAFv2 web ACL (regional) associated with the load balancer: address rules (`aws_wafv2_ip_set` per action and family), country rules (`geo_match_statement`; an `allow` blocks everything else), a rate-based rule per `ciamRateLimit` scoped to the endpoint paths (regular expressions; by client address or a header; the window AWS has, else 300 s with the limit scaled, at least 10), a managed rule group per `ciamWafCategory`. `ciamWafMode` `detect` counts instead of blocking. An exclusion keeps the excluded endpoints out of that group's scope (AWS can't skip one field) |
| `ciamDdosTier` `network-advanced` / `application-advanced` | `aws_shield_protection` on the load balancer (needs the account's Shield Advanced subscription); application-advanced adds `aws_shield_application_layer_automatic_response` |

| TLS terms | ELB security policy |
|---|---|
| 1.3, any profile | `ELBSecurityPolicy-TLS13-1-3-2021-06` |
| 1.2 modern / intermediate / compatible | `ELBSecurityPolicy-TLS13-1-2-Res-2021-06` / `ELBSecurityPolicy-TLS13-1-2-2021-06` / `ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06` (nearest; a comment says so) |

| WAF category | Managed rule group |
|---|---|
| `core-rules`, `known-bad-inputs`, `ip-reputation`, `bot-control` | `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet`, `AWSManagedRulesAmazonIpReputationList`, `AWSManagedRulesBotControlRuleSet` (inspection level `COMMON`) |
| `account-takeover` | `AWSManagedRulesATPRuleSet` with the first literal sign-in path as `login_path` (add its request inspection: the form's username and password fields); none literal: an `UNBOUND` comment |
| `account-creation-fraud` | `AWSManagedRulesACFPRuleSet` with the first literal registration path |

Known limits: request inspection on a passthrough service isn't rendered (a comment; the planner flags the policy); stickiness the load balancer type doesn't offer is a comment.


### DNS

Nothing is rendered into a zone whose binding names `ciamManagedBy` (someone outside the platform runs it): a comment names them, and the plan drafts the request. A name that routes between environments (`ciamRoutingPolicy` `failover-primary` / `failover-secondary` / `weighted` on the service names of several environments) is answered from the environment holding the primary (a weighted set: the first by label), which renders every environment's answer; the others render a comment.

| From the record | Rendered as |
|---|---|
| A service name | Its Route 53 alias record (a recorded `ciamTtlSeconds` doesn't apply to an alias: a comment); routed, with `set_identifier` (the environment) and a failover or weighted routing policy, the other environments' answers as A records with their TTL, each with a TCP `aws_route53_health_check` on its address and first port |
| DNS records (`ciamDnsRecord`) | `aws_route53_record` in the zone the record's name falls in (the zone binding's `ciamProviderRef`, public or private), type, `ciamTtlSeconds` (300 when not recorded), values; no zone bound: an `UNBOUND` comment |
| Outbound forwarders (`ciamDnsForwarder`) | Per domain an `aws_route53_resolver_rule` (`FORWARD`, a `target_ip` per `ciamForwardTarget` on port 53) through `var.resolver_endpoint_id` (the landing zone's outbound Resolver endpoint; the variable is declared only when there are forwarders) and its association with the VPC. Inbound forwarders are the landing zone's inbound endpoint: a comment |

### CDN

A protection policy with `ciamCdn` puts a CloudFront distribution in front of the service: its origin is the service's load balancer (the ALB when TLS terminates at the edge, else the NLB, TLS then ending at CloudFront), over HTTPS with the viewer's `Host` forwarded (AWS's `Managed-AllViewer` origin request policy) and nothing cached (`Managed-CachingDisabled`: sign-in pages and tokens); the viewer certificate from ACM in us-east-1 (another region or none: an `UNBOUND` comment), `TLSv1.2_2021` minimum; the service's alias record points at the distribution. The protection policy's web ACL (and its IP sets) is created CloudFront-scoped through the provider alias `aws.us_east_1` (declared only when a CDN is used) and named by the distribution (`web_acl_id`); Shield protects the distribution. The ALB behind it admits only CloudFront's origin-facing prefix list and carries no web ACL or Shield of its own.

### Network depth

What the core `network` domain records and the stack keeps itself (no `ciamManagedBy`) renders into the platform's root; what someone else keeps (a hub firewall, the landing zone's endpoints) is a comment naming them, rendered in their root. Nothing recorded, nothing rendered (`opsdir_adapter_aws.network`).

| Record | Renders as |
|---|---|
| `ciamPrivateEndpoint` kind `interface` | `aws_vpc_endpoint` `Interface` to `com.amazonaws.<region>.<service>` (`secrets` Secrets Manager, `keys` KMS, `object-storage` S3, `logs` CloudWatch Logs, `messaging` SNS, `registry` ECR API) in the subnets its `ciamSubnetRole` names, `private_dns_enabled` from `ciamPrivateDns`, with its own security group admitting the network's range on 443 |
| kind `gateway` | `aws_vpc_endpoint` `Gateway` (S3, DynamoDB only; others a comment) on the route tables (`ciamRouteTable` provider refs) naming its subnets, the main table for subnets none names; every recorded table when it names no subnets |
| A service, database or kind AWS has no endpoint for | A comment (a database is reached at its own private address) |
| `ciamEndpointService` | `aws_vpc_endpoint_service` on the network load balancer of the service name `ciamServiceRole` names: `allowed_principals` from `ciamAllowedPrincipal`, `acceptance_required` from `ciamAcceptanceRequired`. A service whose traffic policy puts it on an ALB can't be exposed (an endpoint service needs an NLB): a comment |
| `ciamProxy` kind `firewall` the stack keeps | An `aws_networkfirewall_rule_group` (`STATEFUL`, `rules_source_list` `ALLOWLIST` on `TLS_SNI` and `HTTP_HOST`, `*.example` as `.example`, `HOME_NET` the network's range) and a comment to reference it from the firewall policy its `ciamProviderRef` names. A domain list matches web traffic only: sites on other ports (a mail relay on 587) are named in a comment, decided by the policy's other rules |
| Other proxies (a forward proxy, a proxy service) | A comment: their allowlist is kept there |

### Managed databases

The core `data` domain's databases (`ciamDatabase`) the stack keeps render into `main.tf`; one naming someone else in `ciamManagedBy` is a comment naming them (`opsdir_adapter_aws.databases`).

| Record | Renders as |
|---|---|
| `ciamDatabase` (service `rds`, or none) | `aws_db_instance`: engine from `ciamDbEngine` and `ciamDbEdition` (`postgres`, `mysql`, `mariadb`, `sqlserver-se`/`-ee`/`-ex`/`-web`, `oracle-se2`/`-ee`), `ciamDbEngineVersion`, `ciamInstanceSize`, `ciamDbStorageGb`, `ciamPort`, `multi_az` when `ciamDbHighAvailability` is `zone-redundant` (else `ciamZone`), `storage_encrypted` with the KMS key of `ciamEncryptedByRole`, `backup_retention_period` from `ciamRetentionDays`, `deletion_protection`, not publicly accessible; tags `Name`, `Role`, `ManagedBy` |
| `ciamCopyRegion` of an RDS instance | `aws_db_instance_automated_backups_replication`: its automated backups (and the transaction logs point-in-time restore replays) copied to the first copy region, created through that region's provider (`aws.copy_<region>`, declared in `providers.tf`), encrypted with the key's replica there when `ciamEncryptedByRole` is a multi-region key (`mrk-`), else with the key `var.<db>_copy_kms_key_arn` names; RDS replicates to one region, so further regions are a comment, and so is Aurora (a global database or an AWS Backup copy does it) |
| service `aurora` (PostgreSQL, MySQL) | `aws_rds_cluster` with the same settings and one `aws_rds_cluster_instance`, two when zone-redundant |
| Credentials | `manage_master_user_password`: RDS keeps the master password in Secrets Manager, so no password is in the Terraform, its state or the record; `ciamDbCredentialRole` names that secret's binding. The master user name is a variable, `<database>_admin_username` |
| `ciamSubnetRole` | `aws_db_subnet_group` of those subnets |
| Its role, `ciamSourceCidr` | `aws_security_group` `ciam-<env>-<role>`, with an `aws_vpc_security_group_ingress_rule` to the database's port (`ciamPort`, else the engine's) from each range it admits |
| `ciamDbParameter`, `ciamDbTlsRequired` | `aws_db_parameter_group` (Aurora: `aws_rds_cluster_parameter_group`), family from the engine, edition and major version (`postgres16`, `mysql8.0`, `sqlserver-se-15.0`), holding the parameters and, where TLS differs from the engine's default, `rds.force_ssl` (PostgreSQL, SQL Server; required by default from PostgreSQL 15) or `require_secure_transport` (MySQL, MariaDB). Oracle's TLS needs an option group: a comment |
| `ciamProviderRef` recorded | An `import` block (the ARN's last part is the identifier): the database is adopted, not created. Its subnet and parameter groups are adopted by hand, or Terraform creates new ones and moves it to them |
| `ciamDbPointInTime` `FALSE` with backups kept | A comment: RDS restores to a point in time whenever it keeps backups |

### Disks and snapshot policies

The core `data` domain's volumes (`ciamVolume`, each server role's disks) and snapshot policies (`ciamSnapshotPolicy`) render into `main.tf` (`opsdir_adapter_aws.volumes`). Classes to types: `standard` st1, `ssd` gp3, `provisioned` io2.

| Record | Renders as |
|---|---|
| The role's boot volume (`ciamVolumeKind` `boot`) | Each instance's `root_block_device`: `volume_size`, `volume_type`, `iops`, `throughput`, encrypted with its key role's KMS key (`ciamEncryptedByRole`, else the `disk-encryption` binding's; unbound: a comment), tagged `Volume`, `Role`. Without one, the root disk is encrypted with the disk key as before |
| Each data volume of the role | Per server: an `aws_ebs_volume` in the server's zone (size, type, IOPS, throughput, encryption) tagged `Name`, `Volume`, `Role`, `Server`, `SnapshotPolicy`, and an `aws_volume_attachment` at `/dev/sdf`, `/dev/sdg`, … in the volumes' order; the server mounts it at `ciamMountPath` itself (a comment) |
| `ciamVolumeEncrypted` `FALSE` | Rendered as recorded (`encrypted = false`); the planner names it |
| `ciamSnapshotPolicy` the stack keeps | An `aws_dlm_lifecycle_policy` (`execution_role_arn` an input, `dlm_execution_role_arn`) snapshotting the volumes tagged `SnapshotPolicy = <role>`: `create_rule` every `ciamSnapshotEveryHours` (1, 2, 3, 4, 6, 8, 12 or 24; another interval is a comment) from `ciamSnapshotAt`, `retain_rule` `ciamRetentionDays` days, an encrypted `cross_region_copy_rule` per `ciamCopyRegion` (at most three) keyed by the disk key's replica there when it is a multi-region key replicated to that region, else an input `<policy>_<region>_kms_key_arn`; an `import` block when its provider ref (the policy ID) is recorded. One someone else keeps: a comment |

### Backup vaults and plans

The core `data` domain's backup vaults (`ciamBackupVault`) and plans (`ciamBackupPlan`) render as AWS Backup into `main.tf` (`opsdir_adapter_aws.backups`).

| Record | Renders as |
|---|---|
| `ciamBackupVault` the stack keeps | An `aws_backup_vault` `ciam-<env>-<name>` with `kms_key_arn` from its key role (AWS Backup's own key when it names none: a comment), tagged `Name`, `Role`; its lock an `aws_backup_vault_lock_configuration` (`min_retention_days` its `ciamStorageLockDays`; `compliance` with `changeable_for_days = 3`, the grace AWS gives before a compliance lock can't be changed or removed; `governance` without). `ciamCrossRegionRestore` is a comment: on AWS another region's restores come from a plan's copies to a vault there. An `import` block when its provider ref is recorded |
| `ciamBackupPlan` the stack keeps | An `aws_backup_plan` `ciam-<env>-<name>` with one rule into its vault: `schedule` `cron(M H ? * * *)` daily, `cron(M H/N ? * * *)` every N hours, `cron(M H */D * ? *)` every D days (another interval is a comment), `start_window` from `ciamBackupWindowHours`, `lifecycle` `delete_after` its retention, a `copy_action` per `ciamCopyRegion` to that region's vault (its ARN an input, `<plan>_<region>_vault_arn`); and an `aws_backup_selection` choosing every resource tagged `Role` = a role it protects (the volumes, databases and instances this adapter renders carry that tag), AWS Backup's IAM role an input (`backup_iam_role_arn`). A plan whose vault isn't bound is a comment. An `import` block when its provider ref is recorded |
| One someone else keeps (`ciamManagedBy`) | A comment naming them |

## Reading an environment back from Terraform state

```bash
terraform -chdir=… state pull > export/source/prod/terraform.tfstate     # one folder per <cloud>/<env>
opsdir import --dry-run aws/terraform-state export/                        # what the live environment differs in
opsdir import --change CHG-… aws/terraform-state export/                   # record it
```

The importer `aws/terraform-state` reads Terraform state (format version 4, `hashicorp/aws`; managed resources and data sources) into the environment's servers and bindings. Environments are chosen by the folder layout, `<cloud>/<env>/`; an environment whose cloud isn't AWS, and a state outside the layout, are named, not imported.

| AWS resource | Record entry | Matched by |
|---|---|---|
| `aws_vpc` | network: CIDR block; role `network` unless tagged otherwise | VPC ID (`ciamProviderRef`) |
| `aws_subnet` | subnet binding: CIDR block, availability zone | subnet ID (`ciamProviderRef`) |
| `aws_instance` | server: private address, availability zone, instance type, AMI, its subnet; name, role, hostname and product from tags `Name`, `Role`, `Hostname`, `Product` (hostname else the private DNS name) | name, hostname or private address |
| `aws_lb` / `aws_alb` + `aws_lb_listener`, `aws_lb_target_group` and attachments, `aws_route53_record`, `aws_eip` | service name: DNS name and zone of the Route 53 record aliasing the load balancer (else tag `Service`), listener ports (else its target groups' ports), the role most of its targets have, the private address of an internal one or the Elastic IP (allocation and address) of a public one | DNS name |
| `aws_vpc_security_group_ingress_rule` and inline `ingress` of `aws_security_group` | firewall rule: IPv4 source CIDRs, ports, protocol (`tcp`/`udp`), grouped into the record's rules by the name their descriptions end with, `(fw-name)`, or their tag `Name`; target role from the instances in the group, else the group's tag `Role`, else its name's last part (`ciam-<env>-<role>`) | rule name |
| `aws_secretsmanager_secret` (+ `aws_secretsmanager_secret_rotation`) | secret reference `aws-sm://<arn>`: automatic rotation and its function (`ciamRotationFunction`), last rotation when present, the role of the customer managed key that encrypts it (`kms_key_id`: `ciamEncryptedByRole`) | reference URI |
| `aws_kms_key` (+ `aws_kms_replica_key`) | key reference `aws-kms://<arn>`: rotation, replica regions | reference URI |
| `aws_s3_bucket` | object store `s3://<bucket>` | storage reference |
| `aws_nat_gateway` | egress: its public address (`/32`) | NAT gateway ID (`ciamProviderRef`) |
| `aws_lambda_function`, `aws_codepipeline`, `aws_codebuild_project` (+ `aws_cloudwatch_event_rule` / `aws_cloudwatch_event_target`, `aws_scheduler_schedule`) | job binding (`ciamJobBinding`, the core automation domain): what realizes a job in the environment: its ARN, runtime (a build project's image), and the schedules the EventBridge rules and Scheduler schedules that target it run it on (a Lambda alias or version ARN counts as its function); the job itself (`ou=jobs`) names the binding role (`ciamJobRole`) | ARN (`ciamProviderRef`) |
| `aws_autoscaling_group` (+ its `aws_launch_template`, directly or through a mixed instances policy) | compute group (`ciamComputeGroup`, the core compute domain): the server role it runs (`ciamTargetRole`, its tag `Role`), min/desired/max, the zones of its subnets (else its `availability_zones`), the template's image, instance type and whether the metadata service requires tokens (`http_tokens`: IMDSv2). Its binding role is its tag `BindingRole`, else `compute-<role>` | ARN (`ciamProviderRef`) |
| `aws_eks_cluster` (+ `aws_eks_node_group`, `aws_eks_addon`) | cluster (`ciamCluster`): Kubernetes version, add-ons and versions, node groups (`name: instance types, min-max`), the zones of its subnets. Its binding role is its tag `BindingRole` or `Role`, else `cluster` | ARN (`ciamProviderRef`) |
| `aws_sesv2_email_identity`, `aws_ses_domain_identity` (+ `aws_ses_domain_dkim`, the domain's `aws_route53_record` TXT records) | sending identity (`ciamSendingIdentity`, the core messaging domain) for a domain: DKIM verified (signing status `SUCCESS`), SPF authorizing SES (`include:amazonses.com`), the DMARC policy (`_dmarc` record). An identity for a single address isn't a domain's and is left out | ARN (`ciamProviderRef`) |
| `aws_sqs_queue`, `aws_sns_topic`, `aws_cloudwatch_event_bus` (not the default bus), `aws_kinesis_stream` | stream carrier (`ciamStreamBinding`): what carries an event stream (`ou=event-streams` names its binding role, `ciamStreamRole`); an SNS topic an alarm notifies is an alert channel instead | ARN (`ciamProviderRef`) |
| `aws_sns_topic` named in an alarm's `alarm_actions`, `ok_actions` or `insufficient_data_actions` | alert channel (`ciamAlertChannel`, the core observability domain): `topic`; an alert rule's `ciamAlertRole` names it | ARN (`ciamProviderRef`) |
| `aws_cloudwatch_log_group` | log destination (`ciamLogDestination`): `log-group`, its retention in days (`0`: never expires, which meets any obligation); a log route's `ciamLogDestinationRole` names it | ARN (`ciamProviderRef`) |
| `aws_cloudtrail` | audit trail (`ciamAuditTrail`, role `audit-trail` unless tagged): `organization` or `account` (`is_organization_trail`), the activity its event selectors record (basic or advanced; none: `control-plane`), all regions, integrity validation, and where its records go (`ciamLogDestinationRole`: the role of its bucket's object store, or of its CloudWatch log group). The CLI's `cloudtrail describe-trails`, `get-event-selectors` and `list-tags`, and CloudFormation's `AWS::CloudTrail::Trail`, are read the same way | ARN (`ciamProviderRef`) |
| `aws_guardduty_detector` (+ `_feature`, legacy `datasources`, `aws_guardduty_organization_configuration`), `aws_inspector2_enabler`, `aws_config_configuration_recorder` (+ its delivery channel, `aws_config_retention_configuration`), `aws_securityhub_account` (+ `aws_securityhub_standards_subscription`, `_organization_configuration`) | security service (`ciamSecurityService`, role its kind unless tagged): kind, the areas a detector's features or Inspector's resource types watch, the standards and AWS baselines subscribed, organization or account, retention, and where findings go (`ciamFindingsRole`: the SNS topic or log group an EventBridge rule for the service's findings targets, or the recorder's delivery bucket). An SNS topic findings go to is an alert channel | ARN, or `inspector2:`/`config-recorder:` ids |
| `aws_cloudwatch_metric_alarm` | alarm the cloud runs (`ciamAlarmBinding`): what it evaluates (`ciamMetric`: namespace and metric, or `metric query`), the topics it notifies (`ciamNotifies`), the alert rule it realizes (`ciamRealizes`, its tag `Realizes`). Its binding role is its tag `Role` or `BindingRole`, else `alarm-<Realizes>`; untagged alarms are named, not recorded | ARN (`ciamProviderRef`) |
| `aws_synthetics_canary` | synthetic check the cloud runs (`ciamCanaryBinding`): its `rate(...)` schedule as an interval (`5m`), the canary it realizes (tag `Realizes`); binding role as for alarms, else `canary-<Realizes>` | ARN (`ciamProviderRef`) |
| `aws_iam_role` (+ `aws_iam_role_policy`, `aws_iam_role_policy_attachment`, `aws_iam_policy`) | identity binding (`ciamIdentityBinding`, kind `role`, `federated` when an OIDC provider may assume it): who may assume it (`ciamTrustedBy`: a service, `<issuer URL> <subject>` per OIDC subject, a principal ARN), the grants and denials of its inline and attached policies, its permissions boundary's allows as its ceiling (`ciamBoundary`); role from its tag `Role` | role ARN, else its name |
| resource policies: `aws_kms_key` `policy`, `aws_kms_key_policy`, `aws_s3_bucket_policy`, `aws_secretsmanager_secret_policy` | grants (` (resource policy)`; `*` in a key or secret policy is that key or secret) and denials on the roles they name; a deny naming every principal applies to every role in the state; grants to a role the state doesn't hold are named | (on the identity) |
| `aws_ssoadmin_permission_set` (+ `_inline_policy`, `aws_ssoadmin_managed_policy_attachment`, `aws_ssoadmin_account_assignment`) | identity binding per group it is assigned to (kind `permission-set`; the group id as provider ref, as the landing zone names an operator's group): the grants of its policies; role from the permission set's tag `Role` | group id |
| `aws_organizations_policy` (`SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY`; from the management account's state) | guardrail (`ciamGuardrail`, kind `service-control` / `resource-control`): its denies (`ciamDenial`), its allows as a ceiling unless it allows everything (`FullAWSAccess`), what it prevents (`ciamDenies`) by the statement ids the renderer writes (`DenyOutsideRegion`, …); role from its tag `Role` | policy ARN |
| `data aws_ssoadmin_instances`, `aws_ec2_instance_connect_endpoint` | access path (`ciamAccessPath`): `workforce-sso` (role `access-workforce-sso`, the identity store as `ciamTrustedBy`), `session` (tag `Role`, else `access-session`) | ARN |

**What changes.** What the state says replaces the record's values for what it covers; everything else on the entry (owner, rotation dates, consumers, …) is kept. An entry of a kind the state reports but that the state lacks is named ("in the record but not in what the cloud reports"); kinds the state doesn't report at all are left alone. An overlay environment leaves the bindings it inherits to its base.

**Roles of new resources.** A resource the record doesn't have is added only when a role is known, because every binding needs one (`ciamBindingRole`, which migrations, required-role checks and renderers match on) and a role can't be guessed. The role comes from, in order:

1. the resource's tag `Role` (or `BindingRole`); a VPC without one is the `network`;
2. the environment's role map, `roles.json` beside the state: a JSON object of provider references (IDs, ARNs) or names to roles. This is the route for what carries no tags: inline security group rules (by rule name) and resources tagged by another team.

```json
{"subnet-0a1b2c3d": "subnet-admin", "fw-admin": "fw-admin"}
```

The importer fills in everything else from the state. Where the source names a role itself, the source's is kept; map entries that disagree with it or match nothing, and a malformed map, are named in the notices. Without a role the resource is named in the notices with what the state says about it. A new entry also needs its class's required attributes (a server its hostname and subnet, a service its DNS name, target role and ports, …); one that lacks them is named.

**Named, not recorded:** resource types that hold secret values or aren't modeled yet (`aws_secretsmanager_secret_version`, `aws_ssm_parameter`, `random_password`, `tls_private_key`, `aws_iam_access_key`), counted by type.

**Named, not recorded (security group rules):** a port range (`from_port` ≠ `to_port`) and a rule for all ports (`-1`, or `0`–`65535`), since `ciamPort` holds single ports; a source that isn't an IPv4 range (an IPv6 range, a referenced security group, a prefix list, the group itself). The rule's single IPv4 ports and sources are still recorded; a rule with no IPv4 source records nothing. The same from Terraform state, CLI output and CloudFormation.

**Skipped without a notice:** protocols other than `tcp`/`udp` (`ciamProtocol` stays unset) and egress rules.

**Identities, guardrails and access paths.** An identity binding is matched by its provider ref, else by the identity's short name (an IAM role's name, a resource ID's last segment, a service account's account id), so a record that names an identity by its short name takes the full reference from the state. Grants, denials and ceilings are written in the cloud's own terms (`ciamGrant`, `ciamDenial`, `ciamBoundary`: `<action or role> on <resource>`, then ` (resource policy)`, ` (if <condition>)`, ` (eligible)`; parentheses in a condition become brackets; `p!a|b` is what `p` matches but `a` and `b`, `!a|b` every action but those), and the planner evaluates them (see Access below). Groups, users and other principals the state names without a role (a role map names them, as for any resource) are counted in one notice, not listed one by one. A policy outside the state (an AWS managed policy such as `ReadOnlyAccess`, a boundary kept elsewhere) is named: its grants aren't read, so a permission only it gives reads as not granted; `aws iam get-account-authorization-details` holds every policy's document.

**Secrets.** Secret values are never read: a Secrets Manager secret is recorded from its ARN alone, `aws_secretsmanager_secret_version` is skipped, and the reader drops whatever the state marks sensitive before anything sees it.

### The edge, read back

What the edge runs comes back in the edge domain's terms (`opsdir_adapter_aws.edge_inventory`), so the planner compares it with the policies (only what someone chose: AWS's defaults are left out, the TLS mode always kept):

| AWS resource | Record entry |
|---|---|
| `aws_lb` (+ listeners, target groups) | facts on its service name (`ciamEdgeFact`): `tls-mode` (passthrough, terminate, reencrypt from the listeners' and target groups' protocols), `tls-min` / `tls-profile` (the listener's ELB policy through the TLS table; an unknown policy is a `ciamEdgeSetting`), an HTTP(S) `health` check, `stickiness`, `drain` (not 300), an ALB's `idle-timeout` (not 60) |
| `aws_route53_record` aliasing the load balancer or its CloudFront distribution | the service name's DNS name, `ciamTtlSeconds` (60: the load balancer's), `ciamRoutingPolicy` / `ciamRoutingWeight`; a non-alias record answering for another environment of a routed name is named, not recorded |
| `aws_wafv2_web_acl` (+ association, IP sets) | edge service `waf` (role `waf-<the fronted service's role>`): `waf-mode`, `waf-category` (managed groups the WAF table knows), `rate-limit` (rules named `rate-<kind>`), `ip-rule`, `geo-rule`; other rules and groups as settings |
| `aws_shield_protection` (+ automatic response) | edge service `ddos`: `network-advanced`, `application-advanced` |
| `aws_cloudfront_distribution` | edge service `cdn` of the load balancer it has for origin; its minimum protocol as a setting |
| `aws_route53_zone`, other `aws_route53_record`s, `aws_route53_resolver_rule` (FORWARD) | DNS zones (public; private with VPC associations), records (name, type, TTL, values, routing), forwarders; roles `zone-<name>`, `record-<type>-<name>`, `forwarder-<domain>` unless tagged |

An ALB's security group rules and the servers' rules admitting it belong to the load balancer: left out, like a firewall rule naming another security group.

### The network depth, read back

What the network carries beyond VPCs, subnets and security groups comes back in the network domain's terms (`opsdir_adapter_aws.network_inventory`; the CLI and CloudFormation readers normalize to the same Terraform names: `cli_network.py`, `cloudformation_network.py`). Matching is by provider ref; a new one needs its tag `Role`.

| AWS resource | Record entry |
|---|---|
| `aws_route_table` (+ `aws_route`, `_association`, `aws_main_route_table_association`, `aws_default_route_table`) | route table: routes `<destination> <kind> <target>` (a CIDR or prefix list; the target a NAT gateway, transit gateway, peering, VPN gateway, gateway endpoint, a Network Firewall's endpoint (kind `firewall`, its firewall policy the target), a Gateway Load Balancer endpoint, an interface or appliance), read as the role of the binding with that ref when the source reports it; the associated subnets; whether it is the main table. The CLI's local route and default ACL rule are left out, as state leaves them |
| `aws_network_acl` (+ `_rule`, `_association`, `aws_default_network_acl`) | network ACL: rules `<number> <allow\|deny> <in\|out> <protocol> <ports> <cidr>` in number order (IPv6 entries named, not recorded); the subnets |
| `aws_vpc_endpoint` (Interface, Gateway) | private endpoint: what it reaches (the service name's last part), kind, subnets, private DNS; its security groups are the endpoint's, left out of the firewall rules. Gateway Load Balancer endpoints are routing, not private endpoints |
| `aws_vpc_endpoint_service` (+ `_allowed_principal`) | endpoint service: the service name of the load balancer it exposes, its name for consumers, the principals allowed, acceptance |
| `aws_networkfirewall_rule_group` with a domain list (+ `_firewall_policy`, `_firewall`) | egress firewall (proxy kind `firewall`): the sites its `ALLOWLIST` domain lists allow (`.example` as `*.example`) under its firewall policy (the rule group's tag `FirewallPolicy`, as rendered, else the policy referencing it). A domain list holds no ports: the record's sites with ports (`ocsp.example:80`) are the same as the list's without them |
| `aws_vpc_peering_connection`, `aws_ec2_transit_gateway_vpc_attachment`, `aws_vpn_connection` (+ customer and VPN gateways) | interconnect depth: kind, whether the other side accepted, a VPN's peer gateway and BGP numbers; a peering's other side is the environment whose network binding is one of its two VPCs (the one that isn't this environment's), else its tag `PeerEnvironment: <cloud>/<env>`; a new link needs one of them |
| `aws_flow_log` | flow log: scope (VPC, subnet, interface, transit), the log group it writes to and its retention; untagged, a subnet's takes the role `flow-logs-<subnet role>` |
| `aws_nat_gateway` | its egress binding's `ciamNatAllocation`: `static` for a public NAT gateway's Elastic IP |

### Managed databases, read back

`opsdir_adapter_aws.databases` (the CLI normalizes to the same names: `cli_database.py`). Matching is by provider ref (the ARN); a new one needs its tag `Role`. Named fields only: `password` and `master_password` are never read.

| AWS resource | Record entry |
|---|---|
| `aws_db_instance` (not an Aurora member) + its `aws_db_subnet_group` and `aws_db_parameter_group` | database: engine, edition and service (`rds`), version (`engine_version_actual` over `engine_version`), endpoint (`address`) and port, size, storage, zone (single-zone only), `zone-redundant` when `multi_az`, TLS from `rds.force_ssl` / `require_secure_transport` (else the engine's default), retention and point-in-time restore (on while backups are kept), deletion protection, the other parameters the group sets; the IPv4 ranges the rules on its security groups (`vpc_security_group_ids`) admit as `ciamSourceCidr` (those groups aren't read as firewall rules); its subnets, KMS key and master secret (`master_user_secret`) as the roles of those bindings; `ciamCopyRegion` from the region of each `aws_db_instance_automated_backups_replication` copying it (the CLI: `DBInstanceAutomatedBackupsReplications`) |
| `aws_rds_cluster` (+ `aws_rds_cluster_instance`, `aws_rds_cluster_parameter_group`) | the same with service `aurora`; `zone-redundant` when its instances are in more than one zone, the size its instances' |

### Disks and snapshot policies, read back

`opsdir_adapter_aws.volumes` (the CLI normalizes to the same names: `cli_volume.py`). Volumes and snapshot policies are matched by name; a new one needs its tag `Role`.

| AWS resource | Record entry |
|---|---|
| `aws_ebs_volume` (+ `aws_volume_attachment`), grouped by tag `Volume` | data volume of the role its instances run: the most common size, class, IOPS and throughput (a server whose disk differs in size is named), encrypted only when all are; its KMS key and the snapshot policy whose target tag its `SnapshotPolicy` tag matches as roles |
| `aws_instance` `root_block_device` tagged `Volume` | the role's boot volume, the same way. An untagged root disk that isn't encrypted is named |
| `aws_dlm_lifecycle_policy` (enabled) | snapshot policy: interval in hours, start time, retention in days (weeks, months, years converted; by count: named, not read), copy regions, consistency `crash` |

An EBS volume attached to one of the environment's instances without a `Volume` tag is named: which of the record's volumes it is can't be told.

### Backup vaults and plans, read back

`opsdir_adapter_aws.backups` (the CLI normalizes to the same names: `cli_backup.py`). Vaults and plans are matched by name: their tag `Name` (what this adapter renders), else the resource's own; a new one needs its tag `Role`.

| AWS resource | Record entry |
|---|---|
| `aws_backup_vault` (+ `aws_backup_vault_lock_configuration`) | backup vault: its KMS key as its key role, its lock (`compliance` when the lock has a grace, `governance` otherwise) and minimum retention days |
| `aws_backup_plan` (+ its `aws_backup_selection`s) | backup plan, from its first rule: every hours and start time (from the cron expressions this adapter writes; another is named), start window in hours, retention in days, the regions its copies go to, its vault; the roles its selections' `Role` tags choose |

A plan with several rules is named (the first is read); a selection choosing resources by ARN rather than by tag is named (what it protects isn't read).

## Reading an environment from the AWS CLI

Where there is no Terraform state (or to check it against what the account actually runs), `aws/cli-inventory` reads the JSON the AWS CLI prints. Collect it once per environment, into one folder per `<cloud>/<env>`:

```bash
out=export/source/prod; VPC=vpc-0a1b2c3d4e5f67890              # the environment's VPC scopes what is read
mkdir -p $out/target-health $out/route53 $out/kms $out/lambda-tags $out/event-targets
aws ec2 describe-vpcs --vpc-ids $VPC                                   > $out/vpcs.json
aws ec2 describe-subnets --filters Name=vpc-id,Values=$VPC             > $out/subnets.json
aws ec2 describe-instances --filters Name=vpc-id,Values=$VPC           > $out/instances.json
aws ec2 describe-security-groups --filters Name=vpc-id,Values=$VPC     > $out/security-groups.json
aws ec2 describe-security-group-rules                                  > $out/security-group-rules.json   # optional: tags per rule
aws ec2 describe-nat-gateways --filter Name=vpc-id,Values=$VPC         > $out/nat-gateways.json
aws elbv2 describe-load-balancers                                      > $out/load-balancers.json
aws elbv2 describe-target-groups                                       > $out/target-groups.json
for lb in $(aws elbv2 describe-load-balancers --query 'LoadBalancers[].LoadBalancerArn' --output text); do
  aws elbv2 describe-listeners --load-balancer-arn "$lb"               > "$out/listeners-${lb##*/}.json"
  aws elbv2 describe-tags --resource-arns "$lb"                        > "$out/lb-tags-${lb##*/}.json"
done
for tg in $(aws elbv2 describe-target-groups --query 'TargetGroups[].TargetGroupArn' --output text); do
  name=${tg#*targetgroup/}; name=${name%%/*}                           # the file is named by the target group
  aws elbv2 describe-target-health --target-group-arn "$tg"            > "$out/target-health/$name.json"
done
for zone in $(aws route53 list-hosted-zones --query 'HostedZones[].Id' --output text); do
  aws route53 list-resource-record-sets --hosted-zone-id "${zone##*/}" > "$out/route53/${zone##*/}.json"   # named by zone ID
done
aws secretsmanager list-secrets                                        > $out/secrets.json
for key in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  aws kms describe-key --key-id "$key"                                 > "$out/kms/key-$key.json"
  aws kms get-key-rotation-status --key-id "$key"                      > "$out/kms/rotation-$key.json"
done
aws s3api list-buckets                                                 > $out/buckets.json
aws lambda list-functions                                              > $out/functions.json
for fn in $(aws lambda list-functions --query 'Functions[].FunctionArn' --output text); do
  aws lambda list-tags --resource "$fn"                                > "$out/lambda-tags/${fn##*:}.json"   # named by function
done
aws events list-rules                                                  > $out/rules.json
for rule in $(aws events list-rules --query 'Rules[].Name' --output text); do
  aws events list-targets-by-rule --rule "$rule"                       > "$out/event-targets/$rule.json"     # named by rule
done
for s in $(aws scheduler list-schedules --query 'Schedules[].Name' --output text); do
  aws scheduler get-schedule --name "$s"                               > "$out/schedule-$s.json"
done
for p in $(aws codepipeline list-pipelines --query 'pipelines[].name' --output text); do
  aws codepipeline get-pipeline --name "$p"                            > "$out/pipeline-$p.json"
done
aws codebuild batch-get-projects --names $(aws codebuild list-projects --query 'projects' --output text) > $out/build-projects.json

# the edge: attributes, web ACLs and what they protect, Shield, CloudFront, hosted zones, resolver rules
mkdir -p $out/lb-attributes $out/tg-attributes $out/waf-resources
for lb in $(aws elbv2 describe-load-balancers --query 'LoadBalancers[].[LoadBalancerArn,LoadBalancerName]' --output text | tr '\t' ','); do
  aws elbv2 describe-load-balancer-attributes --load-balancer-arn "${lb%%,*}" > "$out/lb-attributes/${lb##*,}.json"
done
for tg in $(aws elbv2 describe-target-groups --query 'TargetGroups[].[TargetGroupArn,TargetGroupName]' --output text | tr '\t' ','); do
  aws elbv2 describe-target-group-attributes --target-group-arn "${tg%%,*}" > "$out/tg-attributes/${tg##*,}.json"
done
for acl in $(aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[].[Name,Id,ARN]' --output text | tr '\t' ','); do
  IFS=, read -r name id arn <<< "$acl"
  aws wafv2 get-web-acl --scope REGIONAL --name "$name" --id "$id" > "$out/web-acl-$name.json"
  aws wafv2 list-resources-for-web-acl --web-acl-arn "$arn" > "$out/waf-resources/$name.json"
done
for set in $(aws wafv2 list-ip-sets --scope REGIONAL --query 'IPSets[].[Name,Id]' --output text | tr '\t' ','); do
  aws wafv2 get-ip-set --scope REGIONAL --name "${set%%,*}" --id "${set##*,}" > "$out/ip-set-${set%%,*}.json"
done
aws shield list-protections > $out/protections.json 2>/dev/null || true      # needs Shield Advanced
aws cloudfront list-distributions > $out/distributions.json                  # CloudFront web ACLs: --scope CLOUDFRONT --region us-east-1
aws route53 list-hosted-zones > $out/hosted-zones.json
aws route53resolver list-resolver-rules > $out/resolver-rules.json

# the network depth: route tables, network ACLs, endpoints and endpoint services, links, flow logs, Network Firewall
aws ec2 describe-route-tables --filters Name=vpc-id,Values=$VPC                   > $out/route-tables.json
aws ec2 describe-network-acls --filters Name=vpc-id,Values=$VPC                   > $out/network-acls.json
aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=$VPC                  > $out/vpc-endpoints.json
aws ec2 describe-vpc-endpoint-service-configurations                             > $out/endpoint-services.json
mkdir -p $out/service-permissions
for s in $(aws ec2 describe-vpc-endpoint-service-configurations --query 'ServiceConfigurations[].ServiceId' --output text); do
  aws ec2 describe-vpc-endpoint-service-permissions --service-id "$s"            > "$out/service-permissions/$s.json"
done
aws ec2 describe-vpc-peering-connections                                         > $out/peering.json
aws ec2 describe-transit-gateway-vpc-attachments --filters Name=vpc-id,Values=$VPC > $out/tgw-attachments.json
aws ec2 describe-vpn-connections                                                 > $out/vpn-connections.json
aws ec2 describe-customer-gateways                                               > $out/customer-gateways.json
aws ec2 describe-vpn-gateways                                                    > $out/vpn-gateways.json
aws ec2 describe-flow-logs                                                       > $out/flow-logs.json
for arn in $(aws network-firewall list-rule-groups --scope ACCOUNT --query 'RuleGroups[].Arn' --output text); do
  aws network-firewall describe-rule-group --rule-group-arn "$arn"                > "$out/rule-group-${arn##*/}.json"
done
for arn in $(aws network-firewall list-firewall-policies --query 'FirewallPolicies[].Arn' --output text); do
  aws network-firewall describe-firewall-policy --firewall-policy-arn "$arn"      > "$out/firewall-policy-${arn##*/}.json"
done
for arn in $(aws network-firewall list-firewalls --query 'Firewalls[].FirewallArn' --output text); do
  aws network-firewall describe-firewall --firewall-arn "$arn"                    > "$out/firewall-${arn##*/}.json"
done

# managed databases: instances, Aurora clusters, subnet groups and the parameters set on their groups (only user-set
# values are read; a group's output must be saved under its name, since the output doesn't say)
aws rds describe-db-instances                                                    > $out/rds-instances.json
aws rds describe-db-clusters                                                     > $out/rds-clusters.json
aws rds describe-db-subnet-groups                                                > $out/rds-subnet-groups.json
mkdir -p $out/db-parameters $out/db-cluster-parameters
for g in $(aws rds describe-db-parameter-groups --query 'DBParameterGroups[?!starts_with(DBParameterGroupName, `default.`)].DBParameterGroupName' --output text); do
  aws rds describe-db-parameters --db-parameter-group-name "$g" --source user     > "$out/db-parameters/$g.json"
done
for g in $(aws rds describe-db-cluster-parameter-groups --query 'DBClusterParameterGroups[?!starts_with(DBClusterParameterGroupName, `default.`)].DBClusterParameterGroupName' --output text); do
  aws rds describe-db-cluster-parameters --db-cluster-parameter-group-name "$g" --source user > "$out/db-cluster-parameters/$g.json"
done

# disks and snapshot policies: the volumes (root volumes included: describe-instances says which they are) and each
# Lifecycle Manager policy (saved under dlm-policies/: its output's key is IAM get-policy's too)
aws ec2 describe-volumes                                                         > $out/volumes.json
mkdir -p $out/dlm-policies
for p in $(aws dlm get-lifecycle-policies --query 'Policies[].PolicyId' --output text); do
  aws dlm get-lifecycle-policy --policy-id "$p"                                  > "$out/dlm-policies/$p.json"
done

# AWS Backup: the vaults, each plan and its selections, and the tags of each vault and plan (list-tags doesn't name its
# resource: saved under backup-tags/ by name)
aws backup list-backup-vaults                                                    > $out/backup-vaults.json
mkdir -p $out/backup-plans $out/backup-tags
for v in $(aws backup list-backup-vaults --query 'BackupVaultList[].BackupVaultName' --output text); do
  aws backup list-tags --resource-arn "$(aws backup describe-backup-vault --backup-vault-name "$v" --query BackupVaultArn --output text)" \
                                                                                 > "$out/backup-tags/$v.json"
done
for p in $(aws backup list-backup-plans --query 'BackupPlansList[].BackupPlanId' --output text); do
  aws backup get-backup-plan --backup-plan-id "$p"                               > "$out/backup-plans/$p.json"
  name=$(aws backup get-backup-plan --backup-plan-id "$p" --query BackupPlan.BackupPlanName --output text)
  aws backup list-tags --resource-arn "$(aws backup get-backup-plan --backup-plan-id "$p" --query BackupPlanArn --output text)" \
                                                                                 > "$out/backup-tags/$name.json"
  for s in $(aws backup list-backup-selections --backup-plan-id "$p" --query 'BackupSelectionsList[].SelectionId' --output text); do
    aws backup get-backup-selection --backup-plan-id "$p" --selection-id "$s"    > "$out/backup-plans/$p-$s.json"
  done
done

# the control-plane audit trail: trails (a multi-region trail listed from several regions is read once), each one's
# event selectors and tags (both name their trail)
aws cloudtrail describe-trails                                                    > $out/trails.json
mkdir -p $out/cloudtrail
for arn in $(aws cloudtrail describe-trails --query 'trailList[].TrailARN' --output text); do
  name=${arn##*/}
  aws cloudtrail get-event-selectors --trail-name "$arn"                         > "$out/cloudtrail/$name-selectors.json"
  aws cloudtrail list-tags --resource-id-list "$arn"                             > "$out/cloudtrail/$name-tags.json"
done

# IAM: roles and policies (AWS managed ones included), key and bucket policies, Identity Center, control policies
mkdir -p $out/key-policy $out/bucket-policy $out/sso-inline $out/sso-managed $out/org
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
aws iam get-account-authorization-details                              > $out/iam.json
for key in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  aws kms get-key-policy --key-id "$key" --policy-name default         > "$out/key-policy/$key.json"       # named by key ID
done
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  aws s3api get-bucket-policy --bucket "$b"                            > "$out/bucket-policy/$b.json" || rm -f "$out/bucket-policy/$b.json"
done
for s in $(aws secretsmanager list-secrets --query 'SecretList[].ARN' --output text); do
  aws secretsmanager get-resource-policy --secret-id "$s"              > "$out/secret-policy-${s##*:}.json"
done
SSO=$(aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text)
for ps in $(aws sso-admin list-permission-sets --instance-arn "$SSO" --query 'PermissionSets' --output text); do
  name=$(aws sso-admin describe-permission-set --instance-arn "$SSO" --permission-set-arn "$ps" --query 'PermissionSet.Name' --output text)
  aws sso-admin describe-permission-set --instance-arn "$SSO" --permission-set-arn "$ps"            > "$out/sso-$name.json"
  aws sso-admin get-inline-policy-for-permission-set --instance-arn "$SSO" --permission-set-arn "$ps" > "$out/sso-inline/$name.json"
  aws sso-admin list-managed-policies-in-permission-set --instance-arn "$SSO" --permission-set-arn "$ps" > "$out/sso-managed/$name.json"
  aws sso-admin list-account-assignments --instance-arn "$SSO" --permission-set-arn "$ps" --account-id "$ACCOUNT" > "$out/sso-assignments-$name.json"
done
# signed in to the organization's management account (ACCOUNT still the environment's): its control policies
for p in $(aws organizations list-policies-for-target --target-id "$ACCOUNT" --filter SERVICE_CONTROL_POLICY --query 'Policies[].Id' --output text); do
  aws organizations describe-policy --policy-id "$p"                   > "$out/org/$p.json"
done                                                                   # and again with --filter RESOURCE_CONTROL_POLICY

opsdir import --dry-run aws/cli-inventory export/
opsdir import --change CHG-… aws/cli-inventory export/
```

File names are free except these: `describe-target-health`, `list-resource-record-sets`, `lambda list-tags`, `events list-targets-by-rule`, `describe-load-balancer-attributes`, `describe-target-group-attributes` and `list-resources-for-web-acl` don't say what they describe, so they are saved as `target-health/<target group name>.json`, `route53/<hosted zone ID>.json`, `lambda-tags/<function name>.json`, `event-targets/<rule name>.json`, `lb-attributes/<load balancer name>.json`, `tg-attributes/<target group name>.json` and `waf-resources/<web ACL name>.json`. The edge outputs (`WebACL`, `IPSet`, `Protections`, `DistributionList`, `HostedZones`, `ResolverRules`) are read as the edge from state is (opsdir_adapter_aws.cli_edge); record sets are read whole (TTLs, values, routing), a zone's own NS and SOA left out. Every other output is recognized by its top-level key (`Vpcs`, `Subnets`, `Reservations`, `SecurityGroups`, `SecurityGroupRules`, `NatGateways`, `LoadBalancers`, `TagDescriptions`, `Listeners`, `TargetGroups`, `SecretList`, `KeyMetadata`, `KeyRotationEnabled`, `Buckets`, `Functions`, `Rules`, `ScheduleExpression`, `pipeline`, `projects`); anything else is named and skipped. `roles.json` is the role map, never read as an output.

The outputs are read into the same resources as Terraform state (the mapping is shared), so the table above, what changes, roles and `roles.json` apply unchanged. Separately listed rules (`describe-security-group-rules`) replace the inline permissions of their groups. What the CLI adds: a secret's last rotation (`ciamLastRotated`) and that rotation is off (`ciamAutoRotate: FALSE`), which state doesn't hold. Differences in scope:

- **Network resources** (subnets, instances, security groups, load balancers, NAT gateways) are read only inside the VPCs `describe-vpcs` lists; others are counted. Terminated instances are skipped.
- **Account-wide listings** (secrets, KMS keys, buckets, functions, pipelines, build projects) report far more than one environment: the ones the record doesn't have and nothing names a role for are counted with a few examples, not listed one by one. Name the ones that belong in `roles.json` (by ARN or name). Only customer managed KMS keys are read; AWS managed keys are counted.
- **IAM** is read as from Terraform state (`opsdir_adapter_aws.cli_iam`): `get-account-authorization-details` gives every role (trust, inline and attached policies, boundary, tags) and every policy's default version, AWS managed policies included, so a permission they give is read (state can't); its users and groups are counted. `get-key-policy` and `get-bucket-policy` don't say whose policy they print: save them as `key-policy/<key id>.json` and `bucket-policy/<bucket>.json` (a policy saved elsewhere is named); the inline and managed policies of a permission set as `sso-inline/<name>.json` and `sso-managed/<name>.json`. `list-secrets` gives each secret's `KmsKeyId`, its key's role then recorded (`ciamEncryptedByRole`). Control policies come from the management account, for the environment's account.
- `list-secrets` never returns secret values, and nothing reads `get-secret-value` output. Disabled EventBridge rules and Scheduler schedules are counted, not read. A function's environment variables are never read.

### What a cloud evaluator says

The renderer writes `access/evaluate.sh` beside the Terraform when an identity the environment binds (by its provider ref) has principals acting as it: for each of their permissions it asks the IAM policy simulator (`aws iam simulate-principal-policy --policy-source-arn <role ARN> --action-names … --resource-arns …`): the permission's actions on its binding's resource and saves the answer as `evaluations/<identity>/<verb>__<role>[.<n>].json` (n numbers a permission's parts: a secret and the key that encrypts it). Run it where the CLI is signed in, into the environment's export folder, then import as above:

```bash
sh out/aws-prod/access/evaluate.sh export/source/prod
opsdir import --dry-run aws/cli-inventory export/
```

Each answer is recorded on the identity as `ciamEvaluated` (`<verb> <role>: allowed|denied|unknown (aws-simulator <date of the import>)`, the worst of a permission's parts), and the planner prefers it over evaluating the recorded policies. Decisions: any `explicitDeny`, or an action not `allowed`, is denied; a missing context value (`MissingContextValues`) is unknown. The simulator evaluates identity policies, one permissions boundary and SCPs, and resource policies only when supplied; not RCPs; it can differ from live access (VPC endpoint policies, session policies). An identity recorded by its role name only can't be simulated (the simulator needs the ARN); a secret recorded without its suffix is named `<arn>-??????`: put its full ARN in the record (an import does) for the simulator to match it.

## Reading an environment from its CloudFormation stacks

Where the environment is managed with CloudFormation, `aws/cloudformation` reads its stacks: one folder per stack under `<cloud>/<env>/` (any folder name), holding what the CLI prints for the stack and its template:

```bash
for stack in ciam-prod-network ciam-prod-app; do
  d=export/source/prod/$stack; mkdir -p $d
  aws cloudformation describe-stacks --stack-name $stack       > $d/stack.json       # parameters, region, account
  aws cloudformation list-stack-resources --stack-name $stack  > $d/resources.json   # physical IDs
  aws cloudformation get-template --stack-name $stack          > $d/template.json    # or copy the template file itself
done
opsdir import --dry-run aws/cloudformation export/
```

The template says what each resource is declared with; the stack's resources give the IDs the record matches on (`vpc-…`, `i-…`, ARNs), so a stack without its resource listing is read for nothing and named, and so is a folder without a template. Values are resolved from the stack's parameters (else the template's defaults), pseudo parameters (`AWS::Region`, `AWS::AccountId`, … from the stack ID) and physical IDs: `Ref`, `Fn::Sub`, `Fn::Join`, `Fn::Select`, and `Fn::GetAtt` where it links resources (a Route 53 alias to its load balancer, a NAT gateway or load balancer to its Elastic IP's address). JSON and YAML templates are read, short tags (`!Ref`, `!Sub`, `!GetAtt`, …) included.

What the stacks declare is read into the same resources as Terraform state (the mapping is shared: VPCs, subnets, instances, security groups and ingress rules, load balancers with listeners and target groups, alias records, Secrets Manager secrets with rotation schedules, KMS keys, S3 buckets, NAT gateways, Lambda functions, EventBridge rules and their targets (`Fn::GetAtt X.Arn` resolves to X's ARN), Scheduler schedules, CodePipeline pipelines, CodeBuild projects, CloudTrail trails (with their event selectors); ARNs built from the stack's partition, region and account), so the table above, roles and `roles.json` apply unchanged. A KMS key's rotation is off unless the template sets `EnableKeyRotation`, as in CloudFormation. Named in the notices:

- functions that aren't evaluated (`Fn::If`, `Fn::ImportValue`, `Fn::FindInMap`, `Fn::Cidr`, …), counted per stack: the attributes computed with them keep the record's values;
- resources without a physical ID (not created, failed, deleted) and resource types not read, counted;
- values only the running resource knows that the template doesn't declare (an instance's address when the template leaves it to AWS) keep the record's values.

A secret's `SecretString`, `SecretBinary` and `GenerateSecretString` are dropped before anything is resolved; `NoEcho` parameters come back from `describe-stacks` masked.

## The region list (a provider prerequisite)

The record's region catalog (core `estate` domain: residencies and the planner's region checks) needs AWS's own list of regions. The adapter declares it as the prerequisite `aws-regions` (`opsdir prerequisites` shows whether it is met) and reads it with `aws/regions`: the output of `aws ec2 describe-regions --all-regions --output json`, every region of the partition your credentials are in, whether or not the account opted in.

```sh
opsdir import aws/regions --run --change CHG-…         # runs the AWS CLI under your own login; opsdir never sees the credentials
aws ec2 describe-regions --all-regions --output json > regions.json
opsdir import aws/regions regions.json --change CHG-…  # or run it yourself (elsewhere) and import the file
```

A region open only to accounts that opt in (`OptInStatus` `opted-in` or `not-opted-in`) is recorded `opt-in`, the rest `available`; a region whose endpoint is under `amazonaws.com` is in the `public` partition. The list gives no display names or geography: add them to the catalog yourself, a refresh keeps them. A refresh adds new regions, shows changed details as conflicts to take or keep, and keeps a region AWS stops listing, marked `not-listed`. An export listing no region is refused.

## Landing zone

What the platform needs from the organization rather than its own Terraform is rendered per environment into `terraform/landing-zone/` (its own root: `providers.tf`, `main.tf`) for whoever keeps the landing zone: the header names them (the owners of the environment's guardrails, else of its cloud, else of the environment) and the MANIFEST marks the files `landing-zone`. Nothing is rendered when the environment needs nothing from one. When the target lacks a guardrail's prevention or a way in the source has, the planner drafts a request to that owner (`requests/<owner>.md`).

| From the record | Rendered as |
|---|---|
| Deployer principals whose identity binding trusts an OIDC issuer (`ciamTrustedBy`: `<issuer URL> <subject>`, a CI pipeline) | `aws_iam_openid_connect_provider` per issuer (audience `sts.amazonaws.com`), and per deployer an `aws_iam_role` assumable only with that pipeline's tokens (`sts:AssumeRoleWithWebIdentity`, `<host>:aud` and `<host>:sub` pinned) with its least-privilege policy |
| Operator principals whose identity binding names a group (`ciamIdentityKind` group or permission-set; the group id as provider ref) | IAM Identity Center: `aws_ssoadmin_permission_set` (4-hour sessions), its permissions as `aws_ssoadmin_permission_set_inline_policy`, `aws_ssoadmin_account_assignment` to the group in `var.account_id` |
| Guardrails' denials (`ciamDenies`) | One `aws_organizations_policy` (service control policy) per guardrail attached to `var.guardrail_target_id` (an OU or account): `region-escape` (AWS's region-control statement: global services exempt; the regions it allows are the cloud's region and those the environment's residency allows, core `estate` domain), `audit-log-disable` (CloudTrail changes on every trail; creation allowed), `service-account-keys` (`iam:CreateAccessKey`), `metadata-v1` (`ec2:RunInstances` without IMDSv2), `root-use` (the root user, bucket policies exempt), `key-deletion` (`kms:ScheduleKeyDeletion`, `DeleteAlias`, `DeleteCustomKeyStore`, `DeleteImportedKeyMaterial`). From AWS's examples (`aws-samples/service-control-policy-examples`) without their privileged-role exemptions. `public-storage` is a `# NOTE`: AWS's mechanism, the Organizations S3 policy type, needs the aws provider v6 |

### Network plumbing

The network's plumbing is the landing zone's, never the platform pipeline's: NAT egress, route tables, network ACLs, interconnects and flow logs always render into `terraform/landing-zone/network.tf`, with each root's inputs in its `providers.tf`. Plumbing whose `ciamManagedBy` names another party (a network team), and private endpoints and egress firewalls kept elsewhere, render into that party's own root, `terraform/landing-zone/<party>/`. A binding with a provider ref already exists, so it gets a Terraform `import` block to adopt it into the keeper's state. A binding without one is created, and the planner asks its keeper for it: one request per party (`requests/<party>.md`), each listing what isn't built yet and naming the root that holds everything they keep. The resources carry tags `Name` and `Role`, which the importers read back.

| From the record | Rendered as |
|---|---|
| NAT egress (`ciamEgress`) | `aws_nat_gateway`: public, its elastic IPs looked up by address (`data "aws_eip"`; secondary allocations for a range of up to 16), or private when its range is private; the public subnet is an input (`var.<egress>_subnet_id`) |
| Route table (`ciamRouteTable`) | `aws_route_table` with inline routes and `aws_route_table_association` per subnet role (import id `<subnet>/<table>`); the main table as `aws_default_route_table`. A route's target is the resource rendered in the same root (a NAT gateway, a peering, the VPN gateway), else the binding's provider ref, else the ref the route names. Inputs are used for what only the keeper knows: `var.transit_gateway_id`, a Network Firewall's endpoint (`var.<firewall>_endpoint_id`), a VPN gateway kept elsewhere. A route with no target to the internet goes to the VPC's internet gateway (`data "aws_internet_gateway"`). Local routes are implicit. Blackhole routes and `for <roles>` scopes are comments |
| Network ACL (`ciamNetworkAcl`) | `aws_network_acl` with its rules as `ingress` / `egress` entries on its subnets |
| Interconnect (`ciamInterconnect`, by `ciamLinkKind`) | `peering`: `aws_vpc_peering_connection` to the other environment's VPC (on AWS only, `peer_region` when it differs; the accepter is the other side's). `transit`: `aws_ec2_transit_gateway_vpc_attachment` on the environment's subnets. `vpn`: `aws_customer_gateway` (`ciamPeerGateway`, `ciamPeerAsn` or 65000), the VPC's `aws_vpn_gateway` (`ciamLocalAsn`, rendered once), `aws_vpn_connection` (BGP when the peer's ASN is recorded, else static routes to `ciamAcceptedCidr`). `dedicated` (Direct Connect), `hub`, and links whose kind isn't recorded are comments |
| Flow log (`ciamFlowLog`) | `aws_flow_log` (`ALL` traffic) on the VPC, each subnet or `var.transit_gateway_id`, to its log destination binding's ARN (CloudWatch Logs with `var.flow_logs_role_arn`, S3, Firehose). Retention is the log destination's; a comment names it. Interface and security-group scopes are comments |
| Private endpoint / egress firewall kept elsewhere | As the stack would render it (VPC endpoints; the Network Firewall domain-list rule group), in the keeper's root |

## Access: what permissions mean on AWS

Permissions are recorded neutrally (the core `access` domain: permission sets of `<verb> <binding role>`, held by principals); this table says what each verb on a binding of a class means here. The renderer grants the first alternative of each requirement. The planner (`opsdir plan`) judges each permission of an identity that records what the cloud gives it, following the cloud's evaluation order: **denied** when an unconditional explicit deny matches (`ciamDenial`: the identity's own policies, a resource's policy, a deny assignment or policy, or a guardrail's) or a ceiling doesn't allow it (`ciamBoundary`: a permissions boundary, a control policy's allows); **allowed** when an unconditional grant (`ciamGrant`) matches; **unknown** when the only grant is conditional (`(if …)`) or eligible but not active (`(eligible)`), or a conditional deny matches, since what decides it wasn't imported. A cloud evaluator's verdict recorded on the identity (`ciamEvaluated`) wins. In the target, a permission denied or not granted is a blocker (with what denies it) and an unknown one an action to verify; grants no permission explains, wildcard grants and escalations no permission explains are actions.

| Verb | Binding | IAM actions (each needed) |
|---|---|---|
| `read-secret` / `write-secret` | secret (`aws-sm://`) | `secretsmanager:GetSecretValue` / `secretsmanager:PutSecretValue` |
| `use-key` / `manage-key` | key (`aws-kms://`) | `kms:Decrypt`, `kms:Encrypt`, `kms:GenerateDataKey` / `kms:DescribeKey`, `kms:EnableKeyRotation`, `kms:PutKeyPolicy` |
| `read-storage` / `write-storage` | object store, backup targets included (`s3://`) | `s3:GetObject`, `s3:ListBucket` / `s3:PutObject` |
| `publish-stream` | stream: topic, queue, bus, data stream | `sns:Publish`, `sqs:SendMessage`, `events:PutEvents`, `kinesis:PutRecords` |
| `consume-stream` | stream: queue, data stream | `sqs:ReceiveMessage` + `sqs:DeleteMessage`, `kinesis:GetRecords` + `kinesis:GetShardIterator` |
| `write-logs` / `read-logs` | log destination (log group ARN) | `logs:PutLogEvents` + `logs:CreateLogStream` / `logs:GetLogEvents` + `logs:FilterLogEvents` |
| `manage` | secret / service name / compute group | `secretsmanager:PutSecretValue`, `UpdateSecret`, `RotateSecret`, `DeleteSecret` / `elasticloadbalancing:ModifyListener`, `RegisterTargets`, `DeregisterTargets` on the renderer's `ciam-<env>-<service>` load balancer and target groups + `route53:ChangeResourceRecordSets` on the zone / `autoscaling:UpdateAutoScalingGroup`, `SetDesiredCapacity` |

A granted pattern (`secretsmanager:*`, `arn:…:secret:ciam/*`) counts as granting. A secret recorded by its full ARN (as the importers record it: Secrets Manager's random six-character suffix included, recognized by a capital or a digit in it) is named by that ARN; one recorded without the suffix by `<arn>-??????`. **Escalation** actions: `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:DeleteRolePermissionsBoundary`, `kms:PutKeyPolicy`, `kms:CreateGrant`, `kms:ScheduleKeyDeletion`, `sts:AssumeRole`. A secret encrypted with a customer managed key (`ciamEncryptedByRole` names the key's role) also needs `kms:Decrypt` on that key to be read and `kms:GenerateDataKey` + `kms:Decrypt` to be written; the renderer grants them only through Secrets Manager in the environment's region (`kms:ViaService`). Denies follow AWS's evaluation logic, `NotAction` read as `!<actions>`; SCPs and RCPs come from the organization's management account (the importers read them when given that account's state or output). Evaluator: `aws iam simulate-principal-policy` (identity policies, one permissions boundary, SCPs; not RCPs; resource policies only when supplied) may be recorded per permission. Still unknown by design: conditions whose context isn't recorded (source VPC or IP, tags, MFA, time), session policies.

## References and vocabulary it owns

| Scheme | Form | Resolved |
|---|---|---|
| `aws-sm` | `aws-sm://<arn>` (Secrets Manager secret) | at run time: `aws secretsmanager get-secret-value --secret-id '<arn>' --query SecretString --output text` |
| `aws-kms` | `aws-kms://<arn>` (KMS key) | never: a key is referenced, its material stays in KMS |
| `aws-acm` | Certificate Manager certificate | not resolved |
| `s3` | `s3://<bucket>` (S3 bucket) | not resolved |

Values of `ciamCloudProvider` (`aws`) and `ciamCloudEnvironment` (`public`) are validated against this adapter. The store refuses AWS credential forms anywhere in the record: access key IDs (`AKIA…`, `ASIA…`) and secret access keys (`aws_secret_access_key = …`).

It adds no required roles, planner checks or schema of its own; the environment's product adapters say which roles it must bind.

## Known limits

- **Not yet run against a live account.** The Terraform and the importers follow the `hashicorp/aws` 5.x schema and the AWS CLI's output shapes; `terraform validate`/`plan` and an import from a real account are part of the testing plan (milestone 7.2, which starts on AWS).
- **Commercial partition only.** GovCloud and China (`aws-us-gov`, `aws-cn`) aren't in the vocabulary yet.
- **Port ranges** aren't recorded (`ciamPort` holds single ports): the importers name them; the renderer writes single ports only.
- **Services without an edge policy are TCP network load balancers.** With one, the renderer writes an application load balancer, its web ACL and Shield protection (see Edge); reading their listeners, TLS policies, certificates, web ACLs and Shield back comes with milestone 4.8's importers. An ALB's addresses are AWS's: a recorded frontend address isn't kept.
- **What the importers can't see:** egress rules, sources other than IPv4 CIDRs, key pairs, IAM in CLI output and CloudFormation stacks (Terraform state only, for now), Image Builder pipelines (`ciamImageBuild` is recorded by hand), autoscaling groups and EKS clusters, and the monitoring above (log groups, alarms, canaries, alert topics), in CLI output and CloudFormation stacks (Terraform state only, for now), KMS key protection, bucket encryption (4.10), CloudFront / WAF / API Gateway (edge importers, 4.8), databases in CloudFormation stacks (milestone 5.6; Terraform state and CLI output read them).
- **Databases someone else keeps** (`ciamManagedBy`) are named in a comment, not rendered into their keeper's root yet.
- **Compute groups' disks:** AWS doesn't render compute groups (launch templates) yet, so their volumes come from the record only; a launch template's block device mappings aren't read into volumes yet. EBS volumes and Lifecycle Manager policies in CloudFormation stacks come with milestone 5.6.

## Tests

`tests/test_aws_audit.py`: control-plane audit trails: an account trail the platform keeps rendered into its bucket (data events noted), trails kept by someone else or delivered to CloudWatch Logs named; the activity event selectors record (basic and advanced); a trail read back from state with its bucket's role, from the CLI (a multi-region trail listed twice read once; selectors and tags by ARN) and from a CloudFormation stack (its ARN from the stack's region and account).

`tests/test_aws_cli_edge.py`: the edge from CLI output: the same facts and edge services as from state (attributes by file name, web ACL rules in CLI shape, Shield, CloudFront, hosted zones, record sets with TTL and routing, resolver rules).

`tests/test_aws_edge_state.py`: the edge read back from state: an ALB's facts equal to the policy that would render it, its web ACL, Shield and CloudFront as edge services named by the service they front, zones, records, a routed name's TTL and routing with the other environment's answer named, Resolver rules, the load balancer's own rules left out.

`tests/test_aws.py` (registration, vocabulary, secret resolution), `tests/test_aws_state.py` (the state importer: round trip, drift, new tagged and untagged resources, secrets and sensitive attributes never read, overlays, layout, a new binding keeps its provider reference, security group roles from their instances), `tests/test_aws_cli.py` (the CLI importer: round trip, facts state lacks, VPC scoping, counted account-wide listings, files placed by name, rules listed separately, `roles.json` never read as output, timestamps), `tests/test_aws_cloudformation.py` (round trip over two YAML/JSON stacks, drift, `GetAtt` and parameter links, resources not created, unknown files, secrets never read, a folder without a template, the resolver), `tests/test_aws_compute.py` (an autoscaling group with its launch template, an untagged group, an EKS cluster with node groups and add-ons), `tests/test_aws_messaging.py` (an SES domain identity with SPF, DKIM and DMARC from its DNS; queues and buses as stream carriers), `tests/test_aws_observability.py` (a topic an alarm notifies as an alert channel, others as stream carriers; log groups with their retention, never-expire included; alarms and canaries with what they realize), `tests/test_aws_firewall_notices.py` (port ranges, all-ports rules and non-IPv4 sources named from state, CLI output and CloudFormation), `tests/test_aws_jobs.py` (functions, pipelines and build projects with their schedules from state, CLI output and CloudFormation; a tagged function placed as a job binding), `tests/test_aws_state_store.py` (state and CLI against Postgres: imported under an approved change, re-import changes nothing). The rendered Terraform is covered end to end by the showcase's golden outputs (`examples/showcase`, the source environment), and the importers by its cloud drift exports (`examples/showcase/exports/cloud/source`).

`tests/test_aws_cdn.py`: a distribution over the load balancer with a CloudFront web ACL and Shield, the us-east-1 certificate rule, an ALB behind CloudFront admitting only CloudFront.

`tests/test_aws_dns.py`: a failover pair answered from the primary's zone (alias, health-checked secondary), a weighted set, a name in someone else's zone, records in their zones, outbound forwarders as Resolver rules.

`tests/test_aws_edge.py`: the edge: TLS terms as ELB policies and back, an ALB with listener policy, ACM certificate, target groups (health, stickiness, draining) and security groups, the unbound certificate, the web ACL (address, country, rate-based rules on endpoint paths, managed groups, an exclusion out of scope), detect mode, account takeover's sign-in path, rate windows and header keys, Shield, a passthrough target group's tuning.

`tests/test_aws_cli_iam.py`: IAM from the CLI: authorization details (a URL-encoded trust, an AWS managed policy read), key and bucket policies by file, a secret's key, a control policy, Identity Center; the simulator's verdicts read back dated (the worst part, a missing context unknown, a role only simulated), preferred by the planner; the rendered `access/evaluate.sh`.

`tests/test_aws_iam.py`: IAM from state: a role's trust (service, OIDC subject), grants with conditions, NotAction denies, attached and managed policies, its boundary; key and bucket policies on the roles they name; permission sets by group; SCPs and RCPs with what they prevent; access paths; a secret's key by role; the planner's allowed, denied and unknown from what was imported.

`tests/test_aws_landing.py`: the landing zone: a deployer's OIDC trust and permissions, an operator group's access, the guardrails, the owner in the header, nothing rendered without need.

`tests/test_aws_access.py`: the AWS access table: a secret by its suffixed ARN or a pattern (not a longer name, not the bare ARN), objects in a bucket (reading also needs `s3:ListBucket`), a topic by stream kind, escalation actions. `tests/test_aws_identities.py`: a workload's IAM role, least-privilege policy and instance profile; notes for what can't be granted.

`tests/test_aws_network.py`: the network depth the stack keeps: an interface endpoint with its security group and private DNS, a gateway endpoint on its subnets' and the main route tables, what AWS has no endpoint for, an endpoint service on an L4 service's NLB and not an ALB, the egress firewall's domain list (web traffic only), what others keep named, nothing rendered without records.

`tests/test_aws_backups.py`: AWS Backup rendered (vault with its key and lock, compliance grace, plan with its cron, window, retention and copies to an input vault, selection by tag `Role`; what it can't render said; others' named) and read back from state and the CLI (lock mode, schedule, copies, protected roles, vault link; several rules or ARN selections named).

`tests/test_aws_volumes.py`: disks and snapshot policies rendered (the boot volume on the root block device, data volumes as EBS volumes with attachments and tags, unencrypted or unbound-key volumes as recorded and said, Lifecycle Manager policies with encrypted copies by the multi-region key's replica or an input, an interval it can't take and others' policies named) and read back from state and the CLI (volumes grouped by their Volume tag, root disks, policies linked by target tag, untagged disks, count-based and disabled policies and unencrypted roots named; dlm-policies/ outputs not read as IAM policies; render-to-state round trip).

`tests/test_aws_databases.py`: managed databases rendered (an RDS instance with its subnet, security and parameter groups, key, RDS-managed password and import block; the ranges it admits as ingress rules on its security group, the engine's port when none is recorded; TLS as a parameter where it isn't the default; Aurora with an instance per zone; one someone else keeps named) and read back from state and the CLI (Aurora members, user-set parameters only, SSM parameters and passwords never read, VPC scoping, render-to-state round trip; the rules on its security groups as its ranges, not firewall rules).

`tests/test_aws_network_state.py`: the network depth read back: route tables (targets as provider refs, a Network Firewall endpoint as the firewall, gateway endpoints, main table), network ACLs (IPv6 named), VPC endpoints and their security groups left out of the rules, endpoint services, the egress firewall's domain list under its policy, peering, transit and VPN depth, flow logs; the CLI (local route and rule 32767 left out) and CloudFormation reading the same.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `aws`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.


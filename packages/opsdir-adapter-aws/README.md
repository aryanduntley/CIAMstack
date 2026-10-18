# opsdir-adapter-aws

opsdir adapter for Amazon Web Services: Terraform for AWS environments, and CloudFormation translated from it on request; AWS Terraform state, AWS CLI output and CloudFormation stacks read back into the record; `aws-sm://` secret references.

**Applies to** environments whose cloud has `ciamCloudProvider: aws` (`ciamCloudEnvironment: public`), in the commercial partition or in AWS GovCloud (US): a cloud whose `ciamRegion` is `us-gov-*` is in the `aws-us-gov` partition (`account.py`: `govcloud`, `partition`), and what AWS doesn't offer there is written as a comment or rendered from the associated standard-partition account (CloudFront, below). A provider adapter: it renders and reads an environment's infrastructure bindings; products (PingDS, PingFederate, …) are other adapters.

**Depends on** `opsdir`, `opsdir-format-terraform` (HCL formatting, the Terraform state reader, the native translation engine), `opsdir-format-cloudformation` (the CloudFormation it renders) and `pyyaml` (CloudFormation templates it reads).

## What it renders

Per environment, `terraform/providers.tf` (`hashicorp/aws ~> 6.69`, the current release it is validated against, and `hashicorp/archive ~> 2.8` when it packages scripts; the same pins in the landing-zone roots; `region` from the cloud's `ciamRegion`; `use_fips_endpoint = true` when the cloud's `ciamFipsEndpoints` is TRUE (core `estate` domain); credentials come from the usual AWS environment, never from the record) and `terraform/main.tf`:

| From the record | Rendered as |
|---|---|
| The `network` binding: `ciamProviderRef` (the VPC ID) | `data aws_vpc` `main`: the landing zone owns the VPC |
| Subnet bindings: `ciamProviderRef` (the subnet ID) | `data aws_subnet` |
| One security group per server role | `aws_security_group` `ciam-<env>-<role>` in the VPC |
| Firewall rules | `aws_vpc_security_group_ingress_rule`, one per source CIDR and port (`ciamSourceCidr` × `ciamPort`), in the target role's group; protocol `ciamProtocol` (default `tcp`); description `<consumer or binding role> (<rule name>)`, the suffix the importers group rules back by |
| Servers | `aws_instance` (AMI `ciamImageRef`, `ciamInstanceSize`, the server's subnet, static `ciamPrivateIp`, its role's security group; encrypted root volume with the `disk-encryption` binding's KMS key, else an `UNBOUND` comment; tags `Name`, `Role`, `Hostname`, `Product`, `ManagedBy`) A server without `ciamImageRef` or `ciamInstanceSize` (both optional) gets `UNBOUND:<server>-image` / `-size` there (core `environment.recorded`; the planner's blocker in the target); without `ciamPrivateIp`, AWS assigns its address. |
| Compute groups (`ciamComputeGroup`, the core compute domain; milestone 5.8) | Per group the environment owns (one it inherits as an overlay is its base's: a comment): `data aws_ami` (its root device's name), an `aws_launch_template` (image, instance type, the role's instance profile and security group, `metadata_options` `http_tokens` `required`/`optional` when `ciamMetadataTokens` is recorded, the role's disks: see [Disks](#disks-and-snapshot-policies), instance tags `Name`, `Role`, `BindingRole`, `BootVolume`, `DataVolumes`) and an `aws_autoscaling_group` (`min_size`, `max_size`, `desired_capacity` when recorded, `vpc_zone_identifier` the subnets of its `ciamSubnetRole`s, the template's latest version, `target_group_arns` of the service names reaching its role with `health_check_type` `ELB`, tags `Role`, `BindingRole`, `ManagedBy` not propagated). Named `ciam-<env>-<group>`; an adopted one (its ARN, `ciamProviderRef`) keeps its name and is imported by it, a comment saying applying gives it the new launch template (its instances run it when next replaced). Missing image, size or subnets: `UNBOUND` values and the planner's blockers (`check_server_inputs`). The role's security group, instance profile and load balancer subnets count the groups' role as run here |
| Service names | Network load balancer, internal when `ciamFrontendIp` is private: one subnet mapping per subnet holding a target, the frontend address pinned in its subnet; a public one takes the Elastic IP allocation named by the service's `ciamProviderRef`. Per `ciamPort`: a TCP target group with a TCP health check, an attachment per server with the target role, a TCP listener. A Route 53 alias A record in `ciamDnsZoneRef` (target health evaluated). With no `ciamFrontendIp`, its exposure (`ciamExposure`, core `edge.exposure`) says internal or internet-facing and AWS assigns the addresses; with neither, an `UNBOUND:<role>-exposure` comment replaces the load balancer and record (the planner's blocker). The record's zone is `ciamDnsZoneRef`, else the zone binding the name falls in, else an `UNBOUND:<role>-dns-zone` comment. The importers record `ciamExposure` for a load balancer with no fixed address (an ALB, an NLB without an Elastic IP). A service whose role a traffic or protection policy names (core `edge` domain) is tuned or replaced by it: see [Edge](#edge-traffic-and-protection-policies) |
| Secret references (`aws-sm://<arn>`) | `data aws_secretsmanager_secret` per secret: metadata only, so a missing secret fails the plan and no value enters Terraform state (`aws_secretsmanager_secret_version` is never rendered) |
| The `backup-target` binding; the `pf-egress` binding | `data aws_s3_bucket` `ds_backups`; `data aws_nat_gateway` `pf_egress` (when it has a `ciamProviderRef`) |
| Workload principals (core `access` domain: kind `workload`, `ciamTargetRole` a server role here) | Per identity role (`ciamIdentityRole`; workload principals sharing one, such as PingFederate's engines and admin console, are one identity with their permissions merged): `aws_iam_role` EC2 may assume (named by its identity binding's provider ref, else `ciam-<env>-<server role>` of the first such principal), an inline `aws_iam_role_policy` with one statement per permission from the access table below (the binding's resource: a secret's ARN with its six-character suffix `-??????`, a key's ARN, `arn:aws:s3:::<bucket>/<prefix>*` and the bucket, a stream's ARN, a log group's ARN and `:*`), an `aws_iam_instance_profile` set on the role's instances; a permission that can't be granted (role unbound here, or no row) is a `# NOTE` |
| Control-plane audit trails (core `observability`: `ciamAuditTrail`) the platform team keeps | `aws_cloudtrail` into the S3 bucket of the object store its `ciamLogDestinationRole` names: `is_multi_region_trail` and `include_global_service_events` from `ciamAllRegions`, `enable_log_file_validation` from `ciamIntegrityValidation`, and its delivery policy: a bucket this render creates gets an `aws_s3_bucket_policy` letting CloudTrail check its ACL and write under `AWSLogs/<account>/` (and `AWSLogs/<organization>/` for an organization trail) with `bucket-owner-full-control`, for this trail only (`aws:SourceArn`); a bucket that exists already or someone else keeps gets a `# NOTE` naming those statements (its policy isn't ours to replace). Scope `organization` (milestone 5.7b): `is_organization_trail`, made from the organization's management account (provider `aws.management`, `ciamManagementRef`; without it a `# NOTE`) and kept with the landing zone (its keeper's root, or named and asked), the environment's own root saying who enables it. Data events (`ciamAuditEvents` `data-read` / `data-write`): advanced event selectors, one for management events when the trail records `control-plane` and one for S3 objects of each bucket its `ciamAuditResourceRole` names, else of every bucket the environment binds but the trail's own (logging writes to it would log themselves); databases have no data events and reading a secret is a Secrets Manager management event, both said in a comment. A log group it also streams to (`ciamAuditStreamRole`, kind `log-group`): `cloud_watch_logs_group_arn` and an IAM role CloudTrail assumes, allowed to create the trail's log streams (`<account>_CloudTrail_*`, and `<organization>_*`) and put events in them. A trail whose `ciamLogDestinationRole` is a log group, not a bucket, is a `# NOTE` (CloudTrail keeps its records in S3) |
| Security services (core `estate`: `ciamSecurityService`) the platform team keeps | threat-detection: `aws_guardduty_detector` (its foundational sources watch control-plane, identity and network) and an `aws_guardduty_detector_feature` per further area (storage `S3_DATA_EVENTS`; containers `EKS_AUDIT_LOGS` and `RUNTIME_MONITORING` with the EKS add-on and Fargate agent; compute `EBS_MALWARE_PROTECTION` and `RUNTIME_MONITORING` with the EC2 agent; databases `RDS_LOGIN_EVENTS`; applications `LAMBDA_NETWORK_LOGS`; key-vaults a comment). vulnerability-scanning: `aws_inspector2_enabler` (EC2, ECR, LAMBDA/LAMBDA_CODE from the areas; EC2 and ECR by default). config-recording: `aws_config_configuration_recorder` through AWS Config's service-linked role, its delivery channel to the bucket of the object store its `ciamFindingsRole` names (none: a `# NOTE`), `aws_config_retention_configuration` from `ciamRetentionDays` (30 to 2557), the recorder status. posture: `aws_securityhub_account` (consolidated control findings) and an `aws_securityhub_standards_subscription` per standard Security Hub has (`cis` v5.0.0, `nist-800-53-r5`, `nist-800-171-r2`, `pci-dss`; baselines `aws-foundational`, `aws-resource-tagging`; partition and region from data sources), the rest a comment. Findings of GuardDuty, Inspector and Security Hub go to the SNS topic or log group (`ciamProviderRef`) of the binding `ciamFindingsRole` names through an `aws_cloudwatch_event_rule` and target; those at or above `ciamIncidentSeverity` (high by default) also go to the incident process (`ciamIncidentRole`'s topic or log group) through a second rule filtering on severity: GuardDuty's numeric `detail.severity` (low 1, medium 4, high 7, critical 9 and up), Security Hub's `detail.findings.Severity.Label` and Inspector's `detail.severity` (the labels at or above it); AWS Config has no finding severity (a `# NOTE`). A service in every region (`ciamAllRegions`, milestone 5.7b) is copied to each region it may run in: the region catalog's available regions of the cloud's partition (`opsdir prerequisites`; without them a `# NOTE` and only the cloud's region), less those the environment's `region-escape` guardrail denies (nothing runs there); opt-in regions are named, not rendered (the catalog doesn't say the account opted in). Each copy (detector and features, enabler, hub and standards, recorder, channel, retention and status: `<name>_<region>`) goes through an aws provider of its own (`region_<region>`: Terraform providers have no `for_each`); IAM is global and made once; a regional recorder leaves global resource types to the cloud's region; Security Hub aggregates every region's findings in the cloud's region (`aws_securityhub_finding_aggregator`, `ALL_REGIONS`), where the findings routing is (without it, a comment says the other regions' findings stay there). Read back, a kind's copies are one service in every region. An organization-wide service (`ciamAuditScope` `organization`, decision 2777) is enabled by the organization and kept with the landing zone (its keeper's root, or named and asked): the management account (`aws.management`, `ciamManagementRef`) registers the security services' delegated administrator (`ciamSecurityAdminRef`: `aws_guardduty_organization_admin_account`, `aws_inspector2_delegated_admin_account`, `aws_securityhub_organization_admin_account`, `aws_organizations_delegated_administrator` for AWS Config), and the administrator's account (`aws.security_admin`) holds its own detector, enabler or hub and the organization configuration: GuardDuty enabling every member with the features its areas need (`auto_enable_organization_members` `ALL`), Inspector enabling its areas' scans, Security Hub in central configuration (a finding aggregator, a configuration policy enabling the standards, associated with the organization's root), an AWS Config organization aggregator through a role with `AWSConfigRoleForOrganizations`. In every region, GuardDuty's and Inspector's parts are made in each region (`management_<region>`, `security_admin_<region>`). The environment's own root keeps the findings and incident routing and a line naming who enables it (AWS Config also its own recorder: an organization can't turn members' recorders on this way); without the two accounts, a `# NOTE`. CloudFormation translates Security Hub's and AWS Config's organization types; GuardDuty's, Inspector's and the delegated administrator registration stay Terraform (no CloudFormation type) |
| Data discovery (core `estate`: `ciamDataDiscovery`) the platform team keeps | Amazon Macie: `aws_macie2_account` (enabled, findings every fifteen minutes); an `aws_macie2_custom_data_identifier` per own data type (`ciamCustomIdentifier` `name: regex`); per discovery a `SCHEDULED` `aws_macie2_classification_job` over the S3 buckets of the object stores `ciamScansRole` names, in the cloud's account (`ciamAccountRef`; none: a `# NOTE`), with those identifiers, `schedule_frequency` daily or weekly (`SUNDAY`) when `ciamRescanDays` is 1 or 7 (none recorded: weekly). Any other interval is never rounded: an `aws_scheduler_schedule` (`rate(1 day)`) invokes an `aws_lambda_function` (`python3.14`, `terraform/discovery/<function>/handler.py` zipped by the archive provider) that starts a `ONE_TIME` classification job over the same buckets and identifiers once that many calendar days have passed since the last successful one (`COMPLETE`, `lastRunErrorStatus` `NONE`; nothing while one is unfinished), with least-privilege roles (the function: create/describe classification jobs, list them, its own log group; the scheduler, trusted for the account's default schedule group: invoke the function only); its environment and tags (`Realizes`, `RescanDays`) let the reader recover the interval; stores that aren't S3 buckets are a comment (Macie examines S3 only). Findings go where `ciamFindingsRole` says through an EventBridge rule (`aws.macie`, `Macie Finding`), as the security services' do; detailed results to the bucket of the object store `ciamResultsRole` names (`aws_macie2_classification_export_configuration`, with that store's KMS key, which Macie requires; otherwise a `# NOTE`). In GovCloud nothing is rendered, only a comment: AWS's General Reference lists no GovCloud endpoint for Macie and its FedRAMP services-in-scope page marks it for US East/West only |
| Suppressions of findings (core `estate`: `ciamSuppression`, carrying out an exception) the platform team keeps | Named `exc-<exception>`: an `aws_securityhub_automation_rule` matching the suppression's `aws:securityhub:<control>` refs (`compliance_security_control_id` `EQUALS`) that sets workflow status `SUPPRESSED` and notes the exception and its expiry; an `aws_guardduty_filter` (`ARCHIVE`, `data aws_guardduty_detector`) for its `aws:guardduty:<type>` refs. Neither takes an expiry (a comment says when to remove it); GovCloud's unavailable automation rules for integrations, other providers' refs and suppressions someone else keeps are comments |
| Required roles without a binding | `# UNBOUND: required role …` |

The renderers build Terraform as data (`opsdir_format_terraform`: `TfBlock`s and top-level comments, a `TfFile` per file; milestone 5.5d) and the text is written once per file at the edge: `terraform.render_files(m, services)` gives `{path: TfFile | text}` (the Terraform roots as data, the scripts and configuration files they package as text) and `render()` is `written(render_files(...))`. The round trip can build its state from either.

Not rendered: the VPC, subnets, NAT gateways, buckets, Elastic IPs and Route 53 zones themselves (referenced, the landing zone creates them); KMS keys (referenced by ARN); egress security group rules; key pairs, IAM instance profiles and user data; application load balancers and TLS listeners (services are TCP pass-through).

## Who keeps what, and which root it renders in

The tables below say how each kind renders. Where it renders follows its keeper (milestone 5.7: the core's `governance.keepers` decides, `opsdir-format-terraform` places):

- What the stack keeps itself goes into the platform's root, `terraform/`.
- What a party keeps goes to that party: the party a binding's `ciamManagedBy` names, or the landing zone's owner for what is the landing zone's by nature (its identities and guardrails, the network's plumbing). If the party takes generated infrastructure (`ciamTakesGeneratedInfra` on its `ciamParty`), it gets a complete root: `terraform/landing-zone/` for the landing zone's owner (also when no party is recorded for it), `terraform/landing-zone/<party>/` for any other. A reference from one root to another becomes an input of the root that reads it and an output of the root that writes it. Files a keeper's root reads beside it (a canary's or function's source, a workflow's definition) are copied into that root.
- If the party doesn't take generated infrastructure, nothing of it is rendered: the platform's root names each entry in a comment (kept by whom, which addresses), and the planner drafts the request to them (`requests/<party>.md`).

This holds for every kind someone else may keep: network plumbing, the landing zone, databases, object stores, volumes, snapshot policies, backups, audit trails, monitors (alarms, log destinations, canaries), security services, suppressions, data discovery and budgets. A row below that says "the platform team keeps" describes how the kind renders; one someone else keeps renders the same way, in its keeper's root. `opsdir render --keeper PARTY` writes one keeper's root whatever its setting, and `--kind CLASS` / `--binding DN` write one slice in `terraform/slice/`, reading the rest through inputs.

## CloudFormation (`--target aws=cloudformation`)

Terraform is the default render target. A render can be written as AWS CloudFormation instead (`opsdir render CLOUD/ENV --target aws=cloudformation`; add `terraform` to keep the Terraform too). The choice is the person rendering's. Only an environment whose stack component records `ciamRenderTarget` binds it: a render may choose among the targets it holds, and another is refused, naming them. The templates are translated from the same Terraform data, so nothing in the record is specific to them: `cfn_types.py` is the table (every Terraform type the renderers write: its CloudFormation type, how its attributes map, what `Ref` / `Fn::GetAtt` a reference to it reads), `cfn_render.py` the CloudFormation target on `opsdir-format-terraform`'s native engine, and `opsdir-format-cloudformation` writes the YAML. A type the table doesn't know is refused by name: a translation never drops or guesses.

- **Layout.** Each Terraform root `terraform/<rest>` becomes `cloudformation/<rest>/template.yaml`, one stack per provider: a resource on an aliased provider runs in another region or account, so in its own `template.<alias>.yaml` (in GovCloud, CloudFront runs from the standard account's `template.us_east_1.yaml`). What the root adopts (its import blocks) is listed in `template.resources-to-import.json` for a resource import. The scripts the Terraform packages (canary code, the Macie scheduler's function) are written beside the templates.
- **Lookups and inputs.** Data sources become parameters, with the record's ids as defaults and AWS-specific parameter types (`AWS::EC2::VPC::Id`, ...), or pseudo parameters (`AWS::AccountId`, `AWS::Partition`, `AWS::Region`). CloudFront's managed policies are named by AWS's ids. An IAM policy document whose condition keys name another resource (an IRSA trust policy naming the cluster's OIDC issuer, a parameter) is its JSON in one `Fn::Sub`. Terraform variables become parameters, a value one stack reads of another's an output and a parameter.
- **Merged into one resource.** What Terraform splits but CloudFormation holds in one resource: the S3 bucket settings (versioning, lifecycle, object lock, public access block, replication, encryption) in `AWS::S3::Bucket`, event targets in their rule, GuardDuty features in the detector, target group attachments in the target group, role policies in the role, egress rules in the security group, the Backup vault lock, the Config recorder status, RDS automated backup replication, the permission set's inline policy, policy attachments, and Shield's automatic response in its protection.
- **What stays Terraform.** `cloudformation/<rest>/terraform/main.tf`, beside the template and applied after it, its variables taking the template's outputs, with a NOTE naming each resource it keeps and why: no CloudFormation type (the Inspector enabler, Config's retention, Macie's export configuration and classification job, service quota requests, the default route table); in GovCloud, the types GovCloud's resource specification lacks (Macie's account and identifiers, Shield protections, Budgets, CloudFront outside the standard account); an adopted resource CloudFormation can't import by its Terraform import id; and whatever waits for or reads one of these. What a template reads that has no CloudFormation type (`cfn_types.BEFORE`: an edge trust policy's CA bundle object in S3, which the ALB trust store loads when it is created) stays instead in `cloudformation/<rest>/terraform-before/main.tf`, applied **before** the template: its outputs are the template's parameters (their defaults the values when the Terraform sets them literally), and its heading names each resource it keeps. One that reads a resource of the template, or that the root applied after reads, can't go first: the template reading it is refused by name. The order is: `terraform-before/`, the templates, `terraform/`. The format-terraform engine holds this (`Table.before`, `Split.before`), so another target can use it.
- **Checked.** cfn-lint passes (errors fail, warnings are shown: `opsdir/scripts/validate-cloudformation.sh`; tests marked `cloudformation`), each template naming the region it is checked for in its own metadata, so a GovCloud template is checked against GovCloud's specification. That holds for the showcase and the CloudFormation sample (`examples/showcase/tests/terraform/cloudformation_sample.py`, which renders every type the renderers write), in us-east-1 and us-gov-west-1. Every Terraform resource goes exactly one place: a template's resource, part of one, or the Terraform root with its reason.
- **Compute groups** (5.8). `AWS::EC2::LaunchTemplate` holds the launch template's settings as `LaunchTemplateData` (its disks and instance and volume tag specifications), its own tags as a `launch-template` tag specification; the boot disk's device name is a parameter (CloudFormation can't ask the AMI, as Terraform does). `AWS::AutoScaling::AutoScalingGroup` names the template's `LatestVersionNumber` and takes its tags with `PropagateAtLaunch`; Terraform's default tags don't reach it.
- **Placements.** Beside each root's templates, `placements.json` says where every Terraform resource went, by address: the template and logical id (`in`, `id`), the resource it is part of (`part of`), or the Terraform root and why it stays there (`why`). Moving an environment from Terraform to CloudFormation, it says what to import where; reading the render back, what each template resource realizes.
- **Read back** (the round trip, `rendered_stacks` in `rendered_state.py`; milestone 5.6c). Each template becomes a stack folder as the CLI saves one: the template, `describe-stacks` (its parameters' defaults, the stack in the cloud's region and account, or the region its provider alias names) and `list-stack-resources`, each resource's physical id what the Terraform read-back assigns the address `placements.json` names (the provider reference of a binding it realizes, else the address itself). Each kept Terraform root (`terraform/`, `terraform-before/`) becomes the state applying it would record, its variables the stacks' outputs. `aws/cloudformation` reads them together, as one import, and must read the same record as the Terraform read-back does (`examples/showcase/tests/unit/test_round_trip.py`, `test_cloudformation_coverage.py`). Where it can't, the reason is inherent: a lookup is a template parameter, not a resource, so only the read-back that reads a looked-up kind judges the record's bindings of that kind; and what AWS assigns at deployment that no template holds (an Elastic IP's address) isn't there. Kinds the CloudFormation render never writes (EKS, hosted zones, queues and streams, SES, resource policies, Instance Connect Endpoints) are read from a template written by hand (5.6d; see "Reading an environment from its CloudFormation stacks"); autoscaling groups and launch templates are rendered and read (5.8).
- **Not yet.** `aws cloudformation validate-template` and a deployment in a sandbox account (milestone 7.2).

## Kubernetes workloads

For an environment that runs workloads on EKS, the `kubernetes` adapter asks this one how a workload's service account assumes its IAM role and how `aws-sm://` references reach the cluster (`kubernetes.py`):

- **Workload identity** (IAM roles for service accounts): annotation `eks.amazonaws.com/role-arn` with the identity binding's provider ref when it is an ARN, else `arn:aws:iam::<account>:role/<name>` from the cloud's `ciamAccountRef`; `UNBOUND:<role>-role-arn` without them. The platform's Terraform renders that role's trust: an `aws_iam_policy_document` letting each EKS cluster's OIDC provider assume it for its service accounts (`sts:AssumeRoleWithWebIdentity`, `<issuer host>:sub` = `system:serviceaccount:<namespace>:<name>`, `:aud` = `sts.amazonaws.com`), the cluster and provider read as data sources from the cluster binding's provider ref (its name or ARN); EC2 too, with the instance profile, only where servers of the role run as well. A service account whose cluster the environment doesn't bind is a `# NOTE`.
- **External Secrets Operator**: a SecretStore with provider `aws` (service `SecretsManager`, the reference's region from its ARN or the cloud's `ciamRegion`, `auth.jwt.serviceAccountRef` the workload's service account); `remoteRef.key` the secret's name or ARN (its whole SecretString).
- **Secrets Store CSI driver** (provider `aws`): `region`, `usePodIdentity: "false"`, each secret a `secretsmanager` object under its alias.

Not rendered here: the IAM role's trust of the cluster's OIDC provider (the role's Terraform still trusts EC2 for servers).

**Behind a cluster gateway** (`ingress.py`): a service name whose role the environment runs only on EKS, in a cluster with an in-cluster gateway (`ciamClusterGateway`), gets the ALB a service on servers gets (TLS policy, ACM certificate, WAFv2 web ACL and Shield per its protection policy, CloudFront when a CDN fronts it, Route 53 alias), placed in the cluster's node subnets. Its target groups (`ciam-<env>-<service>-<port>`) take IP targets on the gateway's port: HTTP 80 when the front terminates TLS, HTTPS 443 when the policy re-encrypts (an ALB doesn't check the gateway's certificate). Nothing in Terraform registers targets: the plug (`gateway_plug`) gives the cluster one `TargetGroupBinding` per target group (AWS Load Balancer Controller, `elbv2.k8s.aws/v1beta1`, checked against v3.6.0: `targetGroupName`, `targetType: ip`, the gateway's Service and port), and the controller registers the gateway's pods. An ALB's health checks carry no service host, so any answer from the gateway (200-499) counts as healthy. The ALB may leave for the node subnets on the gateway's port; each `TargetGroupBinding` carries `networking.ingress` admitting the ALB's subnets (the node subnets, as IP blocks: the ALB's security group id is Terraform's) on any TCP port (the pods' port is the gateway implementation's), so the controller opens the targets' security group itself (with no `networking` it opens nothing). The platform installs the AWS Load Balancer Controller (Helm; its EKS add-on availability in GovCloud wasn't confirmed).

## Render notes

What a render leaves out or to a person is a render note (core `notes`, flow 43): written as its `# NOTE` comment beside what it concerns and listed in the render's NOTES.md and NOTES.json with its severity (blocker: something the record declares won't exist; action: someone must do something by hand; note: worth knowing), its owners and how to handle it; the planner raises the target's blockers and actions. Classified so far: synthetic checks (canaries); security services (a findings or incident route EventBridge can't deliver, AWS Config without its bucket, every region without the region catalog, an organization-wide service without the accounts it is made from: blockers; AWS Config's incidents: an action); audit trails (not rendered or not streamed: blockers; a bucket policy someone else keeps: an action naming its statements); Macie (no job or export: blockers; stores that aren't S3: an action; GovCloud: a note, since the planner raises it); guardrails without an SCP statement (actions); alert rules (an alarm CloudWatch can't express: a blocker; no alarm realizing the rule: a note, the planner's signal check covers it); log groups and log shipping (a destination that isn't a log group, lines the agent can't pick, a role in no bound cluster, writes no principal permits: blockers; a glob of which only the newest file ships: an action); identities (a permit whose role isn't bound here and a firewall rule or service name for a role run only on Kubernetes: notes, the planner's checks cover them; a permit the cloud has no mapping for: an action; a service account in an unbound cluster: a blocker); budgets (not rendered, or alerts to a topic outside the budget's account: blockers); CloudFront in GovCloud (outside its boundary: an action); a forwarder on the organization's own DNS servers (an action: set it up there); databases (copies RDS won't make, clients' ingress without a port: blockers; Oracle's TLS option: an action); backup plans AWS Backup's cron can't schedule (blockers); volumes (no device name, a snapshot policy Lifecycle Manager can't keep: blockers; a group whose disks name different policies: an action); an adopted compute group's new launch template (an action); edges (a passthrough load balancer asked to inspect requests: a note, the planner's policy check raises it; account takeover protection without its sign-in form, Shield Advanced's subscription: actions); the network depth and the landing zone's plumbing (an endpoint AWS has none of, an endpoint service on an application load balancer, a hub link, a blackhole route, a link of no recorded kind, a flow log on a scope without ids, peering across clouds: blockers; a Direct Connect circuit, the firewall policy's reference to its rule group and the sites that aren't web traffic, the other side accepting a peering, the retention a flow log's destination keeps: actions; a database's endpoint, a route for some roles: notes). Other `# NOTE` comments are listed in NOTES.md to review.

## Planner checks

- `check_boundary`: the AWS services the target uses, named as AWS's FedRAMP Certification Package Overviews name them (servers: Amazon Elastic Compute Cloud (EC2); databases by engine: Amazon RDS for Postgres, ...; object stores: Amazon Simple Storage Service (S3); service names: Elastic Load Balancing (ELB); and so on), checked against the in-scope list of the authorization the target relies on (core `estate`: blockers where the target must rely on one). Neither of AWS's lists (2026-08) nor its services-in-scope page (2026-10-08) names Elastic Load Balancing, EC2 Auto Scaling, Data Lifecycle Manager, Site-to-Site VPN, Transit Gateway or CloudWatch Synthetics. Two are covered by a listed service on AWS's own word, shown as in place with the basis: Data Lifecycle Manager (the EBS user guide: assessed as a capability of Amazon EBS; any program listing EBS applies to it) and Site-to-Site VPN (a feature of Amazon VPC in the EC2 API; the scope page counts generally available features of a listed service in scope unless specifically excluded). The others have APIs of their own and no row: a target using them is told so, to check AWS's SSP (the FedRAMP Partner Package in AWS Artifact), use a service in scope, or record an exception.
- `check_regulated_placement`: where AWS says the target's regulated data (core `estate`: `ciamRegulatedData`) may be held: ITAR and EAR export-controlled data only in AWS GovCloud (US) (a blocker elsewhere; in GovCloud an action naming what its guide says may not hold export-controlled data: S3 bucket names and object metadata, Direct Connect metadata, CloudFront outside its ITAR boundary), CJIS and IRS 1075 in GovCloud and the US regions (a blocker outside them), PHI on HIPAA-eligible services under the account's Business Associate Addendum (an action). The core check carries the source's regulated data to the target and asks for US data location and US-person support for export-controlled data (milestone 5.7b).
- `check_discovery_availability`: how each kept data discovery's interval is honoured (an OK line: Macie's own schedule, or the scheduler); a GovCloud target that records data discovery the platform keeps gets an action (a blocker where its data is classified `restricted`): AWS's General Reference lists no GovCloud endpoint for Macie and its FedRAMP services-in-scope page marks it for US East/West only (nothing rendered).
- The managed identity and managed directory checks (core connectors, flows 66 and 76) read `Adapter.managed_identity` (Cognito) and `Adapter.managed_directory` (AWS Managed Microsoft AD): see their sections below.
- `check_server_inputs` (core `infrastructure.checks`, listed by the provider adapters that render servers): the target's servers it has no image or size for, and compute groups missing an image, a size or a subnet role (`ciamSubnetRole`), or naming one the target doesn't bind.

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

### Client certificates at the load balancer (milestone 122, `mtls.py`)

A trust policy checked at the edge (core `pki.trust`: `ciamTrustEnforcedAt: edge`) whose accepting roles (`ciamAcceptedByRole`) a service name of the environment fronts gets, once per environment: an `aws_s3_object` holding the policy's bundle (core `trust.policy_bundle`: its approved anchors, then the followed bundles' subordinate CAs chaining to them; public certificates, so no secret enters state) at `<prefix>trust/<policy>.pem` in the bucket its `ciamTrustStoreRole` binds (an object store with an `s3://bucket[/prefix]` `ciamStorageRef`), and an `aws_lb_trust_store` reading it. Each HTTPS listener of the ALBs in front of those roles gets `mutual_authentication { mode = "verify" }` with that trust store: the ALB checks the chain and passes the client certificate to the targets in `X-Amzn-Mtls-Clientcert`. Render notes say what ALB mTLS leaves to people or products: revocation only against CRLs uploaded into the trust store (`aws_lb_trust_store_revocation`, no OCSP: an action), the policy's certificate policies, key usages and identity mapping (checked by the product on the forwarded certificate: a note), and a bundle over the default 25 CA certificates per trust store (a quota increase: an action). A policy without anchors recording their PEMs or without a trust store location is a blocker, and its listeners stay plain. Checked with `terraform validate` (aws 6.69.1).

Read back (`mtls_inventory.py`, task 585): every importer (Terraform state, CloudFormation, the CLI) checks what the edge runs against the record, for each service name under an edge trust policy that an ALB fronts (the load balancer found by its tag `Service`, or a Route 53 alias naming the service): each HTTPS listener's `mutual_authentication` mode is `verify` (`off` or `passthrough` is named: nothing checks the certificate the products trust), its trust store is the policy's (tag `TrustPolicy`, else the name the render gives it, `ciam-<env>-<policy>`), and the trust store's CA certificates match the policy's bundle by SHA-256 fingerprint, read from the bundle object at the location the trust store was loaded from (`aws_s3_object` content in Terraform state). Each difference is an import notice saying what to do (render and apply the edge again, or find what changed it); a render read back says nothing and changes nothing. A CloudFormation stack is read the same (`AWS::ElasticLoadBalancingV2::TrustStore`, a listener's `MutualAuthentication`), its bundle object from the Terraform state kept beside it. The CLI gives a trust store's name and number of CA certificates only (`elbv2 describe-trust-stores`; its bundle comes only as a download link, `get-trust-store-ca-certificates-bundle`, which nothing fetches): the count is compared, and a notice asks for the fingerprints to be compared by hand.

CloudFormation (task 591): the trust store is an `AWS::ElasticLoadBalancingV2::TrustStore` (`Name`, `CaCertificatesBundleS3Bucket`, `CaCertificatesBundleS3Key`, `Tags`; its `Ref` is its ARN) and each listener's `MutualAuthentication` (`Mode` `verify`, `TrustStoreArn`), as cfn-lint's schemas have them in us-east-1 and us-gov-west-1. CloudFormation has no S3 object type, and the trust store loads its bundle when it is created, so the bundle object stays Terraform in the root applied **before** the template, `cloudformation/<rest>/terraform-before/main.tf` (see "CloudFormation" above): it outputs the object's key, which the template takes as a parameter (`AwsS3Object<Policy>TrustBundleKey`, the key as its default). Applying it first, then the template, gives a stack and a state that read back with nothing said (the state beside the stacks holds the bundle's content).


### DNS

Nothing is rendered into a zone whose binding names `ciamManagedBy` (someone outside the platform runs it): a comment names them, and the plan drafts the request. A name that routes between environments (`ciamRoutingPolicy` `failover-primary` / `failover-secondary` / `weighted` on the service names of several environments) is answered from the environment holding the primary (a weighted set: the first by label), which renders every environment's answer; the others render a comment.

| From the record | Rendered as |
|---|---|
| A service name | Its Route 53 alias record (a recorded `ciamTtlSeconds` doesn't apply to an alias: a comment); routed, with `set_identifier` (the environment) and a failover or weighted routing policy, the other environments' answers as A records with their TTL, each with a TCP `aws_route53_health_check` on its address and first port |
| DNS records (`ciamDnsRecord`) | `aws_route53_record` in the zone the record's name falls in (the zone binding's `ciamProviderRef`, public or private), type, `ciamTtlSeconds` (300 when not recorded), values; no zone bound: an `UNBOUND` comment |
| Outbound forwarders (`ciamDnsForwarder`) | Per domain an `aws_route53_resolver_rule` (`FORWARD`, a `target_ip` per `ciamForwardTarget` on port 53) through `var.resolver_endpoint_id` (the landing zone's outbound Resolver endpoint; the variable is declared only when there are forwarders) and its association with the VPC. Inbound forwarders are the landing zone's inbound endpoint: a comment. A forwarder on the environment's own DNS servers (`ciamResolverHost`: EC2 instances) gets no rule; the variable is declared only for managed forwarders: a comment says what those servers must forward and that the network's DNS servers point at them |

### CDN

A protection policy with `ciamCdn` puts a CloudFront distribution in front of the service: its origin is the service's load balancer (the ALB when TLS terminates at the edge, else the NLB, TLS then ending at CloudFront), over HTTPS with the viewer's `Host` forwarded (AWS's `Managed-AllViewer` origin request policy) and nothing cached (`Managed-CachingDisabled`: sign-in pages and tokens); the viewer certificate from ACM in us-east-1 (another region or none: an `UNBOUND` comment), `TLSv1.2_2021` minimum; the service's alias record points at the distribution. The protection policy's web ACL (and its IP sets) is created CloudFront-scoped through the provider alias `aws.us_east_1` (declared only when a CDN is used) and named by the distribution (`web_acl_id`); Shield protects the distribution. The ALB behind it admits only CloudFront's origin-facing prefix list and carries no web ACL or Shield of its own.

**In AWS GovCloud (US)**, where CloudFront isn't offered (AWS: CloudFront runs from a standard-partition account pointing at the GovCloud origin), the distribution, its managed cache and origin-request policies, the CloudFront-scoped web ACL and Shield are created in the cloud's associated standard account (`ciamBillingAccountRef`, the account its budgets use too) through the `us_east_1` provider configured for that account (`allowed_account_ids` the standard account; standard AWS credentials), under a comment that CloudFront is outside the GovCloud (ITAR) boundary and that AWS's services-in-scope pages (2026-10) list it for FedRAMP Moderate (US East/West) and DoD IL2 only. The viewer certificate must be in that account's ACM in us-east-1 (else `UNBOUND`). A GovCloud Route 53 zone can't alias CloudFront, so the service name gets a CNAME to the distribution's domain name (at a zone apex, or routed between environments, a comment instead). Without a recorded standard account, a comment names what is missing and neither the distribution nor the name's record is rendered.

### Network depth

What the core `network` domain records and the stack keeps itself (no `ciamManagedBy`) renders into the platform's root; what someone else keeps (a hub firewall, the landing zone's endpoints) goes to its keeper (Who keeps what, above). Nothing recorded, nothing rendered (`opsdir_adapter_aws.network`).

| Record | Renders as |
|---|---|
| `ciamPrivateEndpoint` kind `interface` | `aws_vpc_endpoint` `Interface` to `com.amazonaws.<region>.<service>` (`secrets` Secrets Manager, `keys` KMS, `object-storage` S3, `logs` CloudWatch Logs, `messaging` SNS, `registry` ECR API) in the subnets its `ciamSubnetRole` names, `private_dns_enabled` from `ciamPrivateDns`, with its own security group admitting the network's range on 443 |
| kind `gateway` | `aws_vpc_endpoint` `Gateway` (S3, DynamoDB only; others a comment) on the route tables (`ciamRouteTable` provider refs) naming its subnets, the main table for subnets none names; every recorded table when it names no subnets |
| A service, database or kind AWS has no endpoint for | A comment (a database is reached at its own private address) |
| `ciamEndpointService` | `aws_vpc_endpoint_service` on the network load balancer of the service name `ciamServiceRole` names: `allowed_principals` from `ciamAllowedPrincipal`, `acceptance_required` from `ciamAcceptanceRequired`. A service whose traffic policy puts it on an ALB can't be exposed (an endpoint service needs an NLB): a comment |
| `ciamProxy` kind `firewall` the stack keeps | An `aws_networkfirewall_rule_group` (`STATEFUL`, `rules_source_list` `ALLOWLIST` on `TLS_SNI` and `HTTP_HOST`, `*.example` as `.example`, `HOME_NET` the network's range) and a comment to reference it from the firewall policy its `ciamProviderRef` names. A domain list matches web traffic only: sites on other ports (a mail relay on 587) are named in a comment, decided by the policy's other rules |
| Other proxies (a forward proxy, a proxy service) | A comment: their allowlist is kept there |

### Managed databases

The core `data` domain's databases (`ciamDatabase`) render into `main.tf`, or into their keeper's root when `ciamManagedBy` names someone else (Who keeps what, above) (`opsdir_adapter_aws.databases`).

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

### Cognito user pools (managed identity services)

A `ciamManagedIdentity` binding of `ciamManagedService` `cognito-user-pool` (core federation domain, flow 63) that runs one of the platform's identity services (`ciamRealizes`) renders into `main.tf`, or its keeper's root (`opsdir_adapter_aws.cognito`). A neighbour (`ciamPartnerOf`: someone else's pool the platform federates with) isn't the platform's to render: a note.

| Record | Renders as |
|---|---|
| The binding | `aws_cognito_user_pool` named after it, `deletion_protection` `ACTIVE`, `mfa_configuration` `ON` when every integration it serves requires MFA (`ciamMfaRequired`), `OPTIONAL` when some do (the planner's action: Cognito's MFA is the pool's), else `OFF`, with TOTP software tokens; tags `Name`, `Role`, `Realizes` (the identity service) |
| `ciamFqdn` | `aws_cognito_user_pool_domain`: a `*.amazoncognito.com` host as its prefix; any other host as a custom domain with the ACM certificate holding the binding's `ciamTlsCertificate` (`ciamCertificateRef`). GovCloud has no custom domains: a comment |
| Each `oidc-client` integration the identity service serves | A public client: `aws_cognito_user_pool_client` with `ciamRedirectUri` and `ciamPostLogoutRedirectUri`, the `code` and `client_credentials` flows of its grants, its scopes (the OIDC ones as they are, the others as `<identifier>/<scope>` of the resource server: an action names the new names), `COGNITO` and every upstream provider as its identity providers, and token revocation on. A grant Cognito's token endpoint doesn't take, and `offline_access`, are comments. A confidential client (`client_secret_basic` or `client_secret_post`) has the same settings, rendered as an `aws_cloudformation_stack` holding an `AWS::Cognito::UserPoolClient` with `GenerateSecret`, after the resource server and providers it names. The stack's only output is the client ID (`Fn::GetAtt ClientId`; `ClientSecret` is never referenced), so the secret Cognito generates is in no render, template output or Terraform state (U.5, decision 3289). Storing it where the application's reference points is an action. Nothing reads a client back |
| Custom scopes | one `aws_cognito_resource_server`, identifier the identity service's `ciamBaseUrl` |
| Each `saml2-idp` integration it serves | `aws_cognito_identity_provider` (`SAML`), its metadata read from `var.<pool>_<partner>_metadata_url` (the record holds the partner's entity ID and SSO URL, not a metadata URL: an action) |
| `ciamProviderRef` recorded | An `import` block (the pool id, the ARN's last part) |
| A `saml2-sp` (or `ldap`) integration it serves | a comment: Cognito provides no downstream SAML identity provider (the planner blocks it) |

What the planner knows of Cognito is `cognito.COGNITO` (`Adapter.managed_identity`), from AWS's documentation read 2026-10-15 (research note 3078): an OIDC issuer to applications, a SAML service provider and OIDC relying party of upstream providers; the `authorization_code`, `client_credentials` and `refresh_token` grants; client authentication `none` (PKCE on the code flow), `client_secret_basic`, `client_secret_post`; RS256 ID tokens; custom domains. Documented as unsupported: a downstream SAML identity provider, the token-exchange grant, a custom issuer (the issuer is the pool's, distinct from its sign-in domain), per-client MFA and claim transformations without a pre-token-generation trigger. Also unsupported, because the token endpoint takes only those three grants (AWS lists them exhaustively; research 2026-10-17, docs/research m111): the device authorization, JWT-bearer and SAML 2.0 bearer grants. CIBA, dynamic client registration and the password grant are likewise absent, but the record can't ask for them. Not documented either way (blocked until confirmed, connectors.managed_identity): DPoP, PAR, mTLS, `private_key_jwt` and `client_secret_jwt` client authentication, and PKCE required per client (S256 PKCE is supported, but no per-client switch to enforce it is documented). In GovCloud (both regions; FedRAMP scope `Amazon Cognito`): FIPS endpoints required, no custom domains, no Pinpoint, managed login since 2025-03, password-hash import eligibility undocumented; each a planner action or blocker for a target there.

### AWS Managed Microsoft AD (managed directory services)

A `ciamManagedDirectory` binding of `ciamManagedService` `aws-managed-ad` (core directory domain, flow 76) that holds the platform's user directory (`ciamRealizes ds`) renders into `main.tf`, stamped with its entry:

| Record | Renders as |
|---|---|
| The binding | `aws_cloudformation_stack` `ciam-<env>-<binding>-directory` whose template body (`jsonencode`) is one `AWS::DirectoryService::MicrosoftAD` (`DeletionPolicy` and `UpdateReplacePolicy` `Retain`): `Name` from `ciamFqdn`, `ShortName` from `ciamNetbiosName` (else the domain's first label in capitals), `Edition` from `ciamDirectoryEdition` (`standard`, `enterprise`; AWS's default, Enterprise, when unrecorded), `VpcSettings` from the environment's VPC and the two subnets its `ciamSubnetRole` names. Outputs: the directory ID and its DNS addresses only. Tags `Name`, `Role`, `Realizes`; create and update time out after 90 minutes |
| The Admin password | `Password: {{resolve:secretsmanager:<id>}}`, the credential role's (`ciamCredentialRole`) `aws-sm://` secret: CloudFormation resolves the dynamic reference when it creates the directory, so no password is in the template, the Terraform state or the record (decision 3197). Terraform's `aws_directory_service_directory` keeps its required `password` in state, so it isn't used |
| Each `ciamReplicaRegion` | `aws_directory_service_region` on `var.<binding>_<region>_vpc_id` and `var.<binding>_<region>_subnet_ids` (another region's network, which the environment doesn't bind: an action names the variables), `desired_number_of_domain_controllers` from `ciamReplicaCount` |
| Each trust recording its domain's DNS servers (`ciamForwardTarget`) | `aws_directory_service_conditional_forwarder` for its domain |
| No domain, no `aws-sm` secret, or not two subnets | Nothing but an UNBOUND comment naming what is missing (and an action) |
| A neighbour (`ciamPartnerOf`) | a note: not the platform's to render |

The dynamic reference is supported in every resource property but custom resources (AWS's dynamic-references guide), and the type's own schema (cfn-lint's) has `Password` write-only and not part of its primary identifier (`DirectoryId`); Directory Service never returns it, drift detection can't compare it, and drift-aware change sets compare it against the previous deployment's value: the reference text. The render puts the reference in `Password` only (no Outputs, Metadata or Parameters). `Password` is create-only: rotating the secret doesn't change the Admin password (reset it with `aws ds reset-user-password`), and changing the reference replaces the directory (a render note says so). Checked with `terraform validate` against hashicorp/aws 6.69.1 and cfn-lint 1.57.2 (us-east-1, us-gov-west-1, us-gov-east-1); not deployed.

Actions, each a render note: every trust (its password is shared with the other domain: `aws ds create-trust` on both sides), server-side LDAPS (`ciamLdapsMode` `private` or `internet`: a certificate enrolled from AWS Private CA's Connector for AD or an Enterprise CA, then `aws ds enable-ldaps --type Server`), the record's own attribute types and object classes (an LDIF of attributeSchema and classSchema entries through `aws ds start-schema-extension`), the password policies (set on the predefined CustomerPSO-01..05 with AD tools), domain controllers beyond two (`aws ds update-number-of-domain-controllers`). A CloudFormation render keeps the stack, the regions and the forwarders in the Terraform root beside the template (`cfn_types.NO_NATIVE`: the stack already is CloudFormation; the other two have no CloudFormation type).

What the planner knows of it is `directory.AWS_MANAGED_AD` (`Adapter.managed_directory`), from AWS's documentation read 2026-10-16 (research note 3196): LDAP and server-side LDAPS (on a condition: the certificate), LDIF schema extensions (new classes and attributes under their OIDs, additions to existing classes; nothing deleted), five predefined fine-grained password policies (the limit), multi-Region replication (Enterprise only; five Regions, its own included), forest and external trusts in every direction. Internet-facing LDAPS isn't documented either way (blocked until confirmed). In GovCloud (both regions; FedRAMP scope `AWS Directory Service`): no directory sharing, Hybrid Edition or Directory Service Data API, automatic DNS forwarding off, metadata kept free of export-controlled data (actions); multi-Region replication is neither listed as missing nor confirmed there, so a GovCloud target replicating to another region is blocked until AWS confirms it. Users and passwords move only from another Active Directory (ADMT with the Password Export Service): an action for every target.

Known limits: not deployed against a live account (7.2); Hybrid Edition and AD Connector aren't modelled; trusts aren't read back (the CLI's `describe-trusts` isn't collected yet); a directory's live settings (`describe-settings`: TLS, RC4, NTLMv1) aren't rendered or read.

### Disks and snapshot policies

The core `data` domain's volumes (`ciamVolume`, each server role's disks) and snapshot policies (`ciamSnapshotPolicy`) render into `main.tf` (`opsdir_adapter_aws.volumes`). Classes to types: `standard` st1, `ssd` gp3, `provisioned` io2.

| Record | Renders as |
|---|---|
| The role's boot volume (`ciamVolumeKind` `boot`) | Each instance's `root_block_device`: `volume_size`, `volume_type`, `iops`, `throughput`, encrypted with its key role's KMS key (`ciamEncryptedByRole`, else the `disk-encryption` binding's; unbound: a comment), tagged `Volume`, `Role`. Without one, the root disk is encrypted with the disk key as before |
| Each data volume of the role | Per server: an `aws_ebs_volume` in the server's zone (size, type, IOPS, throughput, encryption) tagged `Name`, `Volume`, `Role`, `Server`, `SnapshotPolicy`, and an `aws_volume_attachment` at `/dev/sdf`, `/dev/sdg`, … in the volumes' order; the server mounts it at `ciamMountPath` itself (a comment) |
| A compute group's disks (5.8) | Its launch template's `block_device_mappings`: the boot volume at the AMI's root device (`data.aws_ami.<group>.root_device_name`; without one, encrypted with the disk key), each data volume it keeps at `/dev/sdf`, … (size, type, IOPS, throughput, its key), deleted with the instance. A template tags every disk alike, so the instances name their disks (`BootVolume`, `DataVolumes` = `sdf=<volume> …`, core `data.volumes.disk_tags`) and the disks carry `Group` and, when they all name one, `SnapshotPolicy` (Lifecycle Manager's target); disks naming different policies get none, said |
| `ciamVolumeEncrypted` `FALSE` | Rendered as recorded (`encrypted = false`); the planner names it |
| `ciamSnapshotPolicy` the stack keeps | An `aws_dlm_lifecycle_policy` (`execution_role_arn` an input, `dlm_execution_role_arn`) snapshotting the volumes tagged `SnapshotPolicy = <role>`: `create_rule` every `ciamSnapshotEveryHours` (1, 2, 3, 4, 6, 8, 12 or 24; another interval is a comment) from `ciamSnapshotAt`, `retain_rule` `ciamRetentionDays` days, an encrypted `cross_region_copy_rule` per `ciamCopyRegion` (at most three) keyed by the disk key's replica there when it is a multi-region key replicated to that region, else an input `<policy>_<region>_kms_key_arn`; an `import` block when its provider ref (the policy ID) is recorded. One someone else keeps: a comment |

### Backup vaults and plans

The core `data` domain's backup vaults (`ciamBackupVault`) and plans (`ciamBackupPlan`) render as AWS Backup into `main.tf` (`opsdir_adapter_aws.backups`).

| Record | Renders as |
|---|---|
| `ciamBackupVault` the stack keeps | An `aws_backup_vault` `ciam-<env>-<name>` with `kms_key_arn` from its key role (AWS Backup's own key when it names none: a comment), tagged `Name`, `Role`; its lock an `aws_backup_vault_lock_configuration` (`min_retention_days` its `ciamStorageLockDays`; `compliance` with `changeable_for_days = 3`, the grace AWS gives before a compliance lock can't be changed or removed; `governance` without). `ciamCrossRegionRestore` is a comment: on AWS another region's restores come from a plan's copies to a vault there. An `import` block when its provider ref is recorded |
| `ciamBackupPlan` the stack keeps | An `aws_backup_plan` `ciam-<env>-<name>` with one rule into its vault: `schedule` `cron(M H ? * * *)` daily, `cron(M H/N ? * * *)` every N hours, `cron(M H */D * ? *)` every D days (another interval is a comment), `start_window` from `ciamBackupWindowHours`, `lifecycle` `delete_after` its retention, a `copy_action` per `ciamCopyRegion` to that region's vault (its ARN an input, `<plan>_<region>_vault_arn`); and an `aws_backup_selection` choosing every resource tagged `Role` = a role it protects (the volumes, databases and instances this adapter renders carry that tag), AWS Backup's IAM role an input (`backup_iam_role_arn`). A plan whose vault isn't bound is a comment. An `import` block when its provider ref is recorded |
| One someone else keeps (`ciamManagedBy`) | Rendered the same, in its keeper's root, or named in a comment when the keeper takes no generated infrastructure (Who keeps what, above) |

### Monitoring: alarms, log groups and canaries

The core `observability` domain's alerting, log destinations and synthetic checks render into `main.tf` (`opsdir_adapter_aws.observability`, `opsdir_adapter_aws.canaries`). What is cloud-neutral (which rules an environment delivers, the condition in a cloud's terms, each canary's URL and credentials) comes from the core (`domains/observability/alarms`, `canaries`); this adapter maps it.

| Record | Renders as |
|---|---|
| An alert rule the environment delivers (its `ciamAlertRole` bound: the channel), realized by an alarm binding (`ciamAlarmBinding`, `ciamRealizes`) recording `ciamMetric` `<namespace> <metric>` | `aws_cloudwatch_metric_alarm` named as the binding: the rule's comparison (`eq`/`ne` aren't CloudWatch's: a NOTE), its threshold in the unit written where CloudWatch has it (`ms` as `Milliseconds`, other durations `Seconds`, sizes `Bytes`, `%`/ratios `Percent`, set as the alarm's `unit`); a rate (`/s`, `/min`, `/h`) as a `Sum` of `Count` over a window of at least a minute; the evaluation period as that many windows; `alarm_actions` the channel's SNS topic; tags `Realizes`, `BindingRole` |
| A rule with no alarm here, or whose alarm records no metric or a metric query | A NOTE: Prometheus may evaluate it (`opsdir-adapter-prometheus`) |
| A log destination of kind `log-group` (`ciamLogDestination`, its `ciamProviderRef` a log group ARN) | `aws_cloudwatch_log_group` of that name, `retention_in_days` as recorded, raised to the next value CloudWatch allows (a comment says so); `0` (never expire) as `0`, more than 3653 days as `0` with a comment |
| A canary (`ciamCanary`) whose checked service the environment binds, flow `health`, `login-page`, `saml-sso`, `oidc-token` or `ldap-bind` | `aws_synthetics_canary` named as its canary binding (`ciamCanaryBinding`), running a Python script opsdir renders (`terraform/canaries/<name>/python/canary.py`, zipped by `data archive_file`; runtime the estate setting `aws-canary-runtime`, default `syn-python-selenium-12.0`) at its interval; artifacts at the S3 location its canary binding records (`ciamStorageRef` `s3://bucket/prefix`); tags `Realizes`, `BindingRole`. The script carries the shared probes (core `observability.probes`): a GET (health, login page; `saml-sso`: the identity provider's start of a sign-in for the integration the canary starts from, `ciamStartsFrom`), a client-credentials token request (`oidc-token`), an LDAPS simple bind (`ldap-bind`, anonymous without credentials), reading its `ciamUsesRole` Secrets Manager secret when it runs; the secret is never rendered. A check of a service a private CA certified carries the CA certificates the record holds for it in the script (`CA`, `CA_PARTIAL`; below) |
| A canary of an internal service name | The same canary in the VPC (`vpc_config`): in the subnets its binding names (`ciamSubnetRole`), else those the firewall rules admit to the service on its port, with the canaries' security group (`aws_security_group` `canaries`: out to each checked service on its port, and on 443 to the AWS APIs the script calls) |
| The environment's canaries, once | `aws_iam_role` `ciam-<env>-canaries` (Lambda trusted) and its policy: the artifact locations, the canaries' own log groups, `s3:ListAllMyBuckets`, `xray:PutTraceSegments`, `cloudwatch:PutMetricData` in `CloudWatchSynthetics`, the ENI permissions when a canary runs in the VPC, `secretsmanager:GetSecretValue` on each credentials secret (partition `aws-us-gov` in GovCloud) |
| Not rendered, as a render note (written as its `# NOTE` comment, listed in the render's NOTES.md with how to handle it; a blocker when the canary feeds an alert rule) | A service name whose exposure isn't recorded, an internal one with no subnet to run from, credentials that aren't `aws-sm://`, no artifact location (no canary binding, or one without an `s3://` `ciamStorageRef`), a certificate chaining to CA certificates the record holds none of the PEMs of (the note names the CA, the chain and the CA certificates' owners: record `ciamCertificatePem`) |
| An alarm, log group or canary someone else keeps (`ciamManagedBy`) | Rendered the same, in its keeper's root, or named in a comment when the keeper takes no generated infrastructure (Who keeps what, above) |
| One an overlay inherits from its base | A comment naming the base (`kept by source/prod (this environment inherits it)`): the base's root renders it, so stage and production never create the same alarm, log group or canary twice |

The location of a canary's artifacts is on its binding, not a role, because it is the environment's: Azure's checks keep their own results and Google Cloud's synthetic monitors need a place for their functions' source instead (a `gs://` location on the same attribute), so a role bound only on AWS would be a false blocker on a move. A check of a service whose certificate (`ciamTlsCertificate`) chains to CA certificates the record holds (core `pki.chain`: `ciamIssuedBy`, else a recorded CA certificate whose subject is its issuer) is given their recorded PEMs (`ciamCertificatePem`): a CA's certificate is public material (SPEC R4 still covers keys and secrets), added to the runtime's own trust store, never replacing it, and the intermediate CA given is trusted as the anchor when no root is among them (milestone 113, decision 3109). A CA rotation is a record change (its new certificate recorded) and a re-render. On CloudWatch Synthetics the PEMs are written into the canary's script (Python's default context, `load_verify_locations`; `VERIFY_X509_PARTIAL_CHAIN` for an intermediate anchor, which the Python 3.12 runtime doesn't set by default): no runtime fetch, no extra permission.

### Log routing: product logs to their log groups

Each log route (core `observability`: `ciamLogRoute`) ships the logs its server roles' products declare (`LogSource`s; what a route picks from each: `domains/observability/sources`) to the log group its `ciamLogDestinationRole` names here. Configure-only: opsdir doesn't install the CloudWatch agent or run the add-on; the host baseline installs the agent. Sources: research note 2344 (CloudWatch agent configuration reference, AWS's EKS Fluent Bit setup, Fluent Bit's rewrite_tag and cloudwatch_logs docs).

| Where the role runs | Renders as |
|---|---|
| Servers (`opsdir_adapter_aws.log_agent`) | `host_files`: one CloudWatch agent configuration per server role and install root (`ciamInstallRoot`; the servers sharing it receive it), `/opt/aws/amazon-cloudwatch-agent/etc/opsdir-logs.json`, placed by `opsdir-adapter-ansible` (tag `host-files`) and loaded with `amazon-cloudwatch-agent-ctl -a append-config -m ec2 -s -c file:<path>` when it changes, so the baseline's own configuration stays. One `collect_list` entry per file a route takes whole: the file's glob under the install root, the group's name, stream `{instance_id}/<file>`, `multi_line_start_pattern` when records span lines. No retention (the group's Terraform keeps it); `endpoint_override` to CloudWatch Logs' FIPS endpoint when the cloud uses FIPS endpoints. The servers' writes come from the record: their workload principal's `write-logs <destination role>` permit, through the instance role it already renders |
| EKS (`opsdir_adapter_aws.fluent_bit`) | Per cluster the roles run in, `kubernetes/fluent-bit/<cluster>/` (a kustomization): namespace `ciam-logging`, service account `fluent-bit` annotated with its IAM role (IRSA), a cluster role reading pods and namespaces, the DaemonSet (`public.ecr.aws/aws-observability/aws-for-fluent-bit:3.4.17`, Linux nodes, `/var/log` read-only) and its `fluent-bit.conf`: container output tailed, JSON lines lifted under `log_processed`, a role's pods picked by their `opsdir.io/role` label (the deployment kits set it), each line's source by its container among the role's sources (a kit's log sidecar, e.g. ping-devops's `pf-log-<file>`; the rest the role's main source), then its kind as that source says (one `rewrite_tag` filter per match rule in order, then the source's kind), one `cloudwatch_logs` output per route and role for the kinds it wants (`auto_create_group false`; the FIPS endpoint when required). Terraform: `aws_iam_role` `ciam-<env>-fluent-bit-<cluster>` trusting the cluster's OIDC provider for `ciam-logging/fluent-bit`, allowed `logs:CreateLogStream`, `PutLogEvents` and `DescribeLogStreams` on the routes' groups only. Don't run it beside the CloudWatch Observability add-on's Fluent Bit (logs would be sent twice) |
| Named in `main.tf` (`# NOTE`) | A server file a route takes only some lines of (the agent filters raw lines with regular expressions, not JSON fields); a glob (the agent ships only the most recently modified file it matches); a destination that isn't a log group here; a server role no workload principal lets write to the group; a role on Kubernetes in no cluster the environment binds |

Known limits: not validated against a live agent or cluster (7.2). IRSA, not EKS Pod Identity (both are available in GovCloud; Pod Identity can be added as an alternative). The FIPS endpoint names follow `logs-fips.<region>.amazonaws.com`, to be confirmed for GovCloud (7.2). Off-AWS servers (the agent's on-premises mode) aren't rendered.


### Logs forwarded on to a SIEM (milestone 109, `siem_forwarding.py`)

A log group this environment renders, whose log destination records `ciamForwardsToRole` (the binding role of a SIEM index), is subscribed to an Amazon Data Firehose stream. The stream pushes the group's logs to the index's intake.

| Rendered | What it is |
|---|---|
| `aws_cloudwatch_log_subscription_filter` | Every event of the group (empty pattern) to the stream, through a role CloudWatch Logs assumes. The role may put records on that stream only, and its trust is limited to this account's log groups when the cloud records its account and region |
| `aws_kinesis_firehose_delivery_stream` | An index the Splunk adapter keeps gets `splunk_configuration`: HEC `Raw` at the index's Firehose endpoint (below), the CloudWatch envelope decompressed and kept whole. An index the Elastic adapter keeps gets `http_endpoint_configuration` (Elastic's Firehose intake). Either way, `secrets_manager_configuration` names the secret the index's `ciamCredentialRole` references (`{"hec_token": ...}` or `{"api_key": ...}`), and events it can't deliver go to the group's `ciamStorageRef` (`s3://bucket[/prefix]`) |
| `aws_iam_role` + policy | What Firehose assumes: `secretsmanager:GetSecretValue` on that secret (and `kms:Decrypt` on its key when the secret binding records `ciamEncryptedByRole`), and the backup bucket |

A Splunk index's Firehose endpoint is found from its `ciamIntakeUrl` (task 593, from Splunk's Firehose and HEC documentation):

| The intake URL's host | Where Firehose sends |
|---|---|
| `http-inputs-<stack>.splunkcloud.com` (Splunk Cloud Platform on AWS, its HEC) | `https://http-inputs-firehose-<stack>.splunkcloud.com:443`, Splunk's documented Firehose endpoint for the stack (a note names it) |
| A Splunk Cloud host naming `firehose` | The intake URL as it is |
| Any other Splunk Cloud host (`http-inputs.<stack>` on Google Cloud, Azure, or FedRAMP on AWS GovCloud; a trial stack) | Nothing: Splunk documents no Firehose endpoint for these, and the record holds one intake URL per index. A blocker |
| Any other host (Splunk Enterprise) | The intake URL without its path. An action lists what Firehose needs in front of the HEC: a Classic or Application Load Balancer, HTTPS with a trusted CA-signed certificate for that host, and duration-based sticky sessions |

No credential value is in the render or the Terraform state. A render note asks the SIEM team to put it in the secret (for Splunk, a HEC token with indexer acknowledgment on). A forwarding that lacks an intake URL, a credential, a backup location, a documented Splunk Cloud Firehose endpoint, or an index kept by Splunk or Elastic is a blocker note naming what is missing. CloudFormation deploys the stream (`AWS::KinesisFirehose::DeliveryStream`, no `HECToken`) and the subscription natively. Checked with `terraform validate` (hashicorp/aws 6.69.1) and cfn-lint 1.57.2 (us-east-1, us-gov-west-1). In GovCloud, AWS documents Firehose with no differences; whether Firehose itself reaches the secret and the intake through FIPS endpoints isn't established, and a note says so.
## Reading an environment back from Terraform state

```bash
terraform -chdir=… state pull > export/source/prod/terraform.tfstate     # one folder per <cloud>/<env>
opsdir import --dry-run aws/terraform-state export/                        # what the live environment differs in
opsdir import --change CHG-… aws/terraform-state export/                   # record it
```

The importer `aws/terraform-state` reads Terraform state (format version 4, `hashicorp/aws` 5.x or 6.x: the attributes it reads are named the same in both, and a flow log's group is read from `log_destination` or 5.x's `log_group_name`; managed resources and data sources) into the environment's servers and bindings. Environments are chosen by the folder layout, `<cloud>/<env>/`; an environment whose cloud isn't AWS, and a state outside the layout, are named, not imported. An environment's states are read together, as one import (each root's resources link to the others': a principal's grants in one root and its identity in another), and an object read twice (managed in one root, looked up in another) is placed once, each attribute as reported.

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
| `aws_cloudtrail` | audit trail (`ciamAuditTrail`, role `audit-trail` unless tagged): `organization` or `account` (`is_organization_trail`), the activity its event selectors record (basic or advanced; none: `control-plane`), all regions, integrity validation, where its records go (`ciamLogDestinationRole`: the role of its bucket's object store, or of its CloudWatch log group) and the log group it also streams to (`ciamAuditStreamRole`). Which data resources the selectors name isn't read: the record keeps `ciamAuditResourceRole` (none named means the environment's own, which a read can't tell from a list). The CLI's `cloudtrail describe-trails`, `get-event-selectors` and `list-tags`, and CloudFormation's `AWS::CloudTrail::Trail`, are read the same way | ARN (`ciamProviderRef`) |
| `aws_guardduty_detector` (+ `_feature`, legacy `datasources`, `aws_guardduty_organization_configuration`), `aws_inspector2_enabler`, `aws_config_configuration_recorder` (+ its delivery channel, `aws_config_retention_configuration`), `aws_securityhub_account` (+ `aws_securityhub_standards_subscription`, `_organization_configuration`) | security service (`ciamSecurityService`, role its kind unless tagged): kind, the areas a detector's features or Inspector's resource types watch, the standards and AWS baselines subscribed, organization or account, retention, and where findings go (`ciamFindingsRole`: the SNS topic or log group an EventBridge rule for the service's findings targets, or the recorder's delivery bucket), and the incident route (`ciamIncidentRole`, `ciamIncidentSeverity`: the target of a rule filtering the findings on severity, and the least severity it lets through). An SNS topic findings go to is an alert channel | ARN, or `inspector2:`/`config-recorder:` ids |
| `aws_securityhub_automation_rule` setting workflow `SUPPRESSED`, `aws_guardduty_filter` with action `ARCHIVE` | suppression (`ciamSuppression`, role `suppression-<exception>`): merged per name, the controls (`aws:securityhub:<control>`) and finding types (`aws:guardduty:<type>`) it hides, its exception from the name `exc-<cn>` (linked when the record holds it; else the planner says no exception covers it) | the rule's ARN |
| `aws_macie2_classification_job` (`SCHEDULED`; + `aws_macie2_custom_data_identifier`, `aws_macie2_classification_export_configuration`), or the scheduler's `aws_lambda_function` (tag `RescanDays`) | data discovery (`ciamDataDiscovery`, role `data-discovery`): the buckets it examines as the object stores' roles (`ciamScansRole`), its schedule as days (the function's: its `RESCAN_DAYS`, `BUCKETS` and `CUSTOM_DATA_IDENTIFIER_IDS`), its custom identifiers (`name: regex`), where findings go (the target of the EventBridge rule for `aws.macie`) and results (the export configuration's bucket); the scheduler's function isn't read as a job | the job's or function's ARN or id |
| `aws_cloudwatch_metric_alarm` | alarm the cloud runs (`ciamAlarmBinding`): what it evaluates (`ciamMetric`: namespace and metric, or `metric query`), the topics it notifies (`ciamNotifies`), the alert rule it realizes (`ciamRealizes`, its tag `Realizes`). Its binding role is its tag `Role` or `BindingRole`, else `alarm-<Realizes>`; untagged alarms are named, not recorded | ARN (`ciamProviderRef`) |
| `aws_synthetics_canary` | synthetic check the cloud runs (`ciamCanaryBinding`): its `rate(...)` schedule as an interval (`5m`), the canary it realizes (tag `Realizes`), its `artifact_s3_location` (`ciamStorageRef`, `s3://bucket/prefix`); binding role as for alarms, else `canary-<Realizes>` | ARN (`ciamProviderRef`) |
| `aws_iam_role` (+ `aws_iam_role_policy`, `aws_iam_role_policy_attachment`, `aws_iam_policy`) | identity binding (`ciamIdentityBinding`, kind `role`, `federated` when an OIDC provider may assume it): who may assume it (`ciamTrustedBy`: a service, `<issuer URL> <subject>` per OIDC subject, a principal ARN), the grants and denials of its inline and attached policies, its permissions boundary's allows as its ceiling (`ciamBoundary`); role from its tag `Role` | role ARN, else its name |
| resource policies: `aws_kms_key` `policy`, `aws_kms_key_policy`, `aws_s3_bucket_policy`, `aws_secretsmanager_secret_policy` | grants (` (resource policy)`; `*` in a key or secret policy is that key or secret) and denials on the roles they name; a deny naming every principal applies to every role in the state; grants to a role the state doesn't hold are named | (on the identity) |
| `aws_ssoadmin_permission_set` (+ `_inline_policy`, `aws_ssoadmin_managed_policy_attachment`, `aws_ssoadmin_account_assignment`) | identity binding per group it is assigned to (kind `permission-set`; the group id as provider ref, as the landing zone names an operator's group): the grants of its policies; role from the permission set's tag `Role` | group id |
| `aws_organizations_policy` (`SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY`; from the management account's state) | guardrail (`ciamGuardrail`, kind `service-control` / `resource-control`): its denies (`ciamDenial`), its allows as a ceiling unless it allows everything (`FullAWSAccess`), what it prevents (`ciamDenies`) by the statement ids the renderer writes (`DenyOutsideRegion`, …); role from its tag `Role` | policy ARN |
| `data aws_ssoadmin_instances`, `aws_ec2_instance_connect_endpoint` | access path (`ciamAccessPath`): `workforce-sso` (role `access-workforce-sso`, the identity store as `ciamTrustedBy`), `session` (tag `Role`, else `access-session`). The CLI's `ec2 describe-instance-connect-endpoints` (in the listed VPCs; failed and deleting ones skipped) and CloudFormation's `AWS::EC2::InstanceConnectEndpoint` are read the same way | ARN |

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

### Cognito user pools, read back

`opsdir_adapter_aws.cognito` (the CLI normalizes to the same names: `cli_cognito.py`; a CloudFormation stack's `AWS::Cognito::UserPool` and `UserPoolDomain`: `cloudformation_data.py`). `aws_cognito_user_pool` -> managed identity (kind `managed-identity`, `ciamManagedIdentity`): `cognito-user-pool`, its ARN (else its id) as the provider ref, its custom domain (`custom_domain`, else the `aws_cognito_user_pool_domain` with a certificate) as `ciamFqdn`, the identity service its tag `Realizes` names; a new one needs its tag `Role`. Nothing of its app clients or identity providers is read, so neither a client secret nor an upstream credential is.

### Managed directories, read back

`opsdir_adapter_aws.directory` (the CLI normalizes to the same names: `cli_directory.py`; a CloudFormation stack's `AWS::DirectoryService::MicrosoftAD`: `cloudformation_data.py`). An `aws_directory_service_directory` of type `MicrosoftAD`, or an opsdir directory stack in state (`aws_cloudformation_stack`: its template's MicrosoftAD and the directory ID from its outputs) -> managed directory (kind `managed-directory`, `ciamManagedDirectory`): `aws-managed-ad`, its directory ID as the provider ref, `ciamFqdn`, `ciamNetbiosName`, `ciamDirectoryEdition`, its further regions (`aws_directory_service_region` entries, or the CLI's `RegionsInfo`) and the role its tag `Realizes` names (`ds`). Its `Password` is never read; trusts beneath the binding are kept as recorded.

### Disks and snapshot policies, read back

`opsdir_adapter_aws.volumes` (the CLI normalizes to the same names: `cli_volume.py`). Volumes and snapshot policies are matched by name; a new one needs its tag `Role`.

| AWS resource | Record entry |
|---|---|
| `aws_ebs_volume` (+ `aws_volume_attachment`), grouped by tag `Volume` | data volume of the role its instances run: the most common size, class, IOPS and throughput (a server whose disk differs in size is named), encrypted only when all are; its KMS key and the snapshot policy whose target tag its `SnapshotPolicy` tag matches as roles |
| `aws_instance` `root_block_device` tagged `Volume` | the role's boot volume, the same way. An untagged root disk that isn't encrypted is named |
| `aws_launch_template` whose instance tag specification names its disks (`BootVolume`, `DataVolumes`) | the volumes of the role its instances' tag `Role` names: each `block_device_mappings` entry's EBS settings, joining the same volumes servers' disks are; the snapshot policy its volume tag specification's `SnapshotPolicy` targets |
| `aws_dlm_lifecycle_policy` (enabled) | snapshot policy: interval in hours, start time, retention in days (weeks, months, years converted; by count: named, not read), copy regions, consistency `crash` |

An EBS volume attached to one of the environment's instances without a `Volume` tag is named: which of the record's volumes it is can't be told.

### Backup vaults and plans, read back

`opsdir_adapter_aws.backups` (the CLI normalizes to the same names: `cli_backup.py`). Vaults and plans are matched by name: their tag `Name` (what this adapter renders), else the resource's own; a new one needs its tag `Role`.

| AWS resource | Record entry |
|---|---|
| `aws_backup_vault` (+ `aws_backup_vault_lock_configuration`) | backup vault: its KMS key as its key role, its lock (`compliance` when the lock has a grace, `governance` otherwise) and minimum retention days |
| `aws_backup_plan` (+ its `aws_backup_selection`s) | backup plan, from its first rule: every hours and start time (from the cron expressions this adapter writes; another is named), start window in hours, retention in days, the regions its copies go to, its vault; the roles its selections' `Role` tags choose |

A plan with several rules is named (the first is read); a selection choosing resources by ARN rather than by tag is named (what it protects isn't read).

**Reading its own render back** (the round trip, `reads_back`; `rendered_state.py`). Each rendered root (`terraform/`, `terraform/landing-zone/`) becomes the state applying it would record (`opsdir_format_terraform.state_builder`), read by `aws/terraform-state`. What AWS would assign comes from the record the render was made from:
- a resource realizing a binding the record holds (`REALIZES`: its type and the binding's class; the block named after the binding) gets that binding's provider reference, an ARN as `arn` or another reference as `id`, as the importer reads it;
- any other resource gets an id and an ARN in the root's partition (GovCloud for `us-gov-*`), region and account, plus what AWS assigns its type (`ASSIGNS`: a load balancer's DNS name and zone, an OIDC provider's `oidc-provider/<host>` ARN);
- `tags_all` is the provider's `default_tags` under the resource's own tags, and `aws_partition`, `aws_caller_identity` and `aws_region` are answered.

A render chosen as CloudFormation reads back through `aws/cloudformation` (see "CloudFormation" above); one chosen only as CloudFormation holds no `terraform/*.tf`, and the Terraform read-back says so. The render is the record's intent (its edge policies, the permission table, the guardrails), so the read-back is marked `intent`. It must read back as the bindings it came from, with no copies, and rendering again must give the same files. Where the record still holds what was observed, the changes are what applying would record. In the showcase's source/prod: NLB passthrough becomes the ALB the policies ask for, WAF and Shield come back as edge bindings, and broad grants become least-privilege ones. One gap is known: CloudTrail data events aren't rendered yet (milestone 5.7), so they don't survive.

## Collecting from AWS (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter aws` reads what the three importers below read, read-only, under your own
AWS CLI login (`opsdir_adapter_aws.collect`), and imports it like an export you saved:

- First `aws sts get-caller-identity`: its `Account` must be the cloud's `ciamAccountRef`, or nothing is read.
- `aws/cli-inventory`: every call of the script below, as exact calls in rounds (the listings in the environment's
  VPC, its network binding's provider ref, and the cloud's `ciamRegion`; then each item's details), all `--output
  json --region <region>`, with `AWS_USE_FIPS_ENDPOINT=true` when the cloud records FIPS endpoints. Per-bucket settings
  and bucket policies are read for the buckets the environment records only; secret resource policies for the secrets
  it references only. Lambda functions, CodeBuild projects, Scheduler schedules, EventBridge targets, CodePipeline
  pipelines, CloudFront distributions, launch template versions (their disks and tag specifications kept) and Synthetics canaries are projected (`--query`) to
  the fields the importer reads, so environment variables, inputs, action configuration, origin custom headers and
  user data are never fetched; so are SQS queues (their ARN and tags) and SES identities (type, DKIM status and tags,
  not their sending authorization policies; domains only, an address isn't read). A resource without a setting
  (no bucket policy, no Shield Advanced subscription, a key without rotation support) leaves its file out, and so does
  a security service's organization configuration outside its delegated administrator's account (the generic error
  its API reference documents for the call: GuardDuty `BadRequestException`, Inspector `AccessDeniedException`,
  Security Hub `InvalidAccessException`, also for a Security Hub not enabled); the import then names the service as
  the account's own.
- Organization control policies (service and resource control policies, read by `aws/cli-inventory` as guardrails)
  can be listed only from the organization's management account or a delegated administrator, so they need a second
  login: a collection source names an AWS CLI profile from your own AWS configuration (SSO or a role chain; opsdir
  never sees its credentials), and only the Organizations calls run with `--profile`. First `aws sts
  get-caller-identity` and `aws organizations describe-organization` with that profile: its `Organization.Id` must be
  the cloud's `ciamOrganizationRef` (`o-…`, or an ARN holding it), or the collection stops and nothing is imported.
  Then the account's parents up to the root (`list-parents`), the policies of both types attached to the account and
  to each parent (`list-policies-for-target`: inherited policies apply too), and each policy once (`describe-policy`,
  saved as `org/<policy id>.json`). Without the source the policies aren't collected; the guardrails the record holds
  are kept (the import notes them, it doesn't remove them).

  ```ldif
  dn: cn=org-policies,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops
  objectClass: ciamCollectionSource
  ciamBindingRole: collect-org-policies
  ciamImporter: aws/cli-inventory
  ciamSourceRef: aws-profile://org-mgmt
  ```
- Budgets: the account's own (`budgets describe-budgets --account-id <ciamAccountRef>`, then each budget's
  notifications, their SNS subscribers, projected so e-mail addresses aren't fetched, and its tags, saved under
  `budgets/<account>/`). A GovCloud cloud's budgets are its associated standard account's (`ciamBillingAccountRef`):
  AWS bills GovCloud there and lists no AWS Budgets endpoint in GovCloud. They need a login to that account: a second
  `aws-profile://` collection source, and only the budget calls run with it. Which profile is which is told by its
  identity: each profile's `aws sts get-caller-identity` comes first; the one signed in to `ciamBillingAccountRef` reads
  the budgets, the other the organization's policies (checked against `ciamOrganizationRef` as above). A third profile,
  or a second one for the same purpose, is a problem. AWS Budgets' endpoint is global (listed under us-east-1) with no
  FIPS endpoint, so its calls name `--region us-east-1` and never set `AWS_USE_FIPS_ENDPOINT`.
- `aws/terraform-state`: (a) by default the state object a collection source names, read with `aws s3 cp URI -` (no
  `terraform init`, no lock):

  ```ldif
  dn: cn=tf-state,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops
  objectClass: ciamCollectionSource
  ciamBindingRole: collect-tf-state
  ciamImporter: aws/terraform-state
  ciamSourceRef: s3://example-ciam-tf-state/env:/prod/ciam/terraform.tfstate
  ```

  (b) `--terraform-dir DIR` (the collector's option, opsdir-format-terraform's `TERRAFORM_DIR`): `terraform state pull` in that initialized working directory, the backend as configured
  there.
- `aws/cloudformation`: the stacks collection sources name (`ciamImporter: aws/cloudformation`, `ciamSourceRef:
  cfn://<stack name>` in the cloud's region, or the stack's ARN; a stack in another account is refused), each into its
  own folder as the script under "Reading an environment from its CloudFormation stacks" saves it: `describe-stacks`
  projected to the stack ID, name, status and parameters (Outputs, which can carry values, are never fetched),
  `list-stack-resources`, and `get-template --template-stage Processed` (transforms expanded); then each nested stack
  (an `AWS::CloudFormation::Stack` resource that was created) the same way, in its own folder. Without a source,
  nothing is collected: which stacks belong to an environment is the operator's statement, not a guess.

  ```ldif
  dn: cn=stack-app,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops
  objectClass: ciamCollectionSource
  ciamBindingRole: collect-stack-app
  ciamImporter: aws/cloudformation
  ciamSourceRef: cfn://ciam-prod-app
  ```

Least privilege: a role with exactly these actions (AWS managed read-only policies grant more, some of it data):
`ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`,
`ec2:DescribeSecurityGroupRules`, `ec2:DescribeNatGateways`, `ec2:DescribeRouteTables`, `ec2:DescribeNetworkAcls`,
`ec2:DescribeVpcEndpoints`, `ec2:DescribeVpcEndpointServiceConfigurations`, `ec2:DescribeVpcEndpointServicePermissions`,
`ec2:DescribeVpcPeeringConnections`, `ec2:DescribeTransitGatewayVpcAttachments`, `ec2:DescribeVpnConnections`,
`ec2:DescribeCustomerGateways`, `ec2:DescribeVpnGateways`, `ec2:DescribeFlowLogs`, `ec2:DescribeVolumes`;
`elasticloadbalancing:DescribeLoadBalancers`, `DescribeTargetGroups`, `DescribeListeners`, `DescribeTags`,
`DescribeLoadBalancerAttributes`, `DescribeTargetHealth`, `DescribeTargetGroupAttributes` (and `DescribeTrustStores`
where the record has a trust policy checked at the edge);
`secretsmanager:ListSecrets`, `secretsmanager:GetResourcePolicy`; `kms:ListKeys`, `kms:DescribeKey`,
`kms:GetKeyRotationStatus`, `kms:GetKeyPolicy`; `s3:ListAllMyBuckets`, `s3:GetBucketVersioning`,
`s3:GetBucketObjectLockConfiguration`, `s3:GetEncryptionConfiguration`, `s3:GetBucketPublicAccessBlock`,
`s3:GetLifecycleConfiguration`, `s3:GetReplicationConfiguration`, `s3:GetBucketPolicy` (and `s3:GetObject` on the
Terraform state object only); `lambda:ListFunctions`, `lambda:ListTags`; `events:ListRules`,
`events:ListTargetsByRule`; `scheduler:ListSchedules`, `scheduler:GetSchedule`; `codepipeline:ListPipelines`,
`codepipeline:GetPipeline`; `codebuild:ListProjects`, `codebuild:BatchGetProjects`; `wafv2:ListWebACLs`,
`wafv2:GetWebACL`, `wafv2:ListResourcesForWebACL`, `wafv2:ListIPSets`, `wafv2:GetIPSet`; `shield:ListProtections`;
`cloudfront:ListDistributions`; `route53:ListHostedZones`, `route53:ListResourceRecordSets`;
`route53resolver:ListResolverRules`; `network-firewall:ListRuleGroups`, `DescribeRuleGroup`, `ListFirewallPolicies`,
`DescribeFirewallPolicy`, `ListFirewalls`, `DescribeFirewall`; `rds:DescribeDBInstances`, `DescribeDBClusters`,
`DescribeDBSubnetGroups`, `DescribeDBParameterGroups`, `DescribeDBParameters`, `DescribeDBClusterParameterGroups`,
`DescribeDBClusterParameters`; `dlm:GetLifecyclePolicies`, `dlm:GetLifecyclePolicy`; `backup:ListBackupVaults`,
`ListTags`, `ListBackupPlans`, `GetBackupPlan`, `ListBackupSelections`, `GetBackupSelection`;
`cloudtrail:DescribeTrails`, `GetEventSelectors`, `ListTags`; `autoscaling:DescribeAutoScalingGroups`;
`ec2:DescribeLaunchTemplateVersions`; `eks:ListClusters`, `DescribeCluster`, `ListNodegroups`, `DescribeNodegroup`,
`ListAddons`, `DescribeAddon`; `cloudwatch:DescribeAlarms`, `ListTagsForResource`; `logs:DescribeLogGroups`,
`ListTagsForResource`; `synthetics:DescribeCanaries`; `sns:ListTopics`, `ListTagsForResource`; `sqs:ListQueues`,
`GetQueueAttributes`, `ListQueueTags`; `events:ListEventBuses`, `ListTagsForResource`; `kinesis:ListStreams`,
`ListTagsForResource`; `ses:ListEmailIdentities`, `GetEmailIdentity`; `ec2:DescribeInstanceConnectEndpoints`;
`guardduty:ListDetectors`, `GetDetector`, `DescribeOrganizationConfiguration`; `inspector2:BatchGetAccountStatus`,
`DescribeOrganizationConfiguration`; `config:DescribeConfigurationRecorders`, `DescribeDeliveryChannels`,
`DescribeRetentionConfigurations`; `securityhub:DescribeHub`, `GetEnabledStandards`,
`DescribeOrganizationConfiguration`; `budgets:ViewBudget`, `budgets:ListTagsForResource` (a GovCloud cloud's: in its
standard account, through its profile);
`iam:GetAccountAuthorizationDetails`;
`sso:ListInstances`, `ListPermissionSets`, `DescribePermissionSet`, `GetInlinePolicyForPermissionSet`,
`ListManagedPoliciesInPermissionSet`, `ListAccountAssignments`; `cloudformation:DescribeStacks`,
`ListStackResources`, `GetTemplate` (CloudFormation stacks only). For the organization profile (the management
account or a delegated administrator for policy management): `organizations:DescribeOrganization`, `ListParents`,
`ListPoliciesForTarget`, `DescribePolicy`. `sts:GetCallerIdentity` needs no permission. The
tests pin every (service, operation) the collector may run (`tests/test_aws_collect.py`, OPERATIONS) and refuse any
call that returns secret material.

## AWS Private CA inventory (`aws/private-ca`)

The importer `aws/private-ca` reads the CAs the account owns in the cloud's region into the core pki domain
(certificate authorities, revocation endpoints, CA-scoped templates and issued-certificate inventories), metadata
only: never a key. **Collect** with `opsdir collect --adapter aws/private-ca --env CLOUD/ENV` (after the same
`aws sts get-caller-identity` check as the other collectors), or **import** a saved export with
`opsdir import --change CHG-… --at YYYYMMDDhhmmssZ aws/private-ca DIR` (an inventory is dated: `--at` is required).

What each CA becomes:
- **The CA** (`ou=certificate-authorities`, cn its certificate's subject CN, else its configured subject's, else its
  id; `ciamProviderRef` its ARN): `ciamCaType` root or subordinate, `ciamCaState` (ACTIVE active; CREATING and
  PENDING_CERTIFICATE pending; DISABLED, EXPIRED, FAILED; DELETED deleted, restorable until `RestorableUntil`:
  `ciamCaRestorableUntil`),
  `ciamCaKeyAlgorithm` (`EC_secp384r1`, `RSA_4096`, ...), `ciamCaKeyStorage` (`KeyStorageSecurityStandard`, such as
  `FIPS_140_2_LEVEL_3_OR_HIGHER`; AWS-managed HSM keys, so no `ciamCaKeyRef`) and, for a subordinate,
  `ciamParentAuthority`: the CA in the export (else the record) whose certificate's subject is its issuer.
- **Its revocation endpoints**, as it writes them into what it issues: `crl-1`
  `http://<CustomCname, else <bucket>.s3.<region>.amazonaws.com>/<CustomPath, else crl>/<CA id>.crl` (none when the
  CDP extension is omitted; a partitioned CRL's file name is a GUID per partition, kept as the template
  `{partition}`), and `ocsp-1` `http://<OcspCustomCname, else ocsp.acm-pca.<region>.amazonaws.com>`.
- **Its templates**: each AWS template the newest audit report shows the CA issued from, as the CA's own template
  (cn `<CA>/<template name>`, such as `Example Aero Cloud Issuing CA/EndEntityCertificate/V1`): the extended key
  usages AWS fixes for the template's family (EndEntity: server and client authentication; EndEntityClientAuth;
  EndEntityServerAuth; CodeSigning; OCSPSigning; none for the Blank* and CA templates), the subject always from the
  request (the CSR), no approval or signature, and no validity of its own (the CA's bounds it). Who may request from
  it (`ciamEnrollee`, `ciamEnrollmentScope`): the account's IAM principals whose policies allow
  `acm-pca:IssueCertificate` on the CA (Action or NotAction, Resource or NotResource, wildcards; an
  `acm-pca:TemplateArn` condition narrows them to its templates; a deny takes them away), the CA's resource policy
  (every principal, or another account: broad), and when ACM issued from the template and the CA grants ACM
  (`list-permissions`), the principals allowed `acm:RequestCertificate` (`<ARN> (through ACM)`). Any other condition,
  or a managed policy whose document the export doesn't hold, makes it unknown; permissions boundaries, session
  policies and organization control policies only take access away and aren't judged.
- **Its inventory**: the newest audit report. AWS has no call that lists a CA's certificates, and creating a report is
  a write (`acm-pca:CreateCertificateAuthorityAuditReport`, at most one per 30 minutes), so `opsdir collect` never
  creates one: the CA's owner does, on a schedule (an EventBridge Scheduler schedule calling
  `CreateCertificateAuthorityAuditReport` with the JSON format into the report bucket, under a role allowed that one
  action). The inventory is dated at that report: complete when it is less than a day older than `--at`, else
  incomplete, and incomplete without one; the problem names the command that creates it. Each row (cn its serial as
  hex) is serial, subject as AWS writes it, validity, template, ACM as the requester of what ACM issued, and once
  revoked when and why (the RFC 5280 name).

Where the reports are: a collection source for `aws/private-ca` names the bucket (`ciamSourceRef s3://<bucket>`, one
source); without one no report is read. The export, as `opsdir collect` saves it:

```sh
REGION=us-east-1; BUCKET=<the audit-report bucket>
aws acm-pca list-certificate-authorities --resource-owner SELF --output json --region $REGION > private-ca/cas.json
aws acm-pca list-certificate-authorities --resource-owner OTHER_ACCOUNTS --output json --region $REGION \
  --query '{CertificateAuthorities: CertificateAuthorities[].{Arn: Arn, OwnerAccount: OwnerAccount, Status: Status}}' \
  > private-ca/shared-cas.json                     # named only: their owner holds their audit reports
aws iam get-account-authorization-details --output json --query '<collect.py IAM_POLICIES>' > private-ca/iam.json
# per CA <id> (its ARN <arn>):
aws acm-pca get-certificate-authority-certificate --certificate-authority-arn <arn> ... > private-ca/<id>/certificate.json
aws acm-pca get-policy --resource-arn <arn> ...                 > private-ca/<id>/policy.json      # none: left out
aws acm-pca list-permissions --certificate-authority-arn <arn> ... > private-ca/<id>/permissions.json
aws s3api list-objects-v2 --bucket $BUCKET --prefix audit-report/<id>/ \
  --query "Contents[?ends_with(Key, '.json')].{Key: Key, LastModified: LastModified}" ... > private-ca/<id>/audit-reports.json
aws s3 cp s3://$BUCKET/<the newest key> -                       > private-ca/<id>/audit-report.json
```

Least privilege for the collecting login: `acm-pca:ListCertificateAuthorities` (resource `*`),
`acm-pca:GetCertificateAuthorityCertificate`, `acm-pca:GetPolicy` and `acm-pca:ListPermissions` (scopable to the CAs'
ARNs), `iam:GetAccountAuthorizationDetails`, and on the report bucket `s3:ListBucket` (prefix `audit-report/`) and
`s3:GetObject` (`audit-report/*`), plus `kms:Decrypt` when the reports are encrypted with a customer key. The AWS
managed policy `AWSPrivateCAReadOnly` covers the `acm-pca` part; `AWSPrivateCAAuditor` also grants
`CreateCertificateAuthorityAuditReport` (a write) and isn't needed.

GovCloud (US): AWS Private CA is offered in us-gov-west-1 and us-gov-east-1 (AWS GovCloud (US) User Guide,
govcloud-acmpca.html: endpoints `acm-pca.us-gov-*.amazonaws.com`, ARNs `arn:aws-us-gov:acm-pca:...`), in scope for
FedRAMP High and DoD SRG IL2, IL4 and IL5 there (AWS services in scope by compliance program, October 2026).
Sources disagree on its FIPS endpoints: AWS's FIPS endpoints table lists the plain GovCloud names as FIPS endpoints,
while the General Reference (pca.html) lists no `-fips` name for GovCloud; how the AWS CLI resolves
`AWS_USE_FIPS_ENDPOINT=true` for acm-pca there is unverified. The GovCloud page documents no feature differences
(OCSP, short-lived mode, custom CNAMEs, partitioned CRLs, ACM): their silence isn't proof of parity. The importer names
the CRL and OCSP hostnames it derives in GovCloud, since only the general patterns are documented.

Known limits: not run against a live account (recorded fixtures follow the AWS CLI reference's documented shapes). An
audit report holds no certificate, so no fingerprint: a record certificate is found by its serial (then subject and
validity), and AWS writes the subject in its own form; the CSV report form isn't read. The audit report's completeness
for short-lived-certificate-mode CAs isn't documented. Whether Private CA writes a CA-issuers AIA URL isn't
documented: none is recorded. CAs shared from other accounts are named only. A CA that is disabled, expired or deleted
isn't judged by the planner yet (deferred). The importer's sources: AWS CLI reference (acm-pca), AWS Private CA User
Guide (PcaAuditReport, crl-planning, ocsp-customize, template-varieties, template-definitions), Service Authorization
Reference (list_acm-pca).

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
aws elbv2 describe-trust-stores                                        > $out/trust-stores.json   # where a trust policy is checked at the edge
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

# Cognito user pools: each pool projected to its id, name, ARN, tags and custom domain (no app client or identity
# provider is described: they carry secrets)
mkdir -p $out/user-pools
for i in $(aws cognito-idp list-user-pools --max-results 60 --query 'UserPools[].Id' --output text); do
  aws cognito-idp describe-user-pool --user-pool-id "$i" \
    --query '{UserPool: UserPool.{Id: Id, Name: Name, Arn: Arn, UserPoolTags: UserPoolTags, CustomDomain: CustomDomain}}' \
                                                                                 > "$out/user-pools/$i.json"
done

# managed Microsoft AD directories: projected to ID, type, domain, NetBIOS name, edition, VPC and regions (a
# directory's RADIUS settings carry a shared secret), then each Microsoft AD directory's tags
aws ds describe-directories --query '{DirectoryDescriptions: DirectoryDescriptions[].{DirectoryId: DirectoryId, Type: Type, Name: Name, ShortName: ShortName, Edition: Edition, VpcSettings: {VpcId: VpcSettings.VpcId}, RegionsInfo: {AdditionalRegions: RegionsInfo.AdditionalRegions}}}' > $out/directories.json
mkdir -p $out/directory-tags
for d in $(aws ds describe-directories --query "DirectoryDescriptions[?Type=='MicrosoftAD'].DirectoryId" --output text); do
  aws ds list-tags-for-resource --resource-id "$d"                              > "$out/directory-tags/$d.json"
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

# compute groups: the autoscaling groups and the launch template version each uses (projected: never user data),
# kept for the groups in the environment's VPC (by their subnets); EKS clusters with their node groups and add-ons
aws autoscaling describe-auto-scaling-groups                                     > $out/autoscaling-groups.json
mkdir -p $out/launch-templates $out/eks
for ref in $(aws autoscaling describe-auto-scaling-groups --query 'AutoScalingGroups[].[LaunchTemplate || MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification][] | [].join(`","`, [LaunchTemplateId, Version || `"$Default"`])' --output text); do
  id=${ref%%,*}; v=${ref#*,}
  aws ec2 describe-launch-template-versions --launch-template-id "$id" --versions "$v" \
    --query '{LaunchTemplateVersions: LaunchTemplateVersions[].{LaunchTemplateId: LaunchTemplateId, LaunchTemplateName: LaunchTemplateName, VersionNumber: VersionNumber, DefaultVersion: DefaultVersion, LaunchTemplateData: {ImageId: LaunchTemplateData.ImageId, InstanceType: LaunchTemplateData.InstanceType, MetadataOptions: {HttpTokens: LaunchTemplateData.MetadataOptions.HttpTokens}, BlockDeviceMappings: LaunchTemplateData.BlockDeviceMappings, TagSpecifications: LaunchTemplateData.TagSpecifications}}}' \
                                                                                 > "$out/launch-templates/$id-${v//\$/}.json"
done
for c in $(aws eks list-clusters --query 'clusters[]' --output text); do
  aws eks describe-cluster --name "$c"                                           > "$out/eks/$c.json"
  for g in $(aws eks list-nodegroups --cluster-name "$c" --query 'nodegroups[]' --output text); do
    aws eks describe-nodegroup --cluster-name "$c" --nodegroup-name "$g"         > "$out/eks/$c-nodegroup-$g.json"
  done
  for a in $(aws eks list-addons --cluster-name "$c" --query 'addons[]' --output text); do
    aws eks describe-addon --cluster-name "$c" --addon-name "$a"                 > "$out/eks/$c-addon-$a.json"
  done
done

# monitoring: metric alarms, log groups, Synthetics canaries (projected) and SNS topics, each one's tags saved by its
# name (list-tags-for-resource doesn't name its resource; a log group's name percent-encoded: / as %2F)
mkdir -p $out/alarm-tags $out/log-group-tags $out/topic-tags
aws cloudwatch describe-alarms                                                   > $out/alarms.json
for row in $(aws cloudwatch describe-alarms --query 'MetricAlarms[].join(`","`, [AlarmArn, AlarmName])' --output text); do
  aws cloudwatch list-tags-for-resource --resource-arn "${row%%,*}"              > "$out/alarm-tags/${row#*,}.json"
done
aws logs describe-log-groups                                                     > $out/log-groups.json
for row in $(aws logs describe-log-groups --query 'logGroups[].join(`","`, [logGroupArn, logGroupName])' --output text); do
  name=${row#*,}
  aws logs list-tags-for-resource --resource-arn "${row%%,*}"                    > "$out/log-group-tags/${name//\//%2F}.json"
done
aws synthetics describe-canaries --query '{Canaries: Canaries[].{Name: Name, Schedule: Schedule, Tags: Tags, EngineArn: EngineArn, ArtifactS3Location: ArtifactS3Location, ExecutionRoleArn: ExecutionRoleArn, RuntimeVersion: RuntimeVersion}}' \
                                                                                 > $out/canaries.json
aws sns list-topics                                                              > $out/topics.json
for t in $(aws sns list-topics --query 'Topics[].TopicArn' --output text); do
  aws sns list-tags-for-resource --resource-arn "$t"                             > "$out/topic-tags/${t##*:}.json"
done

# messaging: SQS queues (ARN and tags, projected, saved by queue name), EventBridge buses and Kinesis streams with
# their tags (saved by name, a partner bus's percent-encoded; the default bus is left out), SES domain identities
# (projected: their DKIM status and tags, saved by domain; addresses aren't read)
mkdir -p $out/queues $out/queue-tags $out/event-bus-tags $out/stream-tags $out/email-identities
for url in $(aws sqs list-queues --query 'QueueUrls[]' --output text); do
  q=${url##*/}
  aws sqs get-queue-attributes --queue-url "$url" --attribute-names QueueArn \
    --query '{QueueArn: Attributes.QueueArn}'                                    > "$out/queues/$q.json"
  aws sqs list-queue-tags --queue-url "$url" --query '{Tags: Tags}'              > "$out/queue-tags/$q.json"
done
aws events list-event-buses                                                      > $out/event-buses.json
for row in $(aws events list-event-buses --query 'EventBuses[?Name!=`default`].join(`","`, [Arn, Name])' --output text); do
  name=${row#*,}
  aws events list-tags-for-resource --resource-arn "${row%%,*}"                  > "$out/event-bus-tags/${name//\//%2F}.json"
done
aws kinesis list-streams                                                         > $out/streams.json
for row in $(aws kinesis list-streams --query 'StreamSummaries[?StreamStatus!=`DELETING`].join(`","`, [StreamARN, StreamName])' --output text); do
  aws kinesis list-tags-for-resource --resource-arn "${row%%,*}"                 > "$out/stream-tags/${row#*,}.json"
done
for d in $(aws sesv2 list-email-identities --query 'EmailIdentities[?IdentityType==`DOMAIN`].IdentityName' --output text); do
  aws sesv2 get-email-identity --email-identity "$d" \
    --query '{IdentityType: IdentityType, DkimAttributes: {Status: DkimAttributes.Status}, Tags: Tags}' \
                                                                                 > "$out/email-identities/$d.json"
done

# access paths: EC2 Instance Connect Endpoints in the environment's VPC
aws ec2 describe-instance-connect-endpoints --filters "Name=vpc-id,Values=$VPC"  > $out/instance-connect-endpoints.json

# security services: GuardDuty's detectors (get-detector doesn't name its detector: saved by its id), Inspector's
# account status, AWS Config's recorders, delivery channels and retention, Security Hub and its standards. Each
# service's organization configuration answers only in its delegated administrator's account (saved there under
# organization-configuration/; elsewhere the call fails and the service reads as the account's own). The EventBridge
# rules routing their findings are rules.json and event-targets/ above.
mkdir -p $out/guardduty $out/organization-configuration
for d in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text); do
  aws guardduty get-detector --detector-id "$d"                                  > "$out/guardduty/$d.json"
  aws guardduty describe-organization-configuration --detector-id "$d" \
    > "$out/organization-configuration/guardduty-$d.json" || rm -f "$out/organization-configuration/guardduty-$d.json"
done
aws inspector2 batch-get-account-status                                          > $out/inspector2.json
aws configservice describe-configuration-recorders                               > $out/config-recorders.json
aws configservice describe-delivery-channels                                     > $out/config-channels.json
aws configservice describe-retention-configurations                              > $out/config-retention.json
aws securityhub describe-hub > $out/securityhub-hub.json || rm -f $out/securityhub-hub.json    # not enabled: none
aws securityhub get-enabled-standards > $out/securityhub-standards.json || rm -f $out/securityhub-standards.json
for svc in inspector2 securityhub; do
  aws $svc describe-organization-configuration > "$out/organization-configuration/$svc.json" \
    || rm -f "$out/organization-configuration/$svc.json"
done

# budgets: each budget's notifications, their subscribers (SNS topics only: no e-mail addresses) and its tags, saved
# under budgets/<account>/<budget>/ (the outputs name no account or budget; a budget's name percent-encoded, / as %2F).
# A GovCloud cloud's budgets: signed in to its standard account, ACCOUNT that account's ID. No FIPS endpoint exists.
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
mkdir -p $out/budgets
aws budgets describe-budgets --account-id "$ACCOUNT" --region us-east-1           > "$out/budgets/$ACCOUNT.json"
aws budgets describe-budgets --account-id "$ACCOUNT" --region us-east-1 --query 'Budgets[].BudgetName' --output text \
  | tr '\t' '\n' | while IFS= read -r b; do
  d="$out/budgets/$ACCOUNT/${b//\//%2F}"; mkdir -p "$d"
  aws budgets describe-notifications-for-budget --account-id "$ACCOUNT" --budget-name "$b" --region us-east-1 > "$d/notifications.json"
  aws budgets list-tags-for-resource --resource-arn "arn:aws:budgets::$ACCOUNT:budget/$b" --region us-east-1 > "$d/tags.json"
  count=$(aws budgets describe-notifications-for-budget --account-id "$ACCOUNT" --budget-name "$b" --region us-east-1 \
          --query 'length(Notifications)' --output text)
  for i in $(seq 0 $((count - 1))); do
    n=$(aws budgets describe-notifications-for-budget --account-id "$ACCOUNT" --budget-name "$b" --region us-east-1 \
        --query "Notifications[$i]" --output json)
    aws budgets describe-subscribers-for-notification --account-id "$ACCOUNT" --budget-name "$b" --notification "$n" \
      --query "{Subscribers: Subscribers[?SubscriptionType=='SNS']}" --region us-east-1 > "$d/subscribers-$i.json"
  done
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
# signed in to the organization's management account (ACCOUNT still the environment's): its control policies (the
# account's own here; `opsdir collect` with an aws-profile:// source also reads those its OUs and the root inherit)
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
- **Messaging** is read as from Terraform state (`opsdir_adapter_aws.cli_messaging`): SQS queues by their ARN (`get-queue-attributes`, projected to `QueueArn` or as printed), EventBridge buses, Kinesis streams (deleting ones skipped) and SES identities (`get-email-identity` doesn't name its identity: save it as `email-identities/<identity>.json`; its ARN is built in the environment's partition, region and account, told from a subnet's ARN). `list-queue-tags` and `list-tags-for-resource` don't name their resource: save them as `queue-tags/<queue>.json`, `event-bus-tags/<bus>.json`, `stream-tags/<stream>.json`. SNS topics are monitoring's (`topic-tags/`).
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

Or let `opsdir collect` run these calls for the stacks collection sources name (see "Collecting from AWS"); it follows nested stacks too.

The template says what each resource is declared with; the stack's resources give the IDs the record matches on (`vpc-…`, `i-…`, ARNs), so a stack without its resource listing is read for nothing and named, and so is a folder without a template. The Terraform state of a root kept beside the stacks (`*.tfstate` anywhere in the environment's folder: what an opsdir CloudFormation render keeps in Terraform, applied) is read with them, so one import sees the whole environment. Values are resolved from the stack's parameters (else the template's defaults), pseudo parameters (`AWS::Region`, `AWS::AccountId`, … from the stack ID) and physical IDs: `Ref`, `Fn::Sub`, `Fn::Join`, `Fn::Select`, and `Fn::GetAtt` where it links resources (a Route 53 alias to its load balancer, a NAT gateway or load balancer to its Elastic IP's address). JSON and YAML templates are read, short tags (`!Ref`, `!Sub`, `!GetAtt`, …) included.

What the stacks declare is read into the same resources as Terraform state (the mapping is shared: VPCs, subnets, instances, security groups and ingress rules, load balancers with listeners and target groups, Route 53 records with their routing, Secrets Manager secrets with rotation schedules, KMS keys, S3 buckets, NAT gateways, Lambda functions, EventBridge rules and their targets (`Fn::GetAtt X.Arn` resolves to X's ARN), Scheduler schedules, CodePipeline pipelines, CodeBuild projects, CloudTrail trails (with their event selectors); IAM roles and policies, OIDC providers, control policies and Identity Center; the edge (CloudFront, WAF, Shield, health checks, Resolver rules); RDS instances, Aurora clusters and their subnet and parameter groups, Macie custom data identifiers; GuardDuty detectors with their features, AWS Config recorders and delivery channels, Security Hub and its standards (Inspector's enabler and Config's retention have no CloudFormation type: a render keeps them in Terraform, read beside the stacks), Security Hub automation rules and GuardDuty filters, and the EventBridge rules routing findings, by their event patterns; log groups, metric alarms and Synthetics canaries; EBS volumes with their attachments, Lifecycle Manager policies, AWS Backup vaults (with their lock), plans and selections; budgets with their notifications' SNS topics; autoscaling groups and their launch templates (5.8: through the CLI's normalizers; a group's physical id is its name, which the record's ARN ends in, so it matches the recorded group and the record keeps the ARN); 5.6d, kinds the render never writes, in a template written by hand: EKS clusters with node groups and add-ons (a node group named only by its `Ref`, `<cluster>/<node group>`, by its last part), Route 53 hosted zones (private when they name VPCs), S3 bucket policies and Secrets Manager resource policies (a secret policy's `Ref` is the secret's ARN, also when its `SecretId` names it), EC2 Instance Connect Endpoints, SQS queues (`Ref` its URL), SNS topics, EventBridge buses (partner buses' names whole), Kinesis streams and SES identities (whether SES verified a domain's DKIM isn't in a template: the record keeps it); ARNs built from the stack's partition, region and account), so the table above, roles and `roles.json` apply unchanged. A KMS key's rotation is off unless the template sets `EnableKeyRotation`, as in CloudFormation. Named in the notices:

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

## Quota limits (a provider prerequisite)

Environments record what they need of AWS's limits (core `estate`: `ciamQuotaNeed`, by kind or by `ciamProviderRef` `<service code>.<quota code>`). The adapter maps the kinds to the quota codes AWS's quota tables give: `vcpus` `ec2.L-1216C47A` (Running On-Demand Standard instances), `public-ips` `ec2.L-0263D0A3` (EC2-VPC Elastic IPs), `networks` `vpc.L-F678F1CE` (VPCs per Region), `load-balancers` `elasticloadbalancing.L-53DA6B97` (Application Load Balancers per Region), `database-instances` `rds.L-7B6409FD`, `kubernetes-clusters` `eks.L-1194D53C`. The prerequisite `aws-quotas` is met once every account and region whose environments record needs has its limits; `aws/quotas` fetches them, its commands derived from the record (each region of those clouds, each service the needs name):

```sh
opsdir import aws/quotas --run --change CHG-…    # sts get-caller-identity, then per region and service
                                                 # list-aws-default-service-quotas and list-service-quotas
```

Applied values take precedence over AWS's defaults (`list-service-quotas` leaves out quotas without an applied value). Only the quotas the environments need are kept, in the catalog of the caller's account and the region (`cn=aws:<account>:<region>,ou=quotas`). The codes are the commercial partition's; a GovCloud list lacking one leaves that quota for the planner to name. An increase the operator decided to request (the plan's fix, `ciamQuotaDecision request`) is rendered as `aws_servicequotas_service_quota` at `ciamQuotaRequested` (else the need): AWS is asked when the value is above the applied one; destroying it changes nothing.

## Budgets

Each budget the platform team keeps (core `estate`: `ciamBudget`) is rendered as `aws_budgets_budget` (COST, `limit_amount`/`limit_unit`, `MONTHLY`/`QUARTERLY`/`ANNUALLY`), filtered by the tag policy's environment tag (`TagKeyValue` `user:<key>$<cloud/env>`: activate the tag as a cost allocation tag) or, without one, by the account (`LinkedAccount`), with a `GREATER_THAN` percentage notification per `ciamActualThreshold` (`ACTUAL`) and `ciamForecastThreshold` (`FORECASTED`) to the SNS topic of the channel its `ciamAlertRole` names. AWS Budgets publishes only to a topic in the budget's own account whose policy lets `budgets.amazonaws.com` publish; a channel elsewhere is a `# NOTE` and the notifications are left out. A GovCloud cloud's billing is managed only in its associated standard account: its budgets go through the provider aliased `billing` (us-east-1, `allowed_account_ids` the cloud's `ciamBillingAccountRef`; none: a `# NOTE`), with a comment that how a filter isolates one GovCloud account's spend there isn't documented. Read back from Terraform state as budgets (COST, those periods; percentage thresholds; the first topic as the channel), and the same from the CLI (`cli_budgets.py`, saved by account under `budgets/`) and CloudFormation (`AWS::Budgets::Budget`); a notification the CLI prints without its `ThresholdType` isn't read as a percentage.

## Landing zone

What the platform needs from the organization rather than its own Terraform is rendered per environment into `terraform/landing-zone/` (its own root: `providers.tf`, `main.tf`) for whoever keeps the landing zone: the header names them (the owners of the environment's guardrails, else of its cloud, else of the environment) and the MANIFEST marks the files `landing-zone`. Nothing is rendered when the environment needs nothing from one. When the target lacks a guardrail's prevention or a way in the source has, the planner drafts a request to that owner (`requests/<owner>.md`).

| From the record | Rendered as |
|---|---|
| Deployer principals whose identity binding trusts an OIDC issuer (`ciamTrustedBy`: `<issuer URL> <subject>`, a CI pipeline) | `aws_iam_openid_connect_provider` per issuer (audience `sts.amazonaws.com`), and per deployer an `aws_iam_role` assumable only with that pipeline's tokens (`sts:AssumeRoleWithWebIdentity`, `<host>:aud` and `<host>:sub` pinned) with its least-privilege policy |
| Operator principals whose identity binding names a group (`ciamIdentityKind` group or permission-set; the group id as provider ref) | IAM Identity Center: `aws_ssoadmin_permission_set` (4-hour sessions), its permissions as `aws_ssoadmin_permission_set_inline_policy`, `aws_ssoadmin_account_assignment` to the group in `var.account_id` |
| Guardrails' denials (`ciamDenies`) | One `aws_organizations_policy` (service control policy) per guardrail attached to `var.guardrail_target_id` (an OU or account): `region-escape` (AWS's region-control statement: global services exempt; the regions it allows are the cloud's region and those the environment's residency allows, core `estate` domain), `audit-log-disable` (CloudTrail changes on every trail; creation allowed), `service-account-keys` (`iam:CreateAccessKey`), `metadata-v1` (`ec2:RunInstances` without IMDSv2), `root-use` (the root user, bucket policies exempt), `key-deletion` (`kms:ScheduleKeyDeletion`, `DeleteAlias`, `DeleteCustomKeyStore`, `DeleteImportedKeyMaterial`). From AWS's examples (`aws-samples/service-control-policy-examples`) without their privileged-role exemptions. `public-storage` is an Organizations S3 policy (`aws_organizations_policy` of type `S3_POLICY`, named `<policy>-s3`, attached to the same target: all four S3 Block Public Access settings for every account it applies to), with an action note to enable the S3 policy type on the organization's root; read back as its guardrail's `public-storage` |

### Network plumbing

The network's plumbing is the landing zone's, never the platform pipeline's: NAT egress, route tables, network ACLs, interconnects and flow logs render into the landing zone owner's root, `terraform/landing-zone/network.tf`, with each root's inputs in its `providers.tf`. Plumbing whose `ciamManagedBy` names another party (a network team), and private endpoints and egress firewalls kept elsewhere, render into that party's own root, `terraform/landing-zone/<party>/`, when the party takes generated infrastructure; otherwise they are named and asked of it (Who keeps what, above). A binding with a provider ref already exists, so it gets a Terraform `import` block to adopt it into the keeper's state. A binding without one is created, and the planner asks its keeper for it: one request per party (`requests/<party>.md`), each listing what isn't built yet and naming the root that holds everything they keep. The resources carry tags `Name` and `Role`, which the importers read back.

| From the record | Rendered as |
|---|---|
| NAT egress (`ciamEgress`) | `aws_nat_gateway`: public, its elastic IPs looked up by address (`data "aws_eip"`; secondary allocations for a range of up to 16), or private when its range is private; the public subnet is an input (`var.<egress>_subnet_id`) |
| Route table (`ciamRouteTable`) | `aws_route_table` with inline routes and `aws_route_table_association` per subnet role (import id `<subnet>/<table>`); the main table as `aws_default_route_table`. A route's target is the resource rendered in the same root (a NAT gateway, a peering, the VPN gateway), else the binding's provider ref, else the ref the route names. A route to a VPN goes to the VPC's VPN gateway, read from the root that writes it. Inputs are used for what only the keeper knows: `var.transit_gateway_id`, a Network Firewall's endpoint (`var.<firewall>_endpoint_id`), a VPN gateway when no VPN link is rendered. A route with no target to the internet goes to the VPC's internet gateway (`data "aws_internet_gateway"`). Local routes are implicit. Blackhole routes and `for <roles>` scopes are comments |
| Network ACL (`ciamNetworkAcl`) | `aws_network_acl` with its rules as `ingress` / `egress` entries on its subnets |
| Interconnect (`ciamInterconnect`, by `ciamLinkKind`) | `peering`: `aws_vpc_peering_connection` to the other environment's VPC (on AWS only, `peer_region` when it differs; the accepter is the other side's). `transit`: `aws_ec2_transit_gateway_vpc_attachment` on the environment's subnets. `vpn`: `aws_customer_gateway` (`ciamPeerGateway`, `ciamPeerAsn` or 65000), the VPC's `aws_vpn_gateway` (`ciamLocalAsn`; a VPC attaches one, so it is rendered once, with the environment's first VPN link, and the other links' connections read it, through an input when another keeper's root writes it), `aws_vpn_connection` (BGP when the peer's ASN is recorded, else static routes to `ciamAcceptedCidr`; no tunnel pre-shared key set and `preshared_key_storage = "SecretsManager"`: the VPN service generates the keys and keeps them in Secrets Manager, AWS answers them redacted, so Terraform state holds none (U.5, task 586; with the default Standard storage the provider reads them into `tunnelN_preshared_key` and `customer_gateway_configuration`). An action says where the other end's device reads them (the connection's `preshared_key_arn`) and, for an existing connection, to move its tunnels to that storage before it is adopted). `dedicated` (Direct Connect), `hub`, and links whose kind isn't recorded are comments |
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

Configuration management (`opsdir-adapter-ansible`) reads `aws-sm://` references at run time with the `amazon.aws.secretsmanager_secret` lookup (`ansible_lookup`; region and credentials from the controller's AWS configuration, as the CLI).

Values of `ciamCloudProvider` (`aws`), `ciamCloudEnvironment` (`public`), `ciamManagedService` (`cognito-user-pool`, `aws-managed-ad`) and `ciamDirectoryEdition` (`standard`, `enterprise`) are validated against this adapter. The store refuses AWS credential forms anywhere in the record: access key IDs (`AKIA…`, `ASIA…`) and secret access keys (`aws_secret_access_key = …`).

It adds no required roles or schema of its own (its planner checks are listed above); the environment's product adapters say which roles it must bind.

## Known limits

- **Private-CA trust in canaries is verified locally, not live.** The probes' CA trust ran against openssl-made root and intermediate-only private CAs over HTTPS and LDAPS on Python 3.12 and 3.14 (task 540); a canary on a live CloudWatch Synthetics runtime trusting a recorded CA stays with 7.2. A CA the record holds is always given to the check (a public root recorded there is harmless to add); the record says nothing of a CA it doesn't hold, so such a service's certificate is left to the runtime's own trust store.
- **Not yet run against a live account.** The Terraform and the importers follow the `hashicorp/aws` 6.x schema (the showcase's renders pass `terraform validate` against 6.69) and the AWS CLI's output shapes; `terraform plan` and an import from a real account are part of the testing plan (milestone 7.2, which starts on AWS).
- **No China partition.** China regions (`cn-*`, partition `aws-cn`) aren't recognized: their ARNs would be written with `aws`. GovCloud (US) is recognized by its region (above).
- **Port ranges** aren't recorded (`ciamPort` holds single ports): the importers name them; the renderer writes single ports only.
- **Services without an edge policy are TCP network load balancers.** With one, the renderer writes an application load balancer, its web ACL and Shield protection (see Edge); reading their listeners, TLS policies, certificates, web ACLs and Shield back comes with milestone 4.8's importers. An ALB's addresses are AWS's: a recorded frontend address isn't kept.
- **What the importers can't see:** egress rules, sources other than IPv4 CIDRs, key pairs, Image Builder pipelines (`ciamImageBuild` is recorded by hand), the monitoring above (log groups, alarms, canaries, alert topics) in CLI output, alert topics in CloudFormation stacks (Terraform state reads them all), KMS key protection, bucket encryption (4.10), CloudFront / WAF / API Gateway (edge importers, 4.8).
- **Cognito user pools** (6.1c): a target's pool, domain, clients, resource server and SAML partners render; its schema attributes, password policy, Lambda triggers, managed login branding, upstream OIDC providers, attribute mappings and user import aren't (the record doesn't hold them: the planner names claim transformations and how users move as actions). The SAML partners' metadata URLs are variables. Read back: the pool, its role, tag `Realizes` and custom domain only; its clients and providers (secrets) are never described.
- **Compute groups** (5.8): a launch template tags all its disks alike, so a group's volumes are named by its instances' tags (`BootVolume`, `DataVolumes`) and a disk carries no `Volume` tag or binding role of its own; disks naming different snapshot policies get no `SnapshotPolicy` tag (a backup plan on the group's tag `Role` covers them). An adopted group's existing launch template isn't imported: applying points the group at the rendered one. A launch template's root device name is a CloudFormation parameter, one per data source (a group's and its servers' for the same AMI are separate parameters).

## Tests

`tests/test_aws_audit.py`: control-plane audit trails: an account trail rendered into its bucket (an existing bucket's delivery statements named), one delivering only to a log group named; data events selecting the environment's own buckets but the trail's, with a management selector, or only the named ones' reads; an organization trail from the management account writing the organization's logs and streaming through its delivery role, and said so without a management account or with a stream that isn't a log group; the CloudFormation translation of selectors, stream, role and bucket policy; the activity event selectors record (basic and advanced); a trail read back from state with its bucket's role, from the CLI (a multi-region trail listed twice read once; selectors and tags by ARN) and from a CloudFormation stack (its ARN from the stack's region and account).

`tests/test_aws_cli_edge.py`: the edge from CLI output: the same facts and edge services as from state (attributes by file name, web ACL rules in CLI shape, Shield, CloudFront, hosted zones, record sets with TTL and routing, resolver rules).

`tests/test_aws_edge_state.py`: the edge read back from state: an ALB's facts equal to the policy that would render it, its web ACL, Shield and CloudFront as edge services named by the service they front, zones, records, a routed name's TTL and routing with the other environment's answer named, Resolver rules, the load balancer's own rules left out.

`tests/test_aws.py` (registration, vocabulary, secret resolution), `tests/test_aws_state.py` (the state importer: round trip, drift, new tagged and untagged resources, secrets and sensitive attributes never read, overlays, layout, a new binding keeps its provider reference, security group roles from their instances), `tests/test_aws_cli.py` (the CLI importer: round trip, facts state lacks, VPC scoping, counted account-wide listings, files placed by name, rules listed separately, `roles.json` never read as output, timestamps), `tests/test_aws_cloudformation.py` (round trip over two YAML/JSON stacks, drift, `GetAtt` and parameter links, resources not created, unknown files, secrets never read, a folder without a template, the resolver; IAM, the edge, DNS records, databases, suppressions, log groups, volumes, snapshot policies, backups, alarms and canaries, EKS, hosted zones, resource policies and Instance Connect, queues, topics, buses, streams and SES identities each read as the Terraform state of the same resources does; a partner bus's name kept whole), `tests/test_aws_compute.py` (an autoscaling group with its launch template, an untagged group, an EKS cluster with node groups and add-ons), `tests/test_aws_compute_groups.py` (5.8: a group rendered as a launch template with its role's disks and an autoscaling group in its subnets; an adopted one imported, its disks without one policy untagged; a template's disks read back as the role's volumes from state and the CLI), `tests/test_aws_messaging.py` (an SES domain identity with SPF, DKIM and DMARC from its DNS; queues and buses as stream carriers; the CLI's queues, buses, streams and SES identities read as the same record, an identity without the environment's ARN named), `tests/test_aws_observability.py` (a topic an alarm notifies as an alert channel, others as stream carriers; log groups with their retention, never-expire included; alarms and canaries with what they realize), `tests/test_aws_firewall_notices.py` (port ranges, all-ports rules and non-IPv4 sources named from state, CLI output and CloudFormation), `tests/test_aws_jobs.py` (functions, pipelines and build projects with their schedules from state, CLI output and CloudFormation; a tagged function placed as a job binding), `tests/test_aws_state_store.py` (state and CLI against Postgres: imported under an approved change, re-import changes nothing). The rendered Terraform is covered end to end by the showcase's golden outputs (`examples/showcase`, the source environment), and the importers by its cloud drift exports (`examples/showcase/exports/cloud/source`).

`tests/test_aws_cdn.py`: a distribution over the load balancer with a CloudFront web ACL and Shield, the us-east-1 certificate rule, an ALB behind CloudFront admitting only CloudFront; in GovCloud the distribution from the standard account with a CNAME, the standard account's certificate, and the comment without a recorded standard account.

`tests/test_aws_dns.py`: a failover pair answered from the primary's zone (alias, health-checked secondary), a weighted set, a name in someone else's zone, records in their zones, outbound forwarders as Resolver rules.

`tests/test_aws_edge.py`: the edge: TLS terms as ELB policies and back, an ALB with listener policy, ACM certificate, target groups (health, stickiness, draining) and security groups, the unbound certificate, the web ACL (address, country, rate-based rules on endpoint paths, managed groups, an exclusion out of scope), detect mode, account takeover's sign-in path, rate windows and header keys, Shield, a passthrough target group's tuning.

`tests/test_aws_cli_iam.py`: IAM from the CLI: authorization details (a URL-encoded trust, an AWS managed policy read), key and bucket policies by file, a secret's key, a control policy, Identity Center; the simulator's verdicts read back dated (the worst part, a missing context unknown, a role only simulated), preferred by the planner; the rendered `access/evaluate.sh`.

`tests/test_aws_iam.py`: IAM from state: a role's trust (service, OIDC subject), grants with conditions, NotAction denies, attached and managed policies, its boundary; key and bucket policies on the roles they name; permission sets by group; SCPs and RCPs with what they prevent; access paths (Instance Connect Endpoints from the CLI as from state); a secret's key by role; the planner's allowed, denied and unknown from what was imported.

`tests/test_aws_landing.py`: the landing zone: a deployer's OIDC trust and permissions, an operator group's access, the guardrails, the owner in the header, nothing rendered without need.

`tests/test_aws_access.py`: the AWS access table: a secret by its suffixed ARN or a pattern (not a longer name, not the bare ARN), objects in a bucket (reading also needs `s3:ListBucket`), a topic by stream kind, escalation actions. `tests/test_aws_identities.py`: a workload's IAM role, least-privilege policy and instance profile; notes for what can't be granted; the trust of the Kubernetes service accounts that assume it (IRSA), with EC2 only alongside servers.

`tests/test_aws_network.py`: the network depth the stack keeps: an interface endpoint with its security group and private DNS, a gateway endpoint on its subnets' and the main route tables, what AWS has no endpoint for, an endpoint service on an L4 service's NLB and not an ALB, the egress firewall's domain list (web traffic only), what others keep named, nothing rendered without records.

`tests/test_aws_backups.py`: AWS Backup rendered (vault with its key and lock, compliance grace, plan with its cron, window, retention and copies to an input vault, selection by tag `Role`; what it can't render said; others' named) and read back from state and the CLI (lock mode, schedule, copies, protected roles, vault link; several rules or ARN selections named).

`tests/test_aws_volumes.py`: disks and snapshot policies rendered (the boot volume on the root block device, data volumes as EBS volumes with attachments and tags, unencrypted or unbound-key volumes as recorded and said, Lifecycle Manager policies with encrypted copies by the multi-region key's replica or an input, an interval it can't take and others' policies named) and read back from state and the CLI (volumes grouped by their Volume tag, root disks, policies linked by target tag, untagged disks, count-based and disabled policies and unencrypted roots named; dlm-policies/ outputs not read as IAM policies; render-to-state round trip).

`tests/test_aws_cognito.py`: Cognito user pools: the descriptor (AWS's documented capabilities, GovCloud's differences, what stays not established), `Amazon Cognito` in the FedRAMP boundary; a target rendered (pool, MFA by its integrations, custom domain with its certificate, a client per OIDC client with its flows, scopes and secret, the resource server, the SAML partner and its metadata variable, notes; an adopted pool imported, a prefix domain), GovCloud's custom domain a comment, a neighbour a note; the CloudFormation translation; the planner on what AWS documents (no downstream SAML, no token exchange, GovCloud's custom domain, FIPS endpoints); read back from state, from a render and from the projected CLI output, never a client secret.

`tests/test_aws_databases.py`: managed databases rendered (an RDS instance with its subnet, security and parameter groups, key, RDS-managed password and import block; the ranges it admits as ingress rules on its security group, the engine's port when none is recorded; TLS as a parameter where it isn't the default; Aurora with an instance per zone; one someone else keeps named) and read back from state and the CLI (Aurora members, user-set parameters only, SSM parameters and passwords never read, VPC scoping, render-to-state round trip; the rules on its security groups as its ranges, not firewall rules).

`tests/test_aws_network_state.py`: the network depth read back: route tables (targets as provider refs, a Network Firewall endpoint as the firewall, gateway endpoints, main table), network ACLs (IPv6 named), VPC endpoints and their security groups left out of the rules, endpoint services, the egress firewall's domain list under its policy, peering, transit and VPN depth, flow logs; the CLI (local route and rule 32767 left out) and CloudFormation reading the same.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `aws`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.


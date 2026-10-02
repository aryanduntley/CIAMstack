# opsdir-adapter-aws

opsdir adapter for Amazon Web Services: Terraform for AWS environments; AWS Terraform state, AWS CLI output and CloudFormation stacks read back into the record; `aws-sm://` secret references.

**Applies to** environments whose cloud has `ciamCloudProvider: aws`, in the commercial partition (`ciamCloudEnvironment: public`). A provider adapter: it renders and reads an environment's infrastructure bindings; products (PingDS, PingFederate, …) are other adapters.

**Depends on** `opsdir`, `opsdir-format-terraform` (HCL formatting, the Terraform state reader) and `pyyaml` (CloudFormation templates).

## What it renders

Per environment, `terraform/providers.tf` (`hashicorp/aws ~> 5.0`; `region` from the cloud's `ciamRegion`; credentials come from the usual AWS environment, never from the record) and `terraform/main.tf`:

| From the record | Rendered as |
|---|---|
| The `network` binding: `ciamProviderRef` (the VPC ID) | `data aws_vpc` `main`: the landing zone owns the VPC |
| Subnet bindings: `ciamProviderRef` (the subnet ID) | `data aws_subnet` |
| One security group per server role | `aws_security_group` `ciam-<env>-<role>` in the VPC |
| Firewall rules | `aws_vpc_security_group_ingress_rule`, one per source CIDR and port (`ciamSourceCidr` × `ciamPort`), in the target role's group; protocol `ciamProtocol` (default `tcp`); description `<consumer or binding role> (<rule name>)`, the suffix the importers group rules back by |
| Servers | `aws_instance` (AMI `ciamImageRef`, `ciamInstanceSize`, the server's subnet, static `ciamPrivateIp`, its role's security group; encrypted root volume with the `disk-encryption` binding's KMS key, else an `UNBOUND` comment; tags `Name`, `Role`, `Hostname`, `Product`, `ManagedBy`) |
| Service names | Network load balancer, internal when `ciamFrontendIp` is private: one subnet mapping per subnet holding a target, the frontend address pinned in its subnet; a public one takes the Elastic IP allocation named by the service's `ciamProviderRef`. Per `ciamPort`: a TCP target group with a TCP health check, an attachment per server with the target role, a TCP listener. A Route 53 alias A record in `ciamDnsZoneRef` (target health evaluated) |
| Secret references (`aws-sm://<arn>`) | `data aws_secretsmanager_secret` per secret: metadata only, so a missing secret fails the plan and no value enters Terraform state (`aws_secretsmanager_secret_version` is never rendered) |
| The `backup-target` binding; the `pf-egress` binding | `data aws_s3_bucket` `ds_backups`; `data aws_nat_gateway` `pf_egress` (when it has a `ciamProviderRef`) |
| Required roles without a binding | `# UNBOUND: required role …` |

Not rendered: the VPC, subnets, NAT gateways, buckets, Elastic IPs and Route 53 zones themselves (referenced, the landing zone creates them); KMS keys (referenced by ARN); egress security group rules; key pairs, IAM instance profiles and user data; application load balancers and TLS listeners (services are TCP pass-through).

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
| `aws_secretsmanager_secret` (+ `aws_secretsmanager_secret_rotation`) | secret reference `aws-sm://<arn>`: automatic rotation and its function (`ciamRotationFunction`), last rotation when present | reference URI |
| `aws_kms_key` (+ `aws_kms_replica_key`) | key reference `aws-kms://<arn>`: rotation, replica regions | reference URI |
| `aws_s3_bucket` | storage `s3://<bucket>` | storage reference |
| `aws_nat_gateway` | egress: its public address (`/32`) | NAT gateway ID (`ciamProviderRef`) |
| `aws_lambda_function`, `aws_codepipeline`, `aws_codebuild_project` (+ `aws_cloudwatch_event_rule` / `aws_cloudwatch_event_target`, `aws_scheduler_schedule`) | job binding (`ciamJobBinding`, the core automation domain): what realizes a job in the environment: its ARN, runtime (a build project's image), and the schedules the EventBridge rules and Scheduler schedules that target it run it on (a Lambda alias or version ARN counts as its function); the job itself (`ou=jobs`) names the binding role (`ciamJobRole`) | ARN (`ciamProviderRef`) |
| `aws_autoscaling_group` (+ its `aws_launch_template`, directly or through a mixed instances policy) | compute group (`ciamComputeGroup`, the core compute domain): the server role it runs (`ciamTargetRole`, its tag `Role`), min/desired/max, the zones of its subnets (else its `availability_zones`), the template's image, instance type and whether the metadata service requires tokens (`http_tokens`: IMDSv2). Its binding role is its tag `BindingRole`, else `compute-<role>` | ARN (`ciamProviderRef`) |
| `aws_eks_cluster` (+ `aws_eks_node_group`, `aws_eks_addon`) | cluster (`ciamCluster`): Kubernetes version, add-ons and versions, node groups (`name: instance types, min-max`), the zones of its subnets. Its binding role is its tag `BindingRole` or `Role`, else `cluster` | ARN (`ciamProviderRef`) |
| `aws_sesv2_email_identity`, `aws_ses_domain_identity` (+ `aws_ses_domain_dkim`, the domain's `aws_route53_record` TXT records) | sending identity (`ciamSendingIdentity`, the core messaging domain) for a domain: DKIM verified (signing status `SUCCESS`), SPF authorizing SES (`include:amazonses.com`), the DMARC policy (`_dmarc` record). An identity for a single address isn't a domain's and is left out | ARN (`ciamProviderRef`) |
| `aws_sqs_queue`, `aws_sns_topic`, `aws_cloudwatch_event_bus` (not the default bus), `aws_kinesis_stream` | stream carrier (`ciamStreamBinding`): what carries an event stream (`ou=event-streams` names its binding role, `ciamStreamRole`); an SNS topic an alarm notifies is an alert channel instead | ARN (`ciamProviderRef`) |
| `aws_sns_topic` named in an alarm's `alarm_actions`, `ok_actions` or `insufficient_data_actions` | alert channel (`ciamAlertChannel`, the core observability domain): `topic`; an alert rule's `ciamAlertRole` names it | ARN (`ciamProviderRef`) |
| `aws_cloudwatch_log_group` | log destination (`ciamLogDestination`): `log-group`, its retention in days (`0`: never expires, which meets any obligation); a log route's `ciamLogDestinationRole` names it | ARN (`ciamProviderRef`) |
| `aws_cloudwatch_metric_alarm` | alarm the cloud runs (`ciamAlarmBinding`): what it evaluates (`ciamMetric`: namespace and metric, or `metric query`), the topics it notifies (`ciamNotifies`), the alert rule it realizes (`ciamRealizes`, its tag `Realizes`). Its binding role is its tag `Role` or `BindingRole`, else `alarm-<Realizes>`; untagged alarms are named, not recorded | ARN (`ciamProviderRef`) |
| `aws_synthetics_canary` | synthetic check the cloud runs (`ciamCanaryBinding`): its `rate(...)` schedule as an interval (`5m`), the canary it realizes (tag `Realizes`); binding role as for alarms, else `canary-<Realizes>` | ARN (`ciamProviderRef`) |

**What changes.** What the state says replaces the record's values for what it covers; everything else on the entry (owner, rotation dates, consumers, …) is kept. An entry of a kind the state reports but that the state lacks is named ("in the record but not in what the cloud reports"); kinds the state doesn't report at all are left alone. An overlay environment leaves the bindings it inherits to its base.

**Roles of new resources.** A resource the record doesn't have is added only when a role is known, because every binding needs one (`ciamBindingRole`, which migrations, required-role checks and renderers match on) and a role can't be guessed. The role comes from, in order:

1. the resource's tag `Role` (or `BindingRole`); a VPC without one is the `network`;
2. the environment's role map, `roles.json` beside the state: a JSON object of provider references (IDs, ARNs) or names to roles. This is the route for what carries no tags: inline security group rules (by rule name) and resources tagged by another team.

```json
{"subnet-0a1b2c3d": "subnet-admin", "fw-admin": "fw-admin"}
```

The importer fills in everything else from the state. Where the source names a role itself, the source's is kept; map entries that disagree with it or match nothing, and a malformed map, are named in the notices. Without a role the resource is named in the notices with what the state says about it. A new entry also needs its class's required attributes (a server its hostname and subnet, a service its DNS name, target role and ports, …); one that lacks them is named.

**Named, not recorded:** resource types that hold secret values or aren't modeled yet (`aws_secretsmanager_secret_version`, `aws_ssm_parameter`, `random_password`, `tls_private_key`, `aws_iam_access_key`, `aws_db_instance`), counted by type.

**Named, not recorded (security group rules):** a port range (`from_port` ≠ `to_port`) and a rule for all ports (`-1`, or `0`–`65535`), since `ciamPort` holds single ports; a source that isn't an IPv4 range (an IPv6 range, a referenced security group, a prefix list, the group itself). The rule's single IPv4 ports and sources are still recorded; a rule with no IPv4 source records nothing. The same from Terraform state, CLI output and CloudFormation.

**Skipped without a notice:** protocols other than `tcp`/`udp` (`ciamProtocol` stays unset) and egress rules.

**Secrets.** Secret values are never read: a Secrets Manager secret is recorded from its ARN alone, `aws_secretsmanager_secret_version` is skipped, and the reader drops whatever the state marks sensitive before anything sees it.

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

opsdir import --dry-run aws/cli-inventory export/
opsdir import --change CHG-… aws/cli-inventory export/
```

File names are free except four: `describe-target-health`, `list-resource-record-sets`, `lambda list-tags` and `events list-targets-by-rule` don't say what they describe, so they are saved as `target-health/<target group name>.json`, `route53/<hosted zone ID>.json`, `lambda-tags/<function name>.json` and `event-targets/<rule name>.json`. Every other output is recognized by its top-level key (`Vpcs`, `Subnets`, `Reservations`, `SecurityGroups`, `SecurityGroupRules`, `NatGateways`, `LoadBalancers`, `TagDescriptions`, `Listeners`, `TargetGroups`, `SecretList`, `KeyMetadata`, `KeyRotationEnabled`, `Buckets`, `Functions`, `Rules`, `ScheduleExpression`, `pipeline`, `projects`); anything else is named and skipped. `roles.json` is the role map, never read as an output.

The outputs are read into the same resources as Terraform state (the mapping is shared), so the table above, what changes, roles and `roles.json` apply unchanged. Separately listed rules (`describe-security-group-rules`) replace the inline permissions of their groups. What the CLI adds: a secret's last rotation (`ciamLastRotated`) and that rotation is off (`ciamAutoRotate: FALSE`), which state doesn't hold. Differences in scope:

- **Network resources** (subnets, instances, security groups, load balancers, NAT gateways) are read only inside the VPCs `describe-vpcs` lists; others are counted. Terminated instances are skipped.
- **Account-wide listings** (secrets, KMS keys, buckets, functions, pipelines, build projects) report far more than one environment: the ones the record doesn't have and nothing names a role for are counted with a few examples, not listed one by one. Name the ones that belong in `roles.json` (by ARN or name). Only customer managed KMS keys are read; AWS managed keys are counted.
- `list-secrets` never returns secret values, and nothing reads `get-secret-value` output. Disabled EventBridge rules and Scheduler schedules are counted, not read. A function's environment variables are never read.

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

What the stacks declare is read into the same resources as Terraform state (the mapping is shared: VPCs, subnets, instances, security groups and ingress rules, load balancers with listeners and target groups, alias records, Secrets Manager secrets with rotation schedules, KMS keys, S3 buckets, NAT gateways, Lambda functions, EventBridge rules and their targets (`Fn::GetAtt X.Arn` resolves to X's ARN), Scheduler schedules, CodePipeline pipelines, CodeBuild projects; ARNs built from the stack's partition, region and account), so the table above, roles and `roles.json` apply unchanged. A KMS key's rotation is off unless the template sets `EnableKeyRotation`, as in CloudFormation. Named in the notices:

- functions that aren't evaluated (`Fn::If`, `Fn::ImportValue`, `Fn::FindInMap`, `Fn::Cidr`, …), counted per stack: the attributes computed with them keep the record's values;
- resources without a physical ID (not created, failed, deleted) and resource types not read, counted;
- values only the running resource knows that the template doesn't declare (an instance's address when the template leaves it to AWS) keep the record's values.

A secret's `SecretString`, `SecretBinary` and `GenerateSecretString` are dropped before anything is resolved; `NoEcho` parameters come back from `describe-stacks` masked.

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
- **Services are TCP network load balancers.** Application load balancers are read as services, but their TLS listeners, certificates and HTTP rules aren't recorded, and the renderer writes only TCP pass-through.
- **What the importers can't see:** egress rules, sources other than IPv4 CIDRs, key pairs, IAM instance profiles and roles (milestone 4.7), Image Builder pipelines (`ciamImageBuild` is recorded by hand), autoscaling groups and EKS clusters, and the monitoring above (log groups, alarms, canaries, alert topics), in CLI output and CloudFormation stacks (Terraform state only, for now), Secrets Manager resource policies, KMS key policies and protection, bucket policies and encryption (4.10), CloudFront / WAF / API Gateway (edge, 4.8), databases (counted, 4.10).

## Tests

`tests/test_aws.py` (registration, vocabulary, secret resolution), `tests/test_aws_state.py` (the state importer: round trip, drift, new tagged and untagged resources, secrets and sensitive attributes never read, overlays, layout, a new binding keeps its provider reference, security group roles from their instances), `tests/test_aws_cli.py` (the CLI importer: round trip, facts state lacks, VPC scoping, counted account-wide listings, files placed by name, rules listed separately, `roles.json` never read as output, timestamps), `tests/test_aws_cloudformation.py` (round trip over two YAML/JSON stacks, drift, `GetAtt` and parameter links, resources not created, unknown files, secrets never read, a folder without a template, the resolver), `tests/test_aws_compute.py` (an autoscaling group with its launch template, an untagged group, an EKS cluster with node groups and add-ons), `tests/test_aws_messaging.py` (an SES domain identity with SPF, DKIM and DMARC from its DNS; queues and buses as stream carriers), `tests/test_aws_observability.py` (a topic an alarm notifies as an alert channel, others as stream carriers; log groups with their retention, never-expire included; alarms and canaries with what they realize), `tests/test_aws_firewall_notices.py` (port ranges, all-ports rules and non-IPv4 sources named from state, CLI output and CloudFormation), `tests/test_aws_jobs.py` (functions, pipelines and build projects with their schedules from state, CLI output and CloudFormation; a tagged function placed as a job binding), `tests/test_aws_state_store.py` (state and CLI against Postgres: imported under an approved change, re-import changes nothing). The rendered Terraform is covered end to end by the showcase's golden outputs (`examples/showcase`, the source environment), and the importers by its cloud drift exports (`examples/showcase/exports/cloud/source`).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `aws`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

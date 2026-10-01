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

**What changes.** What the state says replaces the record's values for what it covers; everything else on the entry (owner, rotation dates, consumers, …) is kept. An entry of a kind the state reports but that the state lacks is named ("in the record but not in what the cloud reports"); kinds the state doesn't report at all are left alone. An overlay environment leaves the bindings it inherits to its base.

**Roles of new resources.** A resource the record doesn't have is added only when a role is known, because every binding needs one (`ciamBindingRole`, which migrations, required-role checks and renderers match on) and a role can't be guessed. The role comes from, in order:

1. the resource's tag `Role` (or `BindingRole`); a VPC without one is the `network`;
2. the environment's role map, `roles.json` beside the state: a JSON object of provider references (IDs, ARNs) or names to roles. This is the route for what carries no tags: inline security group rules (by rule name) and resources tagged by another team.

```json
{"subnet-0a1b2c3d": "subnet-admin", "fw-admin": "fw-admin"}
```

The importer fills in everything else from the state. Where the source names a role itself, the source's is kept; map entries that disagree with it or match nothing, and a malformed map, are named in the notices. Without a role the resource is named in the notices with what the state says about it. A new entry also needs its class's required attributes (a server its hostname and subnet, a service its DNS name, target role and ports, …); one that lacks them is named.

**Named, not recorded:** resource types that hold secret values or aren't modeled yet (`aws_secretsmanager_secret_version`, `aws_ssm_parameter`, `random_password`, `tls_private_key`, `aws_iam_access_key`, `aws_db_instance`), counted by type.

**Skipped without a notice:** ingress rules whose source isn't an IPv4 CIDR (IPv6, a referenced security group, a prefix list), port `0`/`-1` (all ports), protocols other than `tcp`/`udp` (`ciamProtocol` stays unset), and egress rules.

**Secrets.** Secret values are never read: a Secrets Manager secret is recorded from its ARN alone, `aws_secretsmanager_secret_version` is skipped, and the reader drops whatever the state marks sensitive before anything sees it.

## Reading an environment from the AWS CLI

Where there is no Terraform state (or to check it against what the account actually runs), `aws/cli-inventory` reads the JSON the AWS CLI prints. Collect it once per environment, into one folder per `<cloud>/<env>`:

```bash
out=export/source/prod; VPC=vpc-0a1b2c3d4e5f67890              # the environment's VPC scopes what is read
mkdir -p $out/target-health $out/route53 $out/kms
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

opsdir import --dry-run aws/cli-inventory export/
opsdir import --change CHG-… aws/cli-inventory export/
```

File names are free except two: `describe-target-health` and `list-resource-record-sets` don't say what they describe, so they are saved as `target-health/<target group name>.json` and `route53/<hosted zone ID>.json`. Every other output is recognized by its top-level key (`Vpcs`, `Subnets`, `Reservations`, `SecurityGroups`, `SecurityGroupRules`, `NatGateways`, `LoadBalancers`, `TagDescriptions`, `Listeners`, `TargetGroups`, `SecretList`, `KeyMetadata`, `KeyRotationEnabled`, `Buckets`); anything else is named and skipped. `roles.json` is the role map, never read as an output.

The outputs are read into the same resources as Terraform state (the mapping is shared), so the table above, what changes, roles and `roles.json` apply unchanged. Separately listed rules (`describe-security-group-rules`) replace the inline permissions of their groups. What the CLI adds: a secret's last rotation (`ciamLastRotated`) and that rotation is off (`ciamAutoRotate: FALSE`), which state doesn't hold. Differences in scope:

- **Network resources** (subnets, instances, security groups, load balancers, NAT gateways) are read only inside the VPCs `describe-vpcs` lists; others are counted. Terminated instances are skipped.
- **Account-wide listings** (secrets, KMS keys, buckets) report far more than one environment: the ones the record doesn't have and nothing names a role for are counted with a few examples, not listed one by one. Name the ones that belong in `roles.json` (by ARN or name). Only customer managed KMS keys are read; AWS managed keys are counted.
- `list-secrets` never returns secret values, and nothing reads `get-secret-value` output.

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

What the stacks declare is read into the same resources as Terraform state (the mapping is shared: VPCs, subnets, instances, security groups and ingress rules, load balancers with listeners and target groups, alias records, Secrets Manager secrets with rotation schedules, KMS keys, S3 buckets, NAT gateways), so the table above, roles and `roles.json` apply unchanged. A KMS key's rotation is off unless the template sets `EnableKeyRotation`, as in CloudFormation. Named in the notices:

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
- **Port ranges:** the importers read a rule's first port only (`from_port`; `to_port` is ignored), so a range comes in as its first port, without a notice. The renderer writes single ports only (`ciamPort` holds single ports).
- **Services are TCP network load balancers.** Application load balancers are read as services, but their TLS listeners, certificates and HTTP rules aren't recorded, and the renderer writes only TCP pass-through.
- **What the importers can't see:** egress rules, sources other than IPv4 CIDRs, key pairs, IAM instance profiles and roles (milestone 4.7), Secrets Manager resource policies, KMS key policies and protection, bucket policies and encryption (4.10), CloudFront / WAF / API Gateway (edge, 4.8), databases (counted, 4.10).

## Tests

`tests/test_aws.py` (registration, vocabulary, secret resolution), `tests/test_aws_state.py` (the state importer: round trip, drift, new tagged and untagged resources, secrets and sensitive attributes never read, overlays, layout, a new binding keeps its provider reference, security group roles from their instances), `tests/test_aws_cli.py` (the CLI importer: round trip, facts state lacks, VPC scoping, counted account-wide listings, files placed by name, rules listed separately, `roles.json` never read as output, timestamps), `tests/test_aws_cloudformation.py` (round trip over two YAML/JSON stacks, drift, `GetAtt` and parameter links, resources not created, unknown files, secrets never read, a folder without a template, the resolver), `tests/test_aws_state_store.py` (state and CLI against Postgres: imported under an approved change, re-import changes nothing). The rendered Terraform is covered end to end by the showcase's golden outputs (`examples/showcase`, the source environment), and the importers by its cloud drift exports (`examples/showcase/exports/cloud/source`).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `aws`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

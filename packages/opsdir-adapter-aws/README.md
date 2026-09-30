# opsdir-adapter-aws

opsdir adapter for Amazon Web Services: Terraform for AWS environments and aws-sm:// secret references.

Applies to environments whose cloud has `ciamCloudProvider: aws`. Renders the environment-specific Terraform (VPC, subnets, instances, load balancers, security groups, DNS) and resolves `aws-sm://` secret references with the AWS CLI at run time. Owns the reference schemes `aws-sm` (Secrets Manager), `aws-kms` (KMS keys), `aws-acm` (certificates in Certificate Manager), `s3`.

## Reading an environment back from Terraform state

```bash
terraform -chdir=… state pull > export/source/prod/terraform.tfstate     # one folder per <cloud>/<env>
opsdir import --dry-run aws/terraform-state export/                        # what the live environment differs in
opsdir import --change CHG-… aws/terraform-state export/                   # record it
```

The importer `aws/terraform-state` reads Terraform state (format version 4; managed resources and data sources) into the environment's servers and bindings: the VPC (`network`), subnets, instances (name, role, hostname and product from their tags `Name`, `Role`, `Hostname`, `Product`; the subnet they are in), each network load balancer with its listeners, targets and the Route 53 record aliasing it (a service name: DNS name, zone, ports, the role it targets, its private address or Elastic IP), security group ingress rules (grouped into the record's firewall rules by the name their descriptions end with, `(fw-name)`, or their tag `Name`), Secrets Manager secrets (as `aws-sm://` references, with rotation), KMS keys (rotation, replica regions), the S3 bucket (`s3://`) and NAT gateways (egress addresses).

What the state says replaces the record's values for what it covers; everything else on the entry is kept. A resource the record doesn't have is added when its tags name its role (`Role`), and named in the notices otherwise; so is an entry the record has that the state doesn't. An overlay environment leaves its base's bindings alone. Secret values in the state (`aws_secretsmanager_secret_version`, generated passwords, anything the state marks sensitive) are never read.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `aws`); nothing in the opsdir core changes. In this repository: `scripts/dev-install.sh`.

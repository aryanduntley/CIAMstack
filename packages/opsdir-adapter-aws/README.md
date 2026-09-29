# opsdir-adapter-aws

opsdir adapter for Amazon Web Services: Terraform for AWS environments and aws-sm:// secret references.

Applies to environments whose cloud has `ciamCloudProvider: aws`. Renders the environment-specific Terraform (VPC, subnets, instances, load balancers, security groups, DNS) and resolves `aws-sm://` secret references with the AWS CLI at run time. Owns the reference schemes `aws-sm` (Secrets Manager), `aws-kms` (KMS keys), `aws-acm` (certificates in Certificate Manager), `s3`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `aws`); nothing in the opsdir core changes. In this repository: `scripts/dev-install.sh`.

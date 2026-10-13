"""The AWS account an environment runs in and how every resource rendered for it is tagged: the provider versions every
root pins (the current releases, validated against), the provider block each root declares, with the account it must
run against (the record's ciamAccountRef: Terraform refuses another), the estate's tag policy as the provider's default
tags, and AWS's FIPS endpoints when the cloud says its clients use them. Pure."""
from opsdir.core.directory import one
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.estate.tags import required_tags
from opsdir_format_terraform.hcl import Block, tf_block, tf_name

AWS_VERSION = "~> 6.68"             # validated against hashicorp/aws 6.68.0
ARCHIVE_VERSION = "~> 2.8"          # validated against hashicorp/archive 2.8.1


def govcloud(m):
    """Whether environment m's cloud runs in an AWS GovCloud (US) region."""
    return (one(m.cloud, "ciamRegion") or "").startswith("us-gov-")


def partition(m):
    """The ARN partition environment m's cloud is in: aws-us-gov in GovCloud (US), else aws."""
    return "aws-us-gov" if govcloud(m) else "aws"


def required_providers(archive=False):
    """The terraform block of an AWS root: aws, and archive when the root packages scripts."""
    return tf_block("terraform", [], [("required_providers", Block((
        ("aws", {"source": "hashicorp/aws", "version": AWS_VERSION}),
        *((("archive", {"source": "hashicorp/archive", "version": ARCHIVE_VERSION}),) if archive else ()))))])


def standard_account(m):
    """The standard (commercial) account a GovCloud cloud is linked to (ciamBillingAccountRef): where its billing and
    the services GovCloud doesn't offer (AWS Budgets, CloudFront) run; None when not recorded."""
    return one(m.cloud, "ciamBillingAccountRef")


def account_id(m):
    """The AWS account environment m's cloud records (ciamAccountRef), or None."""
    return one(m.cloud, "ciamAccountRef")


MANAGEMENT, SECURITY_ADMIN = "management", "security_admin"


def management_account(m):
    """The organization's management account environment m's cloud records (ciamManagementRef), or None."""
    return one(m.cloud, "ciamManagementRef")


def security_admin_account(m):
    """The delegated administrator account of the organization's security services (ciamSecurityAdminRef), or None."""
    return one(m.cloud, "ciamSecurityAdminRef")


def organization_providers(m, regions=()):
    """The aws providers organization-wide settings are made through, for the accounts the record names, in the
    cloud's region and in each of regions (<alias>_<region>: a service in every region): the management account's (an
    organization trail, the delegated administrators it registers) and the security services' delegated
    administrator's (their organization configuration). A root keeps those it uses."""
    accounts = ((MANAGEMENT, management_account(m), "The organization's management account: organization-wide "
                 "settings (an organization trail, delegated administrators)"),
                (SECURITY_ADMIN, security_admin_account(m), "The delegated administrator of the organization's "
                 "security services: their organization-wide configuration"))
    return tuple(provider_block(m, region, alias if region is None else f"{alias}_{tf_name(region)}",
                                what if region is None else f"{what}, in {region}", account=account)
                 for alias, account, what in accounts if account for region in (None, *regions))


def provider_block(m, region=None, alias=None, comment=None, own_account=True, account=None):
    """The aws provider block of environment m: its region (the cloud's unless given), alias, the account Terraform may
    run against (account when given, else the cloud's own for the platform's own roots: own_account; a landing zone's
    keeper may apply from another account), the FIPS endpoints when the cloud uses them, and the tag policy's tags on
    every resource."""
    tags, account = required_tags(m), account or (account_id(m) if own_account else None)
    return tf_block("provider", ["aws"], [
        *((("#", comment),) if comment else ()), *((("alias", alias),) if alias else ()),
        ("region", region or one(m.cloud, "ciamRegion")),
        *((("allowed_account_ids", [account]),) if account else ()),
        *((("use_fips_endpoint", True),) if fips_endpoints(m) else ()),
        *((("default_tags", Block((("tags", tags),))),) if tags else ())])

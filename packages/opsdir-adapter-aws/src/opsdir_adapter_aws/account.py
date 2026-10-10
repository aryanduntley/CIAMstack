"""The AWS account an environment runs in and how every resource rendered for it is tagged: the provider block each
root declares, with the account it must run against (the record's ciamAccountRef: Terraform refuses another), the
estate's tag policy as the provider's default tags, and AWS's FIPS endpoints when the cloud says its clients use them.
Pure."""
from opsdir.core.directory import one
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.estate.tags import required_tags
from opsdir_format_terraform.hcl import Block, block


def govcloud(m):
    """Whether environment m's cloud runs in an AWS GovCloud (US) region."""
    return (one(m.cloud, "ciamRegion") or "").startswith("us-gov-")


def partition(m):
    """The ARN partition environment m's cloud is in: aws-us-gov in GovCloud (US), else aws."""
    return "aws-us-gov" if govcloud(m) else "aws"


def account_id(m):
    """The AWS account environment m's cloud records (ciamAccountRef), or None."""
    return one(m.cloud, "ciamAccountRef")


def provider_block(m, region=None, alias=None, comment=None, own_account=True, account=None):
    """The aws provider block of environment m: its region (the cloud's unless given), alias, the account Terraform may
    run against (account when given, else the cloud's own for the platform's own roots: own_account; a landing zone's
    keeper may apply from another account), the FIPS endpoints when the cloud uses them, and the tag policy's tags on
    every resource."""
    tags, account = required_tags(m), account or (account_id(m) if own_account else None)
    return block("provider", ["aws"], [
        *((("#", comment),) if comment else ()), *((("alias", alias),) if alias else ()),
        ("region", region or one(m.cloud, "ciamRegion")),
        *((("allowed_account_ids", [account]),) if account else ()),
        *((("use_fips_endpoint", True),) if fips_endpoints(m) else ()),
        *((("default_tags", Block((("tags", tags),))),) if tags else ())])

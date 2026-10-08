"""Estate domain: cloud governance of the estate. Which cloud account each environment runs in and the organization
above it, its resource group, how sensitive its data is and who pays for it; the tag policy every rendered resource
follows (renderers tag with required_tags, importers say what the cloud has untagged); the region catalog (each
provider's regions, fetched from the provider), the residencies the estate defines and the one each environment's data
is held to; FIPS endpoints; the cloud security services each environment runs; the provider limits each environment
needs (quotas, checked against the limits fetched from the provider) and the budgets its spending is held to.
Vendor-neutral: the cloud adapters render and read what it records."""
from ...core.contract import Domain, ImportKind, directory_report
from .budgets import BUDGET_HEADERS, budget_role, budget_rows, check_budgets
from .checks import check_fips, check_regions, check_residency, check_tags
from .reports import (REGION_HEADERS, RESIDENCY_HEADERS, TAG_HEADERS, region_rows, residency_rows,
                      tag_rows)
from .quotas import QUOTA_HEADERS, check_quotas, quota_rows
from .schema import FRAGMENT
from .security import SECURITY_HEADERS, check_security, security_role, security_rows
from .tags import tag_notices

DOMAIN = Domain(name="estate", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"tags": directory_report(TAG_HEADERS, tag_rows),
                         "regions": directory_report(REGION_HEADERS, region_rows),
                         "residency": directory_report(RESIDENCY_HEADERS, residency_rows),
                         "security-services": directory_report(SECURITY_HEADERS, security_rows),
                         "quotas": directory_report(QUOTA_HEADERS, quota_rows),
                         "budgets": directory_report(BUDGET_HEADERS, budget_rows)},
                checks=(check_tags, check_regions, check_residency, check_fips, check_security, check_quotas,
                        check_budgets), order=72,
                vocabulary={}, import_checks=(tag_notices,),
                import_kinds=(ImportKind("security", "ciamSecurityService", ("ciamSecurityKind",),
                                         role=security_role),
                              ImportKind("budget", "ciamBudget", ("ciamBudgetAmount",), role=budget_role)),
                role_links={"ciamFindingsRole": ("channel", "logs", "storage", "stream"), "ciamAlertRole": "channel"})

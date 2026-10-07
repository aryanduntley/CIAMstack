"""Estate domain: cloud governance of the estate. Which cloud account each environment runs in and the organization
above it, its resource group, how sensitive its data is and who pays for it; the tag policy every rendered resource
follows (renderers tag with required_tags, importers say what the cloud has untagged); the region catalog (each
provider's regions, fetched from the provider), the residencies the estate defines and the one each environment's data
is held to; FIPS endpoints. Later: security services, quotas and budgets. Vendor-neutral: the cloud adapters render
and read what it records."""
from ...core.contract import Domain, directory_report
from .checks import check_fips, check_regions, check_residency, check_tags
from .reports import (REGION_HEADERS, RESIDENCY_HEADERS, TAG_HEADERS, region_rows, residency_rows,
                      tag_rows)
from .schema import FRAGMENT
from .tags import tag_notices

DOMAIN = Domain(name="estate", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"tags": directory_report(TAG_HEADERS, tag_rows),
                         "regions": directory_report(REGION_HEADERS, region_rows),
                         "residency": directory_report(RESIDENCY_HEADERS, residency_rows)},
                checks=(check_tags, check_regions, check_residency, check_fips), order=72, vocabulary={},
                import_checks=(tag_notices,))

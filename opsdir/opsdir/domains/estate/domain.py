"""Estate domain: cloud governance of the estate. Which cloud account each environment runs in and the organization
above it, its resource group, how sensitive its data is and who pays for it; the tag policy every rendered resource
follows (renderers tag with required_tags, importers say what the cloud has untagged). Later: residency, security
services, quotas and budgets. Vendor-neutral: the cloud adapters render and read what it records."""
from ...core.contract import Domain, directory_report
from .checks import check_tags
from .reports import TAG_HEADERS, tag_rows
from .schema import FRAGMENT
from .tags import tag_notices

DOMAIN = Domain(name="estate", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"tags": directory_report(TAG_HEADERS, tag_rows)},
                checks=(check_tags,), order=72, vocabulary={}, import_checks=(tag_notices,))

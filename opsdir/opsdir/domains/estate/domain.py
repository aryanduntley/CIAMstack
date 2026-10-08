"""Estate domain: cloud governance of the estate. Which cloud account each environment runs in and the organization
above it, its resource group, how sensitive its data is and who pays for it; the tag policy every rendered resource
follows (renderers tag with required_tags, importers say what the cloud has untagged); the region catalog (each
provider's regions, fetched from the provider), the residencies the estate defines and the one each environment's data
is held to; FIPS endpoints; the cloud security services each environment runs and the data discovery services that find where its
sensitive data lies; the provider limits each environment
needs (quotas, checked against the limits fetched from the provider) and the budgets its spending is held to; the
incident reporting obligations each environment is held to, the findings its security services send to the incident
process and the incidents that fall under an obligation; the plan of action and milestones, the exceptions a risk
authority approved (and the planner findings they accept), the compliance assessments, and the clouds' suppressions of
findings that carry exceptions out; the cloud authorizations the environments rely on, the operator's system
boundaries and who meets each control under an authorization. Vendor-neutral: the cloud adapters render and read what it records."""
from ...core.contract import Domain, ImportKind, directory_report
from .budgets import BUDGET_HEADERS, budget_role, budget_rows, check_budgets
from .checks import check_fips, check_regions, check_residency, check_tags
from .discovery import DISCOVERY_HEADERS, check_discovery, discovery_role, discovery_rows
from .authorizations import (AUTHORIZATION_HEADERS, RESPONSIBILITY_HEADERS, authorization_rows, check_authorization,
                             responsibility_rows)
from .poam import (ASSESSMENT_HEADERS, EXCEPTION_HEADERS, POAM_HEADERS, accept_exceptions, assessment_rows,
                   check_poam, exception_rows, poam_rows, suppression_prepare, suppression_role)
from .incidents import (INCIDENT_HEADERS, REPORTING_HEADERS, check_incident_reporting, incident_reporting_rows,
                        reportable_incident_rows)
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
                         "data-discovery": directory_report(DISCOVERY_HEADERS, discovery_rows),
                         "quotas": directory_report(QUOTA_HEADERS, quota_rows),
                         "budgets": directory_report(BUDGET_HEADERS, budget_rows),
                         "incident-reporting": directory_report(REPORTING_HEADERS, incident_reporting_rows),
                         "reportable-incidents": directory_report(INCIDENT_HEADERS, reportable_incident_rows,
                                                                  dated=True),
                         "poam": directory_report(POAM_HEADERS, poam_rows, dated=True),
                         "exceptions": directory_report(EXCEPTION_HEADERS, exception_rows, dated=True),
                         "assessments": directory_report(ASSESSMENT_HEADERS, assessment_rows),
                         "authorizations": directory_report(AUTHORIZATION_HEADERS, authorization_rows, dated=True),
                         "responsibilities": directory_report(RESPONSIBILITY_HEADERS, responsibility_rows)},
                checks=(check_tags, check_regions, check_residency, check_fips, check_security, check_discovery,
                        check_quotas,
                        check_budgets, check_incident_reporting, check_poam,
                        check_authorization), order=72,
                vocabulary={}, import_checks=(tag_notices,),
                import_kinds=(ImportKind("security", "ciamSecurityService", ("ciamSecurityKind",),
                                         role=security_role),
                              ImportKind("discovery", "ciamDataDiscovery", (), role=discovery_role),
                              ImportKind("budget", "ciamBudget", ("ciamBudgetAmount",), role=budget_role),
                              ImportKind("suppression", "ciamSuppression", (), role=suppression_role,
                                         prepare=suppression_prepare)),
                local_classes=("ciamSuppression",), accept=accept_exceptions,
                role_links={"ciamFindingsRole": ("channel", "logs", "storage", "stream"), "ciamAlertRole": "channel",
                            "ciamScansRole": ("storage", "database", "volume"), "ciamResultsRole": "storage",
                            "ciamIncidentRole": ("channel", "logs", "stream")})

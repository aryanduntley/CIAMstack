"""Estate domain vocabulary: how sensitive an environment's data is, where a tag's value comes from, a cloud region's
status, where the tag policy, the region catalog and the residencies live, what a cloud security service is and
watches, what a quota counts and what may be decided about it, where the provider limits fetched live, a budget's
period, amount and currency, where the reporting obligations live, how severe a finding is and what an authority asked
of an incident's preserved media, and the vocabulary of POA&M items, exceptions and compliance assessments (with the
CMMC rules a POA&M must keep to)."""

from ...core.naming import branch

CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")   # least sensitive first
# where a tag rule takes its value in each environment: the environment's owner, that owner's cost center, the
# environment's data classification, the environment (cloud/env), its cloud, or the rule's own value
TAG_SOURCES = ("owner", "cost-center", "classification", "environment", "cloud", "literal")
TAG_POLICY = branch("tag-policy")       # the tag rules (ciamTagRule), one per tag every rendered resource carries
# a region as its provider lists it: available, open only to accounts that opt in, or no longer listed (kept: what names
# it keeps its link, and the planner says so)
REGION_STATUSES = ("available", "opt-in", "not-listed")
REGIONS = branch("regions")             # the region catalog: one ciamRegionCatalog per provider, its ciamCloudRegions
RESIDENCIES = branch("residencies")     # the estate's residencies (ciamResidency): the regions each allows
# what a cloud security service does: detect threats; scan for vulnerabilities; record resources' configuration and its
# changes; assess the estate's posture against compliance frameworks and the cloud's own baseline
SECURITY_KINDS = ("threat-detection", "vulnerability-scanning", "config-recording", "posture")
# what a threat-detection (or vulnerability-scanning) service watches: management API activity, sign-ins and
# credentials, traffic and name lookups, machines, containers and clusters, object storage, databases, key vaults,
# applications and APIs
SECURITY_AREAS = ("control-plane", "identity", "network", "compute", "containers", "storage", "databases",
                  "key-vaults", "applications")
STANDARD_ID = r"[a-z0-9]+(-[a-z0-9]+)*"     # a compliance framework's or baseline's id: nist-800-171-r2, cis
# a data type of the organization's own a data discovery service looks for: `name: regular expression`
CUSTOM_IDENTIFIER = r"[a-z][a-z0-9-]{0,62}: \S.*"
# the regulatory frameworks a posture service assesses that a move can't silently drop (a target without posture
# assessment while the source assesses one of these is a blocker)
REGULATORY = frozenset(("nist-800-53-r5", "nist-800-171-r2", "fedramp-low", "fedramp-moderate", "fedramp-high",
                        "cmmc-l1", "cmmc-l2", "cmmc-l3", "dod-il2", "dod-il4", "dod-il5"))
RESTRICTED = "restricted"                   # the data classification under which a narrower target blocks the move
# what a quota counts, by kinds every cloud has a limit for (each adapter maps them to its provider's own quotas):
# virtual CPUs of the region's standard machines, public IP addresses, networks, load balancers, managed database
# instances, Kubernetes clusters
QUOTA_KINDS = ("vcpus", "public-ips", "networks", "load-balancers", "database-instances", "kubernetes-clusters")
# the operator's decision on a quota the provider grants less of than the environments need: request an increase (to
# ciamQuotaRequested, else the need), or deny it (the move stops)
QUOTA_DECISIONS = ("request", "deny")
QUOTAS = branch("quotas")               # the provider limits fetched: one ciamQuotaCatalog per account and region
BUDGET_PERIODS = ("monthly", "quarterly", "annually")
AMOUNT = r"[0-9]{1,12}(\.[0-9]{1,2})?"   # a budget's amount in its currency: 1500, 1500.50
CURRENCY = r"[A-Z]{3}"                  # ISO 4217: USD, EUR
DEFAULT_CURRENCY = "USD"
# the reporting obligations the estate is held to (ciamReportingObligation: a regime's clock, authority, reporter, ...)
REPORTING_OBLIGATIONS = branch("reporting-obligations")
# how severe a security finding is, least first: the clouds' own scales map onto these (a cloud without critical
# routes its highest as high)
SEVERITIES = ("low", "medium", "high", "critical")
# what an authority asked of an incident's preserved images and monitoring data: nothing yet, the media, which the
# operator provided, or it declined interest
MEDIA_REQUESTS = ("none", "requested", "provided", "declined")
CAGE_CODE = r"[A-Z0-9]{5}"      # a Commercial and Government Entity code: 1ABC2
UEI = r"[A-Z0-9]{12}"           # a Unique Entity ID (SAM.gov): ABCDEF123456
POAM = branch("poam")                   # the plan of action and milestones: one ciamPoamItem per known weakness
EXCEPTIONS = branch("exceptions")       # approved deviations (ciamRiskException): accepted risks, false positives, ...
ASSESSMENTS = branch("assessments")     # compliance assessments (ciamComplianceAssessment): their scores and status
# a control a POA&M item or exception concerns, as framework:control (the framework by the neutral ids posture uses):
# nist-800-171-r2:3.13.11, nist-800-53-r5:SC-13, cmmc-l2:SC.L2-3.13.11
CONTROL_REF = r"[a-z0-9]+(-[a-z0-9]+)*:[A-Za-z0-9][A-Za-z0-9.()-]*"
# a cloud finding or control an exception (or a cloud's suppression) concerns, as provider:kind:id, the kind and id the
# provider's adapter defines (aws:securityhub:IAM.6, aws:guardduty:Recon:EC2/PortProbeUnprotectedPort)
FINDING_REF = r"[a-z0-9-]+:[a-z0-9-]+:.+"
DISCOVERY_SOURCES = ("assessment", "scan", "audit", "continuous-monitoring", "incident")
POAM_STATUSES = ("open", "closed")
RISK_RATINGS = ("low", "moderate", "high")
# what an exception is: FedRAMP's deviation requests (risk adjustment, false positive, operational requirement), a risk
# the authority accepts as is, or a control met another way
EXCEPTION_KINDS = ("risk-adjustment", "false-positive", "operational-requirement", "risk-acceptance",
                   "compensating-control")
EXCEPTION_STATUSES = ("requested", "approved", "rejected", "withdrawn")
# who assessed: the operator itself (a DFARS Basic assessment is a self-assessment), a C3PAO, DCMA DIBCAC, or DoD at the
# Medium or High confidence level (DFARS 252.204-7020)
ASSESSMENT_KINDS = ("self", "c3pao", "dibcac", "dod-medium", "dod-high")
ASSESSMENT_STATUSES = ("conditional", "final")
# findings no exception can accept: the blockers of these areas (a broken contract, a key kept wrongly, a reporting
# obligation lost or unmet, a security service lost, an exception or POA&M itself) and blockers naming withheld
# credentials (no secret to run with)
UNACCEPTABLE_AREAS = frozenset(("Contract", "Key", "Planner", "Incident reporting", "Security", "Exceptions", "POA&M"))
UNACCEPTABLE_PHRASES = ("withheld credentials",)
# CMMC Level 2 (32 CFR 170.21(a)(2), (b)): a Conditional status needs a score of at least 0.8 of the maximum, no POA&M
# requirement worth more than 1 point except SC.L2-3.13.11 when encryption is used but not FIPS-validated (3 points),
# none of these requirements on the POA&M, and the POA&M closed out within 180 days of the Conditional status date
CMMC_FRAMEWORK = "cmmc-l2"
CMMC_MIN_RATIO = 0.8
CMMC_NEVER_POAM = ("3.1.20", "3.1.22", "3.12.4", "3.10.3", "3.10.4", "3.10.5")
CMMC_FIPS_EXCEPTION = ("3.13.11", 3)
CMMC_CLOSEOUT_DAYS = 180
SUPPRESSION_PREFIX = "exc-"   # a cloud suppression is named after the exception it carries out: exc-<exception cn>
AUTHORIZATIONS = branch("authorizations")   # the cloud offerings' authorizations (ciamCloudAuthorization)
BOUNDARIES = branch("boundaries")           # the operator's system boundaries (ciamSystemBoundary): its SSPs
RESPONSIBILITIES = branch("responsibilities")   # who meets each control under an authorization (its CRM)
# an authorization's level, by program: FedRAMP's baselines (Class B, C, D) and the DoD SRG impact levels; a requirement
# is met by the same program at the same or a higher level
AUTHORIZATION_LEVELS = (("fedramp", ("fedramp-low", "fedramp-moderate", "fedramp-high")),
                        ("dod-pa", ("dod-il2", "dod-il4", "dod-il5")))
LEVELS = tuple(lv for _, levels in AUTHORIZATION_LEVELS for lv in levels)
# where an authorization stands: FedRAMP Certified (Rev5) or Validated (20x), equivalent to FedRAMP Moderate per DoD's
# equivalency policy (with evidence), in process, revoked
AUTHORIZATION_STATUSES = ("certified", "validated", "equivalent", "in-process", "revoked")
STANDING = frozenset(("certified", "validated", "equivalent"))
RESPONSIBILITY = ("inherited", "shared", "customer")
# what a customer must configure for its use to be inside an authorization's boundary
CONFIGURATIONS = ("assured-workload", "us-data-location", "us-person-support", "il5-isolation")
SCOPE_STALE_DAYS = 90         # an in-scope service list older than this asks for a fresh one

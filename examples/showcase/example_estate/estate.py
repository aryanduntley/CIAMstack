"""Cloud governance fixture data (data file 15-tag-policy; the rest is used by governance and infrastructure): the
estate's tag policy, the cost center each party is charged to, how sensitive each environment's data is, and the cloud
account each cloud's environments run in (as the exports show them).

  tag policy   Owner (the environment's owner), CostCenter (that owner's cost center), DataClassification (the
               environment's), Environment (cloud/env): every resource rendered carries them (AWS default tags,
               Azure tags, Google Cloud default labels); every import names the resources the cloud reports without
               them (the source's predate the policy)
  accounts     source: AWS account 111122223333; target: the Azure subscription its exports show; standby: project
               example-aero-ciam-standby
  planted      the target environment records no data classification: its DataClassification tag has no value
  regions      what each provider's region command printed (exports/regions/<provider>/regions.json, the real CLI
               output shapes; a synthetic subset of each provider's regions): `aws ec2 describe-regions
               --all-regions`, `az account list-locations`, `gcloud compute regions list`. The record holds no
               region catalog when loaded (the planner says it can't check the regions: A80, A81); approved changes
               CHG-2020..2022 import the lists, then CHG-2023 (changes/) holds every environment to the estate's `us`
               residency (US regions of the three clouds)
  security     each environment's cloud security services (SECURITY, bindings used by infrastructure): the source
               runs GuardDuty, Inspector, AWS Config (history exported to a bucket) and Security Hub (NIST SP 800-53
               Rev. 5, NIST SP 800-171 Rev. 2, AWS Foundational Security Best Practices), findings to an SNS topic;
               the target Defender for Cloud (threat detection, vulnerability scanning, CSPM on NIST SP 800-53 Rev. 5),
               findings to a Log Analytics workspace; the standby Security Command Center's findings and an asset feed
               to a Pub/Sub topic. Planted: the target runs no Defender for Containers, so neither its threat
               detection nor its vulnerability scanning covers containers, and it isn't assessed against NIST SP
               800-171 Rev. 2 (actions); it records no configuration history while the source exports its (a
               blocker): approved change CHG-2024 records Azure's own (Resource Graph, 14 days), which leaves
               actions: the target keeps 14 days of it in the service, the source exports 2557
  discovery    each environment's data discovery (SECURITY too): the source's Macie and the standby's Sensitive Data
               Protection examine the directory backups weekly for sensitive data and the organization's own types
               (OWN_DATA_TYPES: CUI markings, employee numbers), findings to the security topic; Macie is in the
               source's Terraform state. Planted: the target runs none (an action, a blocker once CHG-2029 holds it
               to DFARS) until CHG-2034 records Defender's sensitive data discovery over its backups
  quotas       what each environment needs of its provider's limits (COSTS: vCPUs, public addresses, database
               instances; stage shares production's account and needs nothing of its own) and the limits each
               provider's quota commands printed (exports/quotas/<provider>/, the real CLI output shapes, synthetic
               values), imported by approved changes CHG-2025 (aws/quotas), CHG-2026 (azure/quotas) and CHG-2027
               (gcp/quotas). Planted: until CHG-2026 the target's limits aren't fetched (an action); then its region
               grants 50 vCPUs where it needs 96 (an action whose fix asks the operator to request 96, a value of
               their own, or deny) and Azure reports no limit on database instances (an action: confirm it with
               Microsoft); CHG-2028 approves the increase, which leaves an action until the quotas are fetched again
  incidents    the estate's incident reporting obligation (16-reporting-obligations): DFARS 252.204-7012 (report a
               cyber incident within 72 hours of discovery on DIBNet, to the DoD Cyber Crime Center; one hour to the
               security operations center, which files with the medium assurance certificate dibnet-eca; malware to
               DC3; images and monitoring data preserved 90 days after a report; a synthetic contract number).
               Production and the standby are held to it; GuardDuty (source) and Security Command Center (standby)
               send high and worse findings to the incident process too (an SNS topic, a Pub/Sub topic). Planted:
               the target is held to none (a blocker) and Defender pages no one (an action, and the incident role it
               doesn't bind), until CHG-2029 holds it and routes Defender's high alerts to its incident action group
  compliance   the estate's CMMC Level 2 assessment of production and the target (17-compliance: a C3PAO's, 104 of
               110, Conditional since 2026-08-15, so its POA&M closes out by 2027-02-11), its POA&M item (PingDS's
               LDAPS doesn't run on a FIPS-validated provider: SC.L2-3.13.11, 3 points, allowed on a POA&M), and two
               exceptions under the authorizing official: production's Security Hub IAM.6 finding is a false positive
               (a suppression, Security Hub's automation rule, carries it out: in the source's Terraform state), which
               doesn't carry to the target (an action); the target accepts running without container scanning until
               2027-03-31, planted approved without an expiry (a blocker) until CHG-2030 records it (the plan then shows
               the scanning action as accepted) and suppresses a Defender false positive through the azapi add-on
  authorizations  the cloud offerings' FedRAMP authorizations each environment relies on (18-authorizations): AWS US
               East/West (AGENCYAMAZONEW, Class C Moderate) for production, its in-scope services imported from its
               Certification Package Overview by approved change CHG-2031 (exports/fedramp/: AWS's real package id and
               service names, trimmed to what production uses); Azure (F1209051525, Class D High) for the target and
               Google Cloud (FR1805751477, Class D High, Assured Workloads required: the standby records its workload,
               rendered in its landing zone) recorded by hand, their in-scope names a subset of Microsoft's and Google's
               pages. DFARS 252.204-7012 requires FedRAMP Moderate. The system security plan SSP-CIAM-2026 covers
               production and the standby; SC-12 (key management) is inherited from AWS and the customer's on Azure.
               Planted: the target is outside the SSP (an action) and nothing meets SC-12 on Azure (a blocker), until
               CHG-2032; the target sends mail through Azure Communication Services, which Microsoft's scope tables
               don't list (an action, a blocker once CHG-2029 holds the target to DFARS), and once CHG-2015 gives it
               a DNS Private Resolver forwarder, that isn't listed either (a blocker); CHG-2033 moves the forwarder to
               the landing zone's DNS servers (virtual machines, in scope) and approves exception EXC-2026-04 for the
               reset mail (it carries no CUI): shown as accepted
  budgets      what each environment may spend: the source 25000 USD a month (alerts at 80% and 100% spent and 100%
               forecast to its paging channel; AWS Budgets in its Terraform state), the standby 12000 USD on the
               billing account its cloud names (rendered in its landing zone). Planted: the target has no budget (a
               blocker for the unbound role and an action), until CHG-2028 records one
"""
import json
from types import MappingProxyType

from .common import AWS, AZ, CERTS, GCP, OWN, R, spec, t

TAG_POLICY = f"ou=tag-policy,{R}"
OBLIGATIONS = f"ou=reporting-obligations,{R}"
EXCEPTIONS = f"ou=exceptions,{R}"
AUTHORIZATIONS = f"ou=authorizations,{R}"
AUTHORIZED = MappingProxyType({"source": f"cn=AGENCYAMAZONEW,{AUTHORIZATIONS}",
                               "target": f"cn=F1209051525,{AUTHORIZATIONS}",
                               "standby": f"cn=FR1805751477,{AUTHORIZATIONS}"})
ORGANIZATIONS = MappingProxyType({"standby": "organizations/123456789012"})
SUPPRESSION_RULE = "arn:aws:securityhub:us-east-1:111122223333:automation-rule/0f3c2d1e-5b6a-4c7d-8e9f-a0b1c2d3e4f5"
DFARS = f"cn=dfars-7012,{OBLIGATIONS}"
# (cn, tag key, where its value comes from)
TAG_RULES = (("owner", "Owner", "owner"), ("cost-center", "CostCenter", "cost-center"),
             ("data-classification", "DataClassification", "classification"),
             ("environment", "Environment", "environment"))
COST_CENTERS = MappingProxyType({"ciam-platform": "CC-1001", "customer-portal-team": "CC-2040",
                                 "supplier-portal-team": "CC-2041"})
# environment -> data classification (the target has none yet: planted)
CLASSIFICATION = MappingProxyType({"source": "confidential", "stage": "internal", "standby": "confidential",
                                   "lab": "internal"})
ACCOUNTS = MappingProxyType({"source": "111122223333", "target": "00000000-0000-0000-0000-000000000000",
                             "standby": "example-aero-ciam-standby"})
SECURITY_TOPIC = "arn:aws:sns:us-east-1:111122223333:ciam-prod-security"
INCIDENT_TOPIC = "arn:aws:sns:us-east-1:111122223333:ciam-prod-security-incidents"
CONFIG_BUCKET = "example-aero-ciam-prod-config"
DETECTOR = "arn:aws:guardduty:us-east-1:111122223333:detector/6ec9a2f1b3d4e5f60718293a4b5c6d7e"
HUB = "arn:aws:securityhub:us-east-1:111122223333:hub/default"
_SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
_WORKSPACE = (f"{_SUB}/resourceGroups/rg-ciam-prod/providers/Microsoft.OperationalInsights/workspaces/"
              "law-ciam-prod-security")
_PROJECT = "projects/example-aero-ciam-standby"
_ALL = {"ciamAuditScope": "account", "ciamAllRegions": "TRUE", "ciamFindingsRole": "security-findings"}
_INCIDENTS = {"ciamIncidentRole": "security-incidents", "ciamIncidentSeverity": "high"}
# the organization's own data types every data discovery service looks for: CUI banner markings, employee numbers
OWN_DATA_TYPES = ("cui-marking: CUI//[A-Z][A-Z/-]*", "employee-id: EA[0-9]{6}")
_DISCOVERY = {"ciamScansRole": "backup-target", "ciamCustomIdentifier": list(OWN_DATA_TYPES), "ciamRescanDays": 7,
              "ciamFindingsRole": "security-findings"}
MACIE_JOB = "arn:aws:macie2:us-east-1:111122223333:classification-job/3ce05dbb7ec5505def334104bf1b1fd5"
# Each environment's security bindings: (class, name, binding role, attributes).
SECURITY = MappingProxyType({
    "source": (
        ("ciamAlertChannel", "security-alerts", "security-findings",
         {"ciamChannelKind": "topic", "ciamProviderRef": SECURITY_TOPIC}),
        ("ciamAlertChannel", "security-incidents", "security-incidents",
         {"ciamChannelKind": "topic", "ciamProviderRef": INCIDENT_TOPIC}),
        ("ciamObjectStore", "config-history", "config-history",
         {"ciamStorageRef": f"s3://{CONFIG_BUCKET}", "ciamProviderRef": f"arn:aws:s3:::{CONFIG_BUCKET}",
          "ciamStorageVersioning": "TRUE"}),
        ("ciamSecurityService", "guardduty", "threat-detection",
         {"ciamSecurityKind": "threat-detection", **_ALL, "ciamProviderRef": DETECTOR, **_INCIDENTS,
          "ciamSecurityCoverage": ["control-plane", "identity", "network", "compute", "containers", "storage",
                                   "databases"]}),
        ("ciamSecurityService", "inspector", "vulnerability-scanning",
         {"ciamSecurityKind": "vulnerability-scanning", "ciamAuditScope": "account",
          "ciamFindingsRole": "security-findings", "ciamSecurityCoverage": ["compute", "containers"],
          "ciamProviderRef": "inspector2:111122223333-EC2:ECR"}),
        ("ciamSecurityService", "config", "config-recording",
         {"ciamSecurityKind": "config-recording", "ciamAuditScope": "account", "ciamRetentionDays": 2557,
          "ciamFindingsRole": "config-history", "ciamProviderRef": "config-recorder:config"}),
        ("ciamSuppression", "exc-EXC-2026-01", "suppression-EXC-2026-01",
         {"ciamFindingRef": "aws:securityhub:IAM.6", "ciamExceptionRef": f"cn=EXC-2026-01,{EXCEPTIONS}",
          "ciamProviderRef": SUPPRESSION_RULE}),
        ("ciamSecurityService", "security-hub", "posture",
         {"ciamSecurityKind": "posture", "ciamAuditScope": "account", "ciamFindingsRole": "security-findings",
          "ciamComplianceStandard": ["nist-800-53-r5", "nist-800-171-r2"],
          "ciamSecurityBaseline": "aws-foundational", "ciamProviderRef": HUB}),
        ("ciamDataDiscovery", "macie-backups", "data-discovery", {**_DISCOVERY, "ciamProviderRef": MACIE_JOB})),
    # planted: no Defender for Containers (no containers watched or scanned), not assessed against NIST SP 800-171
    # Rev. 2, no configuration history recorded, no incident routing (CHG-2029 routes Defender's high alerts), no data
    # discovery (CHG-2034 records Defender's sensitive data discovery)
    "target": (
        ("ciamLogDestination", "security-logs", "security-findings",
         {"ciamDestinationKind": "workspace", "ciamRetentionDays": 400, "ciamProviderRef": _WORKSPACE}),
        ("ciamSecurityService", "defender", "threat-detection",
         {"ciamSecurityKind": "threat-detection", **_ALL,
          "ciamSecurityCoverage": ["control-plane", "identity", "network", "compute", "storage", "databases"],
          "ciamProviderRef": f"{_SUB}/providers/Microsoft.Security/pricings/defender"}),
        ("ciamSecurityService", "defender-vulnerability", "vulnerability-scanning",
         {"ciamSecurityKind": "vulnerability-scanning", **_ALL, "ciamSecurityCoverage": "compute",
          "ciamProviderRef": f"{_SUB}/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/"
                             "AzureServersSetting"}),
        ("ciamSecurityService", "defender-cspm", "posture",
         {"ciamSecurityKind": "posture", **_ALL, "ciamComplianceStandard": "nist-800-53-r5",
          "ciamSecurityBaseline": "microsoft-cloud-security-benchmark",
          "ciamProviderRef": f"{_SUB}/providers/Microsoft.Security/pricings/CloudPosture"})),
    "standby": (
        ("ciamStreamBinding", "security-findings", "security-findings",
         {"ciamStreamKind": "topic", "ciamProviderRef": f"{_PROJECT}/topics/ciam-security"}),
        ("ciamStreamBinding", "security-incidents", "security-incidents",
         {"ciamStreamKind": "topic", "ciamProviderRef": f"{_PROJECT}/topics/ciam-security-incidents"}),
        ("ciamSecurityService", "scc", "threat-detection",
         {"ciamSecurityKind": "threat-detection", **_ALL, **_INCIDENTS,
          "ciamSecurityCoverage": ["control-plane", "identity", "network", "compute", "containers", "storage"],
          "ciamProviderRef": f"{_PROJECT}/locations/global/notificationConfigs/scc-findings"}),
        ("ciamSecurityService", "assets", "config-recording",
         {"ciamSecurityKind": "config-recording", **_ALL, "ciamRetentionDays": 35,
          "ciamProviderRef": f"{_PROJECT}/feeds/assets"}),
        ("ciamDataDiscovery", "sdp-backups", "data-discovery",
         {**_DISCOVERY, "ciamProviderRef": f"{_PROJECT}/locations/us-east4/discoveryConfigs/ciam-backups"})),
})

# Each environment's quota needs and budget, as bindings (class, name, binding role, attributes): the budget alerts the
# environment's paging channel (observability's alerts-page)
_NEEDS = (("vcpus", "quota-vcpus"), ("public-ips", "quota-public-ips"),
          ("database-instances", "quota-database-instances"))
BUDGET_ARN = "arn:aws:budgets::111122223333:budget/source-prod-monthly-spend"
_BUDGET = {"ciamBudgetPeriod": "monthly", "ciamActualThreshold": [80, 100], "ciamForecastThreshold": 100,
           "ciamAlertRole": "alerts-page"}
BILLING_ACCOUNTS = MappingProxyType({"standby": "01A2B3-C4D5E6-F7A8B9"})


def _needs(counts):
    return tuple(("ciamQuotaNeed", role, role, {"ciamQuotaKind": kind, "ciamQuotaNeeded": n})
                 for (kind, role), n in zip(_NEEDS, counts))


COSTS = MappingProxyType({
    "source": (*_needs((96, 8, 2)),
               ("ciamBudget", "monthly-spend", "budget",
                {"ciamBudgetAmount": "25000", "ciamCurrency": "USD", **_BUDGET, "ciamProviderRef": BUDGET_ARN})),
    "target": _needs((96, 8, 2)),        # planted: no budget (CHG-2028 records one)
    "standby": (*_needs((48, 4, 1)),
                ("ciamBudget", "monthly-spend", "budget",
                 {"ciamBudgetAmount": "12000", "ciamCurrency": "USD", **_BUDGET})),
})


def entries():
    return (*(spec("15-tag-policy", f"cn={cn},{TAG_POLICY}", ["top", "ciamTagRule"], cn=cn, ciamTagKey=key,
                   ciamTagSource=source, description=f"Every rendered resource carries {key}")
              for cn, key, source in TAG_RULES),
            spec("16-reporting-obligations", DFARS, ["top", "ciamReportingObligation"], cn="dfars-7012",
                 ciamReportingHours=72, ciamInternalReportingHours=1,
                 ciamReportingAuthority=f"cn=dod-dc3,{OWN}", ciamReportingParty=f"cn=security-operations,{OWN}",
                 ciamMalwareSubmission="https://www.dc3.mil", ciamPreservationDays=90,
                 ciamReportingCertificateRef=f"cn=dibnet-eca,{CERTS}", ciamContractNumber="FA0000-26-C-0001",
                 ciamDocUrl="https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-"
                            "and-cyber-incident-reporting", ciamRequiredAuthorization="fedramp-moderate",
                 description="DFARS 252.204-7012: rapidly report cyber incidents (72 hours from discovery) on DIBNet "
                             "(synthetic contract number)"),
            *compliance(), *authorizations())


AO = f"cn=authorizing-official,{OWN}"


def compliance():
    """The CMMC assessment, the POA&M item and the exceptions (17-compliance)."""
    return (spec("17-compliance", f"cn=CMMC-2026,ou=assessments,{R}", ["top", "ciamComplianceAssessment"],
                 cn="CMMC-2026", ciamFramework="cmmc-l2", ciamAssessmentKind="c3pao", ciamAssessedAt=t("2026-08-15"),
                 ciamAssessmentScore=104, ciamAssessmentMaxScore=110, ciamAssessmentStatus="conditional",
                 ciamAffectedEnvironment=[AWS, AZ], ciamFullScoreBy=t("2026-12-15"),
                 ciamAssessmentRef="C3PAO report EA-2026-L2-017 (synthetic)", ciamOwner=[AO]),
            spec("17-compliance", f"cn=POAM-2026-001,ou=poam,{R}", ["top", "ciamPoamItem"], cn="POAM-2026-001",
                 ciamWeakness="PingDS's LDAPS runs on a JSSE provider that isn't FIPS 140 validated",
                 ciamPoamStatus="open", ciamAffectedEnvironment=[AWS, AZ],
                 ciamControlRef=["cmmc-l2:SC.L2-3.13.11", "nist-800-171-r2:3.13.11"],
                 ciamDiscoverySource="assessment", ciamAssessmentRef="C3PAO report EA-2026-L2-017 (synthetic)",
                 ciamDiscoveredAt=t("2026-08-15"), ciamScheduledCompletion=t("2026-12-15"),
                 ciamMilestone=["2026-10-31: FIPS provider (Bouncy Castle FIPS) qualified on stage",
                                "2026-12-15: production directory servers switched over"],
                 ciamRiskRating="moderate", ciamPointValue=3, ciamOwner=[f"cn=ciam-platform,{OWN}"]),
            spec("17-compliance", f"cn=EXC-2026-01,{EXCEPTIONS}", ["top", "ciamRiskException"], cn="EXC-2026-01",
                 ciamExceptionKind="false-positive", ciamExceptionStatus="approved", ciamAffectedEnvironment=AWS,
                 ciamFindingRef="aws:securityhub:IAM.6",
                 ciamJustification="the root user is disabled by a service control policy; its hardware MFA device is "
                                   "held by the break-glass process the control can't see",
                 ciamRiskAuthority=AO, ciamApprovedBy="CAB 2026-09-18", ciamApprovedAt=t("2026-09-18"),
                 ciamExpiresAt=t("2027-03-31"), ciamOwner=[f"cn=ciam-platform,{OWN}"]),
            # planted: approved without an expiry (CHG-2030 records it)
            spec("17-compliance", f"cn=EXC-2026-02,{EXCEPTIONS}", ["top", "ciamRiskException"], cn="EXC-2026-02",
                 ciamExceptionKind="risk-acceptance", ciamExceptionStatus="approved", ciamAffectedEnvironment=AZ,
                 ciamAcceptsFinding="Security: vulnerability-scanning watches containers",
                 ciamJustification="the target runs no containers until the PingGateway move in 2027; Defender for "
                                   "Containers is enabled with it",
                 ciamRiskAuthority=AO, ciamApprovedBy="CAB 2026-09-18", ciamApprovedAt=t("2026-09-18"),
                 ciamOwner=[f"cn=ciam-platform,{OWN}"]))


# provider -> what its region command printed: AWS (RegionName, OptInStatus; the commercial partition's endpoints)
AWS_REGIONS = (("us-east-1", "opt-in-not-required"), ("us-east-2", "opt-in-not-required"),
               ("us-west-1", "opt-in-not-required"), ("us-west-2", "opt-in-not-required"),
               ("ca-central-1", "opt-in-not-required"), ("eu-west-1", "opt-in-not-required"),
               ("eu-central-1", "opt-in-not-required"), ("af-south-1", "not-opted-in"), ("me-south-1", "not-opted-in"))
# Azure (name, display name, geography, geography group, physical location, paired region; None: a logical location)
AZURE_LOCATIONS = (("eastus", "East US", "United States", "US", "Virginia", "westus"),
                   ("eastus2", "East US 2", "United States", "US", "Virginia", "centralus"),
                   ("centralus", "Central US", "United States", "US", "Iowa", "eastus2"),
                   ("westus2", "West US 2", "United States", "US", "Washington", "westcentralus"),
                   ("canadacentral", "Canada Central", "Canada", "Canada", "Toronto", "canadaeast"),
                   ("westeurope", "West Europe", "Europe", "Europe", "Netherlands", "northeurope"),
                   ("northeurope", "North Europe", "Europe", "Europe", "Ireland", "westeurope"),
                   ("uksouth", "UK South", "United Kingdom", "UK", "London", "ukwest"),
                   ("unitedstates", "United States", None, "US", None, None),
                   ("europe", "Europe", None, "Europe", None, None))
GCP_REGIONS = ("us-central1", "us-east1", "us-east4", "us-west1", "northamerica-northeast1", "europe-west1",
               "europe-west2")


def _aws():
    return {"Regions": [{"Endpoint": f"ec2.{r}.amazonaws.com", "RegionName": r, "OptInStatus": s}
                        for r, s in AWS_REGIONS]}


def _azure_location(name, display, geography, group, place, paired):
    sub = "/subscriptions/" + ACCOUNTS["target"]
    meta = ({"regionType": "Physical", "regionCategory": "Recommended", "geography": geography,
             "geographyGroup": group, "physicalLocation": place,
             "pairedRegion": [{"id": f"{sub}/locations/{paired}", "name": paired}]} if geography else
            {"regionType": "Logical", "regionCategory": "Other", "geographyGroup": group})
    return {"displayName": display, "id": f"{sub}/locations/{name}", "metadata": meta, "name": name,
            "regionalDisplayName": f"({group}) {display}" if geography else display, "type": "Region"}


def _gcp():
    base = f"https://www.googleapis.com/compute/v1/projects/{ACCOUNTS['standby']}/regions"
    return [{"kind": "compute#region", "name": r, "description": r, "status": "UP",
             "zones": [f"https://www.googleapis.com/compute/v1/projects/{ACCOUNTS['standby']}/zones/{r}-{z}"
                       for z in "abc"], "selfLink": f"{base}/{r}"} for r in GCP_REGIONS]


def region_exports():
    """{path under exports/: text} of what each provider's region command printed."""
    return {"regions/aws/regions.json": json.dumps(_aws(), indent=4) + "\n",
            "regions/azure/regions.json": json.dumps([_azure_location(*loc) for loc in AZURE_LOCATIONS],
                                                     indent=2) + "\n",
            "regions/gcp/regions.json": json.dumps(_gcp(), indent=2) + "\n"}


# what each provider's quota commands printed for the environments' regions: AWS (service, quota code, name, default,
# applied value or None), Azure (usage name, localized name, limit, current value), Google Cloud (metric, limit, usage)
AWS_QUOTAS = (("ec2", "L-1216C47A", "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances", 5.0, 256.0),
              ("ec2", "L-0263D0A3", "EC2-VPC Elastic IPs", 5.0, 20.0),
              ("ec2", "L-34B43A08", "All Standard (A, C, D, H, I, M, R, T, Z) Spot Instance Requests", 5.0, None),
              ("rds", "L-7B6409FD", "DB instances", 40.0, None),
              ("rds", "L-952B80B8", "Parameter groups", 50.0, None))
AZURE_COMPUTE = (("cores", "Total Regional vCPUs", 50, 0), ("standardDSv5Family", "Standard DSv5 Family vCPUs", 10, 0),
                 ("virtualMachines", "Virtual Machines", 25000, 0))
AZURE_NETWORK = (("VirtualNetworks", "Virtual Networks", 1000, 2),
                 ("PublicIPAddresses", "Public IP Addresses", 1000, 3),
                 ("LoadBalancers", "Load Balancers", 1000, 1))
GCP_REGION_QUOTAS = (("CPUS", 72.0, 12.0), ("IN_USE_ADDRESSES", 8.0, 2.0), ("N2_CPUS", 24.0, 0.0),
                     ("DISKS_TOTAL_GB", 4096.0, 500.0))
GCP_PROJECT_QUOTAS = (("NETWORKS", 15.0, 2.0), ("FIREWALLS", 200.0, 9.0))


def _aws_quotas(service, applied):
    account = "" if not applied else ACCOUNTS["source"]
    return {"Quotas": [{"ServiceCode": s, "ServiceName": s.upper(), "QuotaArn": f"arn:aws:servicequotas:us-east-1:"
                        f"{account}:{s}/{code}", "QuotaCode": code, "QuotaName": name,
                        "Value": value if applied else default, "Unit": "None", "Adjustable": True,
                        "GlobalQuota": False} for s, code, name, default, value in AWS_QUOTAS
                       if s == service and (value is not None or not applied)]}


def _azure_usages(rows, network):
    sub = "/subscriptions/" + ACCOUNTS["target"]
    return [{**({"id": f"{sub}/providers/Microsoft.Network/locations/eastus2/usages/{n}"} if network else {}),
             "currentValue": cur, "limit": lim, "name": {"localizedValue": loc, "value": n}, "unit": "Count"}
            for n, loc, lim, cur in rows]


def quota_exports():
    """{path under exports/: text} of what each provider's quota commands printed for the environments' regions."""
    gproject = ACCOUNTS["standby"]
    return {"quotas/aws/caller.json": json.dumps({"UserId": "AIDAEXAMPLEOPERATOR01", "Account": ACCOUNTS["source"],
                                                  "Arn": f"arn:aws:iam::{ACCOUNTS['source']}:user/ciam-operator"},
                                                 indent=4) + "\n",
            **{f"quotas/aws/us-east-1/{s}{x}.json": json.dumps(_aws_quotas(s, applied), indent=4) + "\n"
               for s in ("ec2", "rds") for x, applied in (("-defaults", False), ("", True))},
            "quotas/azure/account.json": json.dumps({"environmentName": "AzureCloud", "id": ACCOUNTS["target"],
                                                     "isDefault": True, "name": "ciam-prod", "state": "Enabled",
                                                     "tenantId": "11111111-1111-1111-1111-111111111111"},
                                                    indent=2) + "\n",
            "quotas/azure/eastus2/compute.json": json.dumps(_azure_usages(AZURE_COMPUTE, False), indent=2) + "\n",
            "quotas/azure/eastus2/network.json": json.dumps(_azure_usages(AZURE_NETWORK, True), indent=2) + "\n",
            "quotas/gcp/project.json": json.dumps({
                "kind": "compute#project", "name": gproject,
                "selfLink": f"https://www.googleapis.com/compute/v1/projects/{gproject}",
                "quotas": [{"metric": m, "limit": lim, "usage": use} for m, lim, use in GCP_PROJECT_QUOTAS]},
                indent=2) + "\n",
            "quotas/gcp/us-central1.json": json.dumps({
                "kind": "compute#region", "name": "us-central1", "status": "UP",
                "selfLink": f"https://www.googleapis.com/compute/v1/projects/{gproject}/regions/us-central1",
                "quotas": [{"metric": m, "limit": lim, "usage": use} for m, lim, use in GCP_REGION_QUOTAS]},
                indent=2) + "\n"}


# What production uses of AWS US East/West, as AWS's Certification Package Overview names it (exports/fedramp/: AWS's
# real package id, offering and service names; the list trimmed to these)
AWS_SERVICES = ("Amazon Elastic Compute Cloud (EC2)", "Amazon Virtual Private Cloud (VPC)", "Amazon RDS for Postgres",
                "Amazon Simple Storage Service (S3)", "Amazon Elastic Block Store (EBS)",
                "AWS Key Management Service (KMS)", "AWS Secrets Manager", "AWS Certificate Manager (ACM)",
                "Amazon Simple Notification Service (SNS)", "Amazon Cloudwatch", "Amazon Cloudwatch Logs",
                "AWS CloudTrail", "Amazon GuardDuty", "Amazon Inspector", "AWS Config", "AWS Security Hub CSPM",
                "Amazon Route 53", "AWS Backup", "AWS Identity and Access Management (IAM)", "AWS Organizations",
                "Amazon EventBridge", "Amazon Simple Email Service (SES)", "Amazon Kinesis Data Streams")
# What the target and the standby may use, as Microsoft's compliance-scope page (Azure table) and Google's Assured
# Workloads supported products (Data Boundary for FedRAMP High) name them: a subset of each
AZURE_SERVICES = ("Virtual Machines", "Virtual Machine Scale Sets", "Virtual Network", "Load Balancer", "Private Link",
                  "Azure Database for PostgreSQL", "Storage: Blobs (incl. Azure Data Lake Storage Gen2)",
                  "Storage: Disks (incl. managed disks)", "Key Vault", "Backup",
                  "Azure Monitor (incl. Application Insights, Log Analytics, and Application Change Analysis)",
                  "Microsoft Defender for Cloud (formerly Azure Security Center)", "Resource Graph", "Azure Policy",
                  "DNS", "Event Hubs", "Service Bus", "Front Door", "Web Application Firewall", "VPN Gateway",
                  "Microsoft Entra ID (P1 + P2)", "Azure Kubernetes Service (AKS)", "Container Registry")
GCP_SERVICES = ("Compute Engine", "Virtual Private Cloud (VPC)", "Cloud Load Balancing", "Cloud SQL", "Cloud Storage",
                "Persistent Disk", "Cloud Key Management Service (Cloud KMS)", "Secret Manager", "Cloud Logging",
                "Cloud Monitoring", "Security Command Center", "Cloud Asset Inventory", "Pub/Sub", "Cloud DNS",
                "Backup and DR Service", "Identity and Access Management (IAM)", "Organization Policy Service",
                "Cloud VPN", "Cloud Interconnect")
SSP = f"cn=SSP-CIAM-2026,ou=boundaries,{R}"
SC12 = "nist-800-53-r5:SC-12"


def authorizations():
    """The authorizations, the system boundary and the control responsibilities (18-authorizations)."""
    owner = [f"cn=ciam-platform,{OWN}"]
    return (spec("18-authorizations", AUTHORIZED["source"], ["top", "ciamCloudAuthorization"], cn="AGENCYAMAZONEW",
                 ciamPackageId="AGENCYAMAZONEW", ciamCloudProvider="aws", ciamCloudEnvironment="public",
                 ciamAuthorizationLevel="fedramp-moderate", ciamAuthorizationStatus="certified",
                 ciamCertifiedAt=t("2013-05-01"), ciamCrmRef="AWS CIS/CRM workbook (FedRAMP package, trust center)",
                 ciamDocUrl="https://www.fedramp.gov/marketplace/products/AGENCYAMAZONEW/", ciamOwner=owner),
            spec("18-authorizations", AUTHORIZED["target"], ["top", "ciamCloudAuthorization"], cn="F1209051525",
                 ciamPackageId="F1209051525", ciamOfferingName="Azure Commercial Cloud", ciamProviderName="Microsoft",
                 ciamCloudProvider="azure", ciamCloudEnvironment="public", ciamDeploymentModel="Public Cloud",
                 ciamAuthorizationLevel="fedramp-high", ciamAuthorizationStatus="certified",
                 ciamCertificationType="Rev5", ciamCertifiedAt=t("2019-05-03"), ciamInScopeService=list(AZURE_SERVICES),
                 ciamScopeAsOf=t("2026-09-15"), ciamRetrievedAt=t("2026-09-20"),
                 ciamSourceUrl="https://learn.microsoft.com/en-us/azure/azure-government/compliance/"
                               "azure-services-in-fedramp-auditscope",
                 ciamCrmRef="Azure CIS/CRM workbook (FedRAMP package)",
                 ciamDocUrl="https://www.fedramp.gov/marketplace/products/F1209051525/", ciamOwner=owner),
            spec("18-authorizations", AUTHORIZED["standby"], ["top", "ciamCloudAuthorization"], cn="FR1805751477",
                 ciamPackageId="FR1805751477", ciamOfferingName="Google Services", ciamProviderName="Google",
                 ciamCloudProvider="gcp", ciamCloudEnvironment="public", ciamDeploymentModel="Public Cloud",
                 ciamAuthorizationLevel="fedramp-high", ciamAuthorizationStatus="certified",
                 ciamCertificationType="Rev5", ciamCertifiedAt=t("2019-12-04"), ciamInScopeService=list(GCP_SERVICES),
                 ciamScopeAsOf=t("2026-09-15"), ciamRetrievedAt=t("2026-09-20"),
                 ciamSourceUrl="https://cloud.google.com/assured-workloads/docs/supported-products",
                 ciamRequiresConfiguration="assured-workload",
                 ciamDocUrl="https://www.fedramp.gov/marketplace/products/FR1805751477/", ciamOwner=owner),
            spec("18-authorizations", SSP, ["top", "ciamSystemBoundary"], cn="SSP-CIAM-2026",
                 ciamSspRef="SSP-CIAM-2026 v3.1 (synthetic)", ciamAffectedEnvironment=[AWS, GCP],
                 ciamRiskAuthority=f"cn=authorizing-official,{OWN}", ciamOwner=owner),
            spec("18-authorizations", f"cn=aws-sc-12,ou=responsibilities,{R}", ["top", "ciamControlResponsibility"],
                 cn="aws-sc-12", ciamAuthorizationRef=AUTHORIZED["source"], ciamControlRef=SC12,
                 ciamResponsibility="inherited", ciamOwner=owner),
            # planted: nothing meets it on Azure (CHG-2032 records the implementation)
            spec("18-authorizations", f"cn=azure-sc-12,ou=responsibilities,{R}", ["top", "ciamControlResponsibility"],
                 cn="azure-sc-12", ciamAuthorizationRef=AUTHORIZED["target"], ciamControlRef=SC12,
                 ciamResponsibility="customer",
                 ciamCustomerAction="establish and manage the keys of customer-managed encryption (Key Vault)",
                 ciamOwner=owner))


def cpo_exports():
    """{path under exports/: text} of the AWS US East/West Certification Package Overview production relies on, in the
    FRC-CSO-PKG shape (AWS's package id, offering and service names; trimmed to what production uses)."""
    doc = {"serviceIdentification": {"fedRampPackageId": "AGENCYAMAZONEW", "providerName": "Amazon Web Services, Inc.",
                                     "serviceName": "AWS US East/West", "serviceAcronym": "AWS",
                                     "serviceDescription": "Trimmed for the showcase to the services production uses",
                                     "certificationType": "Rev5", "website": "https://aws.amazon.com/",
                                     "logo": "https://www.fedramp.gov/assets/img/logos/CSP_logos/Amazon%20Logo.png"},
           "serviceProperties": {"serviceType": ["IaaS", "PaaS", "SaaS"], "deploymentModel": "Public Cloud",
                                 "securityCategorization": "Moderate (FedRAMP Certification Level Class C)"},
           "cpoMetadata": {"version": "2026.08.26", "lastUpdated": "2026-08-26T18:21:46.492Z"},
           "contactInformation": [{"contactType": "Security", "contactName": "AWS Compliance FedRAMP"}],
           "certifiedServices": [{"serviceName": s, "serviceDescription": s} for s in AWS_SERVICES]}
    return {"fedramp/aws-east-west-cpo.json": json.dumps(doc, indent=2) + "\n"}

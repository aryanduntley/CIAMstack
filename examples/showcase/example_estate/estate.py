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
  quotas       what each environment needs of its provider's limits (COSTS: vCPUs, public addresses, database
               instances; stage shares production's account and needs nothing of its own) and the limits each
               provider's quota commands printed (exports/quotas/<provider>/, the real CLI output shapes, synthetic
               values), imported by approved changes CHG-2025 (aws/quotas), CHG-2026 (azure/quotas) and CHG-2027
               (gcp/quotas). Planted: until CHG-2026 the target's limits aren't fetched (an action); then its region
               grants 50 vCPUs where it needs 96 (an action whose fix asks the operator to request 96, a value of
               their own, or deny) and Azure reports no limit on database instances (an action: confirm it with
               Microsoft); CHG-2028 approves the increase, which leaves an action until the quotas are fetched again
  budgets      what each environment may spend: the source 25000 USD a month (alerts at 80% and 100% spent and 100%
               forecast to its paging channel; AWS Budgets in its Terraform state), the standby 12000 USD on the
               billing account its cloud names (rendered in its landing zone). Planted: the target has no budget (a
               blocker for the unbound role and an action), until CHG-2028 records one
"""
import json
from types import MappingProxyType

from .common import R, spec

TAG_POLICY = f"ou=tag-policy,{R}"
# (cn, tag key, where its value comes from)
TAG_RULES = (("owner", "Owner", "owner"), ("cost-center", "CostCenter", "cost-center"),
             ("data-classification", "DataClassification", "classification"),
             ("environment", "Environment", "environment"))
COST_CENTERS = MappingProxyType({"ciam-platform": "CC-1001", "customer-portal-team": "CC-2040",
                                 "supplier-portal-team": "CC-2041"})
# environment -> data classification (the target has none yet: planted)
CLASSIFICATION = MappingProxyType({"source": "confidential", "stage": "internal", "standby": "confidential"})
ACCOUNTS = MappingProxyType({"source": "111122223333", "target": "00000000-0000-0000-0000-000000000000",
                             "standby": "example-aero-ciam-standby"})
SECURITY_TOPIC = "arn:aws:sns:us-east-1:111122223333:ciam-prod-security"
CONFIG_BUCKET = "example-aero-ciam-prod-config"
DETECTOR = "arn:aws:guardduty:us-east-1:111122223333:detector/6ec9a2f1b3d4e5f60718293a4b5c6d7e"
HUB = "arn:aws:securityhub:us-east-1:111122223333:hub/default"
_SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
_WORKSPACE = (f"{_SUB}/resourceGroups/rg-ciam-prod/providers/Microsoft.OperationalInsights/workspaces/"
              "law-ciam-prod-security")
_PROJECT = "projects/example-aero-ciam-standby"
_ALL = {"ciamAuditScope": "account", "ciamAllRegions": "TRUE", "ciamFindingsRole": "security-findings"}
# Each environment's security bindings: (class, name, binding role, attributes).
SECURITY = MappingProxyType({
    "source": (
        ("ciamAlertChannel", "security-alerts", "security-findings",
         {"ciamChannelKind": "topic", "ciamProviderRef": SECURITY_TOPIC}),
        ("ciamObjectStore", "config-history", "config-history",
         {"ciamStorageRef": f"s3://{CONFIG_BUCKET}", "ciamProviderRef": f"arn:aws:s3:::{CONFIG_BUCKET}",
          "ciamStorageVersioning": "TRUE"}),
        ("ciamSecurityService", "guardduty", "threat-detection",
         {"ciamSecurityKind": "threat-detection", **_ALL, "ciamProviderRef": DETECTOR,
          "ciamSecurityCoverage": ["control-plane", "identity", "network", "compute", "containers", "storage",
                                   "databases"]}),
        ("ciamSecurityService", "inspector", "vulnerability-scanning",
         {"ciamSecurityKind": "vulnerability-scanning", "ciamAuditScope": "account",
          "ciamFindingsRole": "security-findings", "ciamSecurityCoverage": ["compute", "containers"],
          "ciamProviderRef": "inspector2:111122223333-EC2:ECR"}),
        ("ciamSecurityService", "config", "config-recording",
         {"ciamSecurityKind": "config-recording", "ciamAuditScope": "account", "ciamRetentionDays": 2557,
          "ciamFindingsRole": "config-history", "ciamProviderRef": "config-recorder:config"}),
        ("ciamSecurityService", "security-hub", "posture",
         {"ciamSecurityKind": "posture", "ciamAuditScope": "account", "ciamFindingsRole": "security-findings",
          "ciamComplianceStandard": ["nist-800-53-r5", "nist-800-171-r2"],
          "ciamSecurityBaseline": "aws-foundational", "ciamProviderRef": HUB})),
    # planted: no Defender for Containers (no containers watched or scanned), not assessed against NIST SP 800-171
    # Rev. 2, no configuration history recorded
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
        ("ciamSecurityService", "scc", "threat-detection",
         {"ciamSecurityKind": "threat-detection", **_ALL,
          "ciamSecurityCoverage": ["control-plane", "identity", "network", "compute", "containers", "storage"],
          "ciamProviderRef": f"{_PROJECT}/locations/global/notificationConfigs/scc-findings"}),
        ("ciamSecurityService", "assets", "config-recording",
         {"ciamSecurityKind": "config-recording", **_ALL, "ciamRetentionDays": 35,
          "ciamProviderRef": f"{_PROJECT}/feeds/assets"})),
})

# Each environment's quota needs and budget, as bindings (class, name, binding role, attributes): the budget alerts the
# environment's paging channel (observability's alerts-page)
_NEEDS = (("vcpus", "quota-vcpus"), ("public-ips", "quota-public-ips"), ("database-instances", "quota-database-instances"))
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
    return tuple(spec("15-tag-policy", f"cn={cn},{TAG_POLICY}", ["top", "ciamTagRule"], cn=cn, ciamTagKey=key,
                      ciamTagSource=source, description=f"Every rendered resource carries {key}")
                 for cn, key, source in TAG_RULES)


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
AZURE_NETWORK = (("VirtualNetworks", "Virtual Networks", 1000, 2), ("PublicIPAddresses", "Public IP Addresses", 1000, 3),
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

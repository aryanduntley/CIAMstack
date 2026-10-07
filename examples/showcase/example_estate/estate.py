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

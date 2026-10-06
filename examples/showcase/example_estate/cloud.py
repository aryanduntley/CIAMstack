"""What the clouds report the environments run (pure: builds text). Generated from the same fixture data as the record,
so each export matches it except for the drift planted in each cloud's module, which `opsdir import --dry-run` shows:
cloud_aws (source/prod: Terraform state of the stack and of the landing zone), cloud_azure (target/prod: Azure CLI
output and a role map), cloud_gcp (standby/prod: Cloud Asset Inventory and gcloud output). Every environment's public
names are on the corporate DNS team's Infoblox, so no cloud's DNS holds them.
"""
from opsdir.core.jsondata import indented

from .cloud_aws import landing_zone_state, source_state
from .cloud_azure import target_inventory
from .cloud_gcp import standby_inventory
from .common import AWS, AZ, GCP


def cloud_exports():
    """{path under exports/cloud/: text}: what each cloud reports its environment runs."""
    source, target, standby = (dn.split(",")[1].split("=")[1] for dn in (AWS, AZ, GCP))
    return {f"{source}/prod/terraform.tfstate": source_state(),
            f"{source}/prod/landing-zone.tfstate": landing_zone_state(),
            **{f"{target}/prod/{name}": indented(doc) for name, doc in target_inventory().items()},
            **{f"{standby}/prod/{name}": text for name, text in standby_inventory().items()}}

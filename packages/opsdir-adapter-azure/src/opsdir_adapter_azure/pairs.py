"""Azure's region pairs: where Azure copies what it keeps geo-redundantly (a Flexible Server's geo-redundant backups,
GRS storage) from each region. Pure."""

# Azure's region pairs (Microsoft: "Azure region pairs and nonpaired regions"; Azure Government's from "Azure
# Government overview", list of regions): a region -> the region its geo-redundant copies go to. Some pairs are one-way
# (westus3 -> eastus, brazilsouth -> southcentralus, usgovvirginia -> usgovtexas); a region not here (a nonpaired
# region, or one whose pair isn't published: US DoD Central and East) is named, not guessed.
PAIRS = {"eastus": "westus", "westus": "eastus", "eastus2": "centralus", "centralus": "eastus2",
         "westus2": "westcentralus", "westcentralus": "westus2", "westus3": "eastus",
         "northcentralus": "southcentralus", "southcentralus": "northcentralus", "brazilsouth": "southcentralus",
         "canadacentral": "canadaeast", "canadaeast": "canadacentral", "northeurope": "westeurope",
         "westeurope": "northeurope", "uksouth": "ukwest", "ukwest": "uksouth", "francecentral": "francesouth",
         "francesouth": "francecentral", "germanywestcentral": "germanynorth", "germanynorth": "germanywestcentral",
         "swedencentral": "swedensouth", "switzerlandnorth": "switzerlandwest",
         "switzerlandwest": "switzerlandnorth", "norwayeast": "norwaywest", "norwaywest": "norwayeast",
         "eastasia": "southeastasia", "southeastasia": "eastasia", "japaneast": "japanwest", "japanwest": "japaneast",
         "koreacentral": "koreasouth", "koreasouth": "koreacentral", "australiaeast": "australiasoutheast",
         "australiasoutheast": "australiaeast", "centralindia": "southindia", "southindia": "centralindia",
         "westindia": "southindia", "indiasouthcentral": "centralindia", "brazilsoutheast": "brazilsouth",
         "australiacentral": "australiacentral2", "australiacentral2": "australiacentral",
         "southafricanorth": "southafricawest", "southafricawest": "southafricanorth", "uaenorth": "uaecentral",
         "uaecentral": "uaenorth",
         "usgovvirginia": "usgovtexas", "usgovarizona": "usgovtexas", "usgovtexas": "usgovarizona"}


def paired_region(region):
    """The region Azure pairs region with (where its geo-redundant copies go), or None when it isn't known here."""
    return PAIRS.get((region or "").lower().replace(" ", ""))

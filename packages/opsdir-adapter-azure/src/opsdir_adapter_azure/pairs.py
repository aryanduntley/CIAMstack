"""Azure's region pairs: where Azure copies what it keeps geo-redundantly (a Flexible Server's geo-redundant backups,
GRS storage) from each region. Pure."""

# Azure's cross-region replication pairs (Microsoft: "Azure cross-region replication pairings for all geographies"):
# a region -> the region its geo-redundant copies go to. Some pairs are one-way (westus3 -> eastus, brazilsouth ->
# southcentralus); a region not here (US Gov Texas pairs with two) is named, not guessed.
PAIRS = {"eastus": "westus", "westus": "eastus", "eastus2": "centralus", "centralus": "eastus2",
         "westus2": "westcentralus", "westcentralus": "westus2", "westus3": "eastus",
         "northcentralus": "southcentralus", "southcentralus": "northcentralus", "brazilsouth": "southcentralus",
         "canadacentral": "canadaeast", "canadaeast": "canadacentral", "northeurope": "westeurope",
         "westeurope": "northeurope", "uksouth": "ukwest", "ukwest": "uksouth", "francecentral": "francesouth",
         "francesouth": "francecentral", "germanywestcentral": "germanynorth", "germanynorth": "germanywestcentral",
         "swedencentral": "swedensouth", "swedensouth": "swedencentral", "switzerlandnorth": "switzerlandwest",
         "switzerlandwest": "switzerlandnorth", "norwayeast": "norwaywest", "norwaywest": "norwayeast",
         "eastasia": "southeastasia", "southeastasia": "eastasia", "japaneast": "japanwest", "japanwest": "japaneast",
         "koreacentral": "koreasouth", "koreasouth": "koreacentral", "australiaeast": "australiasoutheast",
         "australiasoutheast": "australiaeast", "centralindia": "southindia", "southindia": "centralindia",
         "usgovvirginia": "usgovtexas", "usgovarizona": "usgovtexas"}


def paired_region(region):
    """The region Azure pairs region with (where its geo-redundant copies go), or None when it isn't known here."""
    return PAIRS.get((region or "").lower().replace(" ", ""))

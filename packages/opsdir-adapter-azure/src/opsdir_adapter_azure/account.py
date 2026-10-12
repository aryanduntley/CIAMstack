"""The Azure subscription an environment runs in and how every resource rendered for it is tagged: the provider versions
every root pins (the current releases, validated against), the azurerm provider block of each root (the subscription
its input names, Azure Government when the cloud is in it, the resource providers it registers: none but the landing
zone's, a note when the cloud says its clients use FIPS endpoints: azurerm has no switch for them), the subscription
the record names (ciamAccountRef) as the default of each root's subscription_id input, and the estate's tag policy
merged into each resource's own tags (azurerm has no provider-wide default tags). Pure."""
from opsdir.core.directory import one, rdn_value, values
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.estate.tags import required_tags
from opsdir_format_terraform.hcl import Block, comment, ref, tf_block

FIPS_NOTE = ("FIPS endpoints: Azure has no separate FIPS endpoints for the provider to use; FIPS 140 is met by the "
             "services' own validated modules, or by Azure Government (ciamCloudEnvironment usgovernment)")
AZURERM_VERSION = "~> 5.9"          # validated against hashicorp/azurerm 5.9.0
AZAPI_VERSION = "~> 2.13"           # validated against Azure/azapi 2.13.0
AZUREAD_VERSION = "~> 3.10"         # validated against hashicorp/azuread 3.10.0
AZAPI_ADD_ON = "azapi"              # ciamProviderAddOn: the cloud allows Microsoft's azapi provider



def azapi_allowed(m):
    """Whether environment m's cloud allows Microsoft's azapi provider for what azurerm doesn't manage
    (ciamProviderAddOn azapi)."""
    return AZAPI_ADD_ON in values(m.cloud, "ciamProviderAddOn")


# What Microsoft's Azure Government documentation (2026-10) doesn't say is available there, for a renderer's note
GOV_UNSTATED = ("Azure Government: Microsoft's Azure Government documentation (2026-10) doesn't state that {} {} "
                "available there: confirm with the account team before relying on it")


def government_unstated(m, what, verb="is"):
    """The Azure Government note for something whose availability there Microsoft doesn't state, in environment m's
    cloud when it is Azure Government, else ()."""
    return (comment(GOV_UNSTATED.format(what, verb)),) if government(m) else ()


def government(m):
    """Whether environment m's cloud runs in Azure Government (a US Gov or US DoD region)."""
    return (one(m.cloud, "ciamRegion") or "").lower().startswith(("usgov", "usdod"))

def required_providers(azapi=False, azuread=False):
    """The terraform block of an Azure root: azurerm, azapi when the root renders azapi resources, azuread when it
    renders Microsoft Entra ID policy (risk-based Conditional Access)."""
    return tf_block("terraform", [], [("required_providers", Block((
        ("azurerm", {"source": "hashicorp/azurerm", "version": AZURERM_VERSION}),
        *((("azapi", {"source": "Azure/azapi", "version": AZAPI_VERSION}),) if azapi else ()),
        *((("azuread", {"source": "hashicorp/azuread", "version": AZUREAD_VERSION}),) if azuread else ()))))])


def azuread_provider(m):
    """The azuread provider block of a root of environment m: Microsoft Graph in the cloud's environment (Azure
    Government: usgovernment, its DoD regions usgovernmentl5; Graph at graph.microsoft.us / dod-graph.microsoft.us)."""
    region = (one(m.cloud, "ciamRegion") or "").lower()
    env = "usgovernmentl5" if region.startswith("usdod") else \
        "usgovernment" if one(m.cloud, "ciamCloudEnvironment") == "usgovernment" else None
    return tf_block("provider", ["azuread"], [("environment", env)] if env else [])


def provider_block(m, register=()):
    """The azurerm provider block of a root of environment m. It registers no resource providers of its own
    (resource_provider_registrations "none"), but those in register (the landing zone's, for every root)."""
    gov = (("environment", "usgovernment"),) if one(m.cloud, "ciamCloudEnvironment") == "usgovernment" else ()
    listed = (("resource_providers_to_register", list(register)),) if register else ()
    return tf_block("provider", ["azurerm"], [*((("#", FIPS_NOTE),) if fips_endpoints(m) else ()),
                                            ("features", Block(())), ("subscription_id", ref("var.subscription_id")),
                                            *gov, ("resource_provider_registrations", "none"), *listed])


def subscription_id(m):
    """The subscription environment m's cloud records (ciamAccountRef), or None."""
    return one(m.cloud, "ciamAccountRef")


def subscription_variable(m, described=False):
    """The subscription_id input of a root of environment m, defaulting to the recorded subscription."""
    return tf_block("variable", ["subscription_id"], [
        ("type", ref("string")),
        *((("description", f"The subscription {rdn_value(m.env)} runs in"),) if described else ()),
        *((("default", subscription_id(m)),) if subscription_id(m) else ())])


def tagged(m, own):
    """A resource's tags in environment m: the tag policy's, with the resource's own over them."""
    return {**required_tags(m), **own}

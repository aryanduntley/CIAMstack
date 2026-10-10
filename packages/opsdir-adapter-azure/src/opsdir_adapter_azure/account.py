"""The Azure subscription an environment runs in and how every resource rendered for it is tagged: the azurerm provider
block of each root (the subscription its input names, Azure Government when the cloud is in it, a note when the cloud
says its clients use FIPS endpoints: azurerm has no switch for them), the subscription the record names
(ciamAccountRef) as the default of each root's subscription_id input, and the estate's tag policy merged into each
resource's own tags (azurerm has no provider-wide default tags). Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.estate.tags import required_tags
from opsdir_format_terraform.hcl import Block, block, ref

FIPS_NOTE = ("FIPS endpoints: Azure has no separate FIPS endpoints for the provider to use; FIPS 140 is met by the "
             "services' own validated modules, or by Azure Government (ciamCloudEnvironment usgovernment)")



def government(m):
    """Whether environment m's cloud runs in Azure Government (a US Gov or US DoD region)."""
    return (one(m.cloud, "ciamRegion") or "").lower().startswith(("usgov", "usdod"))

def provider_block(m):
    """The azurerm provider block of a root of environment m."""
    gov = (("environment", "usgovernment"),) if one(m.cloud, "ciamCloudEnvironment") == "usgovernment" else ()
    return block("provider", ["azurerm"], [*((("#", FIPS_NOTE),) if fips_endpoints(m) else ()), ("features", Block(())),
                                            ("subscription_id", ref("var.subscription_id")), *gov])


def subscription_id(m):
    """The subscription environment m's cloud records (ciamAccountRef), or None."""
    return one(m.cloud, "ciamAccountRef")


def subscription_variable(m, described=False):
    """The subscription_id input of a root of environment m, defaulting to the recorded subscription."""
    return block("variable", ["subscription_id"], [
        ("type", ref("string")),
        *((("description", f"The subscription {rdn_value(m.env)} runs in"),) if described else ()),
        *((("default", subscription_id(m)),) if subscription_id(m) else ())])


def tagged(m, own):
    """A resource's tags in environment m: the tag policy's, with the resource's own over them."""
    return {**required_tags(m), **own}

"""The Azure subscription an environment runs in and how every resource rendered for it is tagged: the subscription
the record names (ciamAccountRef) as the default of each root's subscription_id input, and the estate's tag policy
merged into each resource's own tags (azurerm has no provider-wide default tags). Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.domains.estate.tags import required_tags
from opsdir_format_terraform.hcl import block, ref


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

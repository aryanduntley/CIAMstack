"""Azure resource IDs as the Azure readers take them apart: a segment of an ARM ID, a subnet's reference in the record
(<virtual network>/<subnet>); and an item's field in any case. Shared by the Terraform state, CLI and ARM readers.
Pure."""


def arm_segment(arm_id, after):
    """The ARM ID segment following `after` (case-insensitive): arm_segment('/…/vaults/kv-1', 'vaults') == 'kv-1'."""
    parts = (arm_id or "").split("/")
    return next((parts[i + 1] for i, p in enumerate(parts[:-1]) if p.lower() == after.lower()), None)


def with_properties(item):
    """An ARM item with its properties merged into it: the CLI prints some resources flattened, others nested under
    properties, as an ARM template does."""
    props = item.get("properties")
    return {**item, **props} if isinstance(props, dict) else item


def arm_field(item, name):
    """An item's field by name in any case (the CLI prints mxRecords and frequency; an ARM template may say MXRecords
    and Frequency), None when absent."""
    return next((v for k, v in item.items() if k.lower() == name.lower()), None)


def subnet_ref(arm_id):
    """<virtual network>/<subnet> of a subnet's ARM ID, the record's provider reference for it."""
    vnet, sub = arm_segment(arm_id, "virtualNetworks"), arm_segment(arm_id, "subnets")
    return f"{vnet}/{sub}" if vnet and sub else None

"""What the Azure CLI family readers share of an item (a CLI output's, or an ARM template resource's as arm.py shapes
it). Pure."""


def flattened(item):
    """An item's fields with its properties merged in, as the CLI prints most resources (some commands, az rest among
    them, print them nested)."""
    return {**item, **(item.get("properties") or {})} if isinstance(item.get("properties"), dict) else item

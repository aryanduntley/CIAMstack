"""Azure: reading back what Microsoft's azapi provider wrote. An azapi resource's state attributes hold its ARM body
(body): an object, or JSON text as an older state holds it. The read-backs that take an azapi resource as the azurerm
or CLI resource it stands for (a continuous export, an alert suppression rule, a VPN connection, a Purview scan's
data source and trigger) read it here. Pure."""
import json


def azapi_body(a):
    """An azapi resource's body from its state attributes a: an object, or JSON text (as an older state holds it)
    parsed; {} otherwise (none, not JSON, not an object)."""
    b = a.get("body")
    try:
        b = json.loads(b) if isinstance(b, str) else b
    except ValueError:
        return {}
    return b if isinstance(b, dict) else {}

"""What the Google Cloud renderers share: the network and region every resource is placed in, the network tag a server
role's instances carry (what firewall rules target) and labels as Google Cloud allows them. Pure."""
import re

from opsdir.core.directory import rdn_value
from opsdir_format_terraform.hcl import ref

NETWORK = ref("data.google_compute_network.main.self_link")
REGION = ref("var.region")


def network_tag(m, role):
    """The network tag of environment m's servers of a role."""
    return f"ciam-{rdn_value(m.env)}-{role}"


def label(v):
    """A label value as Google Cloud allows it (lowercase letters, digits, - and _; 63 characters)."""
    return re.sub(r"[^a-z0-9_-]", "-", (v or "").lower())[:63]

"""What the Google Cloud renderers and readers share: the network and region every resource is placed in, the network
tag a server role's instances carry (what firewall rules target), labels as Google Cloud allows them, and resource
names taken apart. Pure."""
import re

from opsdir.core.directory import rdn_value
from opsdir_format_terraform.hcl import ref

NETWORK = ref("data.google_compute_network.main.self_link")
REGION = ref("var.region")
PRIORITIES = (1000, 10, 65535)        # firewall rule and policy rule priorities: first slot, step, last
MANAGED = "Managed by opsdir"         # what a resource the platform's own Terraform made says (where labels can't)
_SELF_LINK = re.compile(r"^(?:https:)?//[^/]+/(?:(?:[a-z]+/)?(?:v\d+[a-z0-9]*|beta|alpha)/)?")


def state_labels(a, own=None):
    """All the labels a source reports on a resource: effective_labels (the provider's default labels included) with
    its own (own, else its labels) over them; what the estate's tag check judges."""
    return {**(a.get("effective_labels") or {}), **(own if own is not None else a.get("labels") or {})}


def network_tag(m, role):
    """The network tag of environment m's servers of a role."""
    return f"ciam-{rdn_value(m.env)}-{role}"


def label(v):
    """A label value as Google Cloud allows it (lowercase letters, digits, - and _; 63 characters)."""
    return re.sub(r"[^a-z0-9_-]", "-", (v or "").lower())[:63]


def resource_id(v):
    """A Google Cloud resource name from an id, a self link (https://<api host>/[<api>/]v1/projects/...) or a Cloud
    Asset Inventory full resource name (//<service>.googleapis.com/projects/...)."""
    return _SELF_LINK.sub("", v) if v else v


def name_parts(resource_name):
    """{collection: id} of a Google Cloud resource name (projects/p/regions/r/subnetworks/s; 'global' dropped); {}
    when it isn't one."""
    tokens = [t for t in resource_id(resource_name or "").split("/") if t != "global"]
    return dict(zip(tokens[::2], tokens[1::2])) if tokens and len(tokens) % 2 == 0 else {}

"""The Google Cloud project an environment runs in and how every resource rendered for it is labelled: the project the
record names (ciamAccountRef) as the default of each root's project_id input, the estate's tag policy as the
provider's default labels, in label form (lowercase letters, digits, - and _), and a note when the cloud says its
clients use FIPS endpoints (the google provider has no switch for them). Pure."""
import re

from opsdir.core.directory import one, rdn_value
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.estate.tags import required_tags
from opsdir_format_terraform.hcl import block, ref
from .names import label


def project_id(m):
    """The project environment m's cloud records (ciamAccountRef), or None."""
    return one(m.cloud, "ciamAccountRef")


def project_variable(m, described=False):
    """The project_id input of a root of environment m, defaulting to the recorded project."""
    return block("variable", ["project_id"], [
        ("type", ref("string")),
        *((("description", f"The project {rdn_value(m.env)} runs in"),) if described else ()),
        *((("default", project_id(m)),) if project_id(m) else ())])


def label_key(key):
    """A tag key as a label key: lowercase, [a-z0-9_-], starting with a letter."""
    return re.sub(r"^[^a-z]+", "", label(key)) or "tag"


def default_labels(m):
    """The tag policy's tags in environment m as labels."""
    return {label_key(k): label(v) for k, v in required_tags(m).items()}


FIPS_NOTE = ("FIPS endpoints: the google provider has no FIPS endpoint switch; FIPS 140 is met by Google Cloud's own "
             "validated modules, or enforced for a folder with Assured Workloads")


def provider_block(m, *body):
    """The google provider block of environment m: a FIPS note when its cloud uses FIPS endpoints, the given settings,
    then the policy's default labels."""
    labels = default_labels(m)
    return block("provider", ["google"], [*((("#", FIPS_NOTE),) if fips_endpoints(m) else ()), *body,
                                          *((("default_labels", labels),) if labels else ())])

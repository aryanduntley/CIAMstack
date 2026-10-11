"""The Google Cloud project an environment runs in and how every resource rendered for it is labelled: the provider
version every root pins (the current release, validated against), the project the record names (ciamAccountRef) as
the default of each root's project_id input, the estate's tag policy as the provider's default labels, in label form
(lowercase letters, digits, - and _), and a note when the cloud says its clients use FIPS endpoints (the google
provider has no switch for them); and the Assured Workloads compliance regime an environment's required authorization
level asks for (Google Cloud has no separate government cloud: a regulated placement is a workload under such a
regime). Pure."""
import re

from opsdir.core.directory import one, rdn_value
from opsdir.domains.estate.authorizations import required_levels
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.estate.tags import required_tags
from opsdir_format_terraform.hcl import Block, ref, tf_block
from .names import label

GOOGLE_VERSION = "~> 8.6"           # validated against hashicorp/google 8.6.0


def required_providers():
    """The terraform block of a Google Cloud root: the google provider."""
    return tf_block("terraform", [], [("required_providers", Block((
        ("google", {"source": "hashicorp/google", "version": GOOGLE_VERSION}),)))])


def project_id(m):
    """The project environment m's cloud records (ciamAccountRef), or None."""
    return one(m.cloud, "ciamAccountRef")


def project_variable(m, described=False):
    """The project_id input of a root of environment m, defaulting to the recorded project."""
    return tf_block("variable", ["project_id"], [
        ("type", ref("string")),
        *((("description", f"The project {rdn_value(m.env)} runs in"),) if described else ()),
        *((("default", project_id(m)),) if project_id(m) else ())])


# the Assured Workloads compliance regime of each required level, the most demanding first
REGIMES = (("dod-il5", "IL5"), ("dod-il4", "IL4"), ("fedramp-high", "FEDRAMP_HIGH"),
           ("fedramp-moderate", "FEDRAMP_MODERATE"), ("dod-il2", "IL2"))


def regime(m):
    """The Assured Workloads compliance regime environment m's most demanding required authorization level asks for
    (IL5, IL4, FEDRAMP_HIGH, FEDRAMP_MODERATE, IL2), or None when it requires none of them."""
    return next((r for level, r in REGIMES if level in required_levels(m)), None)


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
    return tf_block("provider", ["google"], [*((("#", FIPS_NOTE),) if fips_endpoints(m) else ()), *body,
                                             *((("default_labels", labels),) if labels else ())])

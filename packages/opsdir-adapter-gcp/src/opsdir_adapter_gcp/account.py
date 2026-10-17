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
from opsdir.domains.estate.regulated import regulated_data
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.estate.tags import required_tags
from opsdir.core.notes import note, note_comment
from opsdir_format_terraform.hcl import Block, ref, tf_block
from .names import label

GOOGLE_VERSION = "~> 8.7"           # validated against hashicorp/google 8.7.0
ARCHIVE_VERSION = "~> 2.8"          # validated against hashicorp/archive 2.8.1 (the current release, 2026-10-14)


def required_providers(archive=False):
    """The terraform block of a Google Cloud root: the google provider, and archive when the root packages function
    source."""
    return tf_block("terraform", [], [("required_providers", Block((
        ("google", {"source": "hashicorp/google", "version": GOOGLE_VERSION}),
        *((("archive", {"source": "hashicorp/archive", "version": ARCHIVE_VERSION}),) if archive else ()))))])


def project_id(m):
    """The project environment m's cloud records (ciamAccountRef), or None."""
    return one(m.cloud, "ciamAccountRef")


def project_variable(m, described=False):
    """The project_id input of a root of environment m, defaulting to the recorded project."""
    return tf_block("variable", ["project_id"], [
        ("type", ref("string")),
        *((("description", f"The project {rdn_value(m.env)} runs in"),) if described else ()),
        *((("default", project_id(m)),) if project_id(m) else ())])


ORGANIZATION = "organization_id"


def organization_id(m):
    """The organization environment m's cloud belongs to (its ciamOrganizationRef organizations/<id>, or a bare id), or
    None when the record names none or a folder."""
    ref_ = one(m.cloud, "ciamOrganizationRef") or ""
    kind, _, rest = ref_.rpartition("/")
    return rest if rest and kind in ("", "organizations") else None


def organization_variable(m, description):
    """The organization_id input of a root of environment m (organization-wide settings are made on it), defaulting
    to the recorded organization."""
    return tf_block("variable", [ORGANIZATION], [
        ("type", ref("string")), ("description", description),
        *((("default", organization_id(m)),) if organization_id(m) else ())])


# the Assured Workloads compliance regime of each required level, the most demanding first
REGIMES = (("dod-il5", "IL5"), ("dod-il4", "IL4"), ("fedramp-high", "FEDRAMP_HIGH"),
           ("fedramp-moderate", "FEDRAMP_MODERATE"), ("dod-il2", "IL2"))


# the Assured Workloads compliance regime holding each kind of regulated data (google 8.6's values; the API renamed them
# DATA_BOUNDARY_FOR_ITAR and so on), the most demanding first; Google has no package for EAR (research note 2805)
DATA_REGIMES = (("itar", "ITAR"), ("cjis", "CJIS"), ("irs-1075", "IRS_1075"),
                ("hipaa", "HEALTHCARE_AND_LIFE_SCIENCES_CONTROLS_US_SUPPORT"))


def level_regime(m):
    """The Assured Workloads compliance regime environment m's most demanding required authorization level asks for
    (IL5, IL4, FEDRAMP_HIGH, FEDRAMP_MODERATE, IL2), or None when it requires none of them."""
    return next((r for level, r in REGIMES if level in required_levels(m)), None)


def data_regime(m):
    """The Assured Workloads compliance regime the regulated data environment m holds asks for (ITAR, CJIS, IRS_1075,
    the healthcare package), the most demanding first, or None."""
    return next((r for kind, r in DATA_REGIMES if kind in regulated_data(m)), None)


def regime(m):
    """The compliance regime of environment m's Assured Workloads workload: one per workload, so the regulated data's
    when it holds some (a legal duty over the data: decision 2807; the planner names the level's package it doesn't
    apply), else its required level's, else None."""
    return data_regime(m) or level_regime(m)


def label_key(key):
    """A tag key as a label key: lowercase, [a-z0-9_-], starting with a letter."""
    return re.sub(r"^[^a-z]+", "", label(key)) or "tag"


def default_labels(m):
    """The tag policy's tags in environment m as labels."""
    return {label_key(k): label(v) for k, v in required_tags(m).items()}


FIPS_NOTE = ("the google provider has no FIPS endpoint switch; FIPS 140 is met by Google Cloud's own validated "
             "modules, or enforced for a folder with Assured Workloads")


def fips_note(m):
    """The render note (a plain note) of environment m's FIPS endpoints the google provider has no switch for, or
    None; every provider block writes its comment."""
    return note("Security", "note", "FIPS endpoints", FIPS_NOTE, (), None, m.label) if fips_endpoints(m) else None


def provider_block(m, *body):
    """The google provider block of environment m: a FIPS note when its cloud uses FIPS endpoints, the given settings,
    then the policy's default labels."""
    labels = default_labels(m)
    return tf_block("provider", ["google"], [*((("#", note_comment(fips_note(m))),) if fips_endpoints(m) else ()),
                                             *body,
                                             *((("default_labels", labels),) if labels else ())])

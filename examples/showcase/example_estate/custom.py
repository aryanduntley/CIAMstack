"""Custom definitions fixture data: fields and a record type the operator defines for the record itself
(22-custom-schema), and records of that type (90-feature-flags). The fields are used on environments and integrations
elsewhere in the estate (owners' cost centers are the core ciamCostCenter and environments' data residency the core
residencies: estate)."""
from types import MappingProxyType

from .common import CUSTOM, FLAGS, owner, spec
from .config import TOKEN_LIFETIME

# name -> definition attributes (the metadata says what, which values, which records, where it lives, why)
FIELDS = (
    ("xTokenLifetimeMinutes", dict(
        ciamDefinitionNumber=3, ciamValueType="int", ciamPortability="intent", ciamCarriedBy="ciamIntegration",
        ciamMinValue=5, ciamMaxValue=1440, ciamUnit="minutes", ciamDefaultValue=60, ciamOverridable="TRUE",
        ciamPurpose="Access token lifetime agreed with the application owner",
        ciamSettingRef=TOKEN_LIFETIME, ciamUsedBy="pingfederate",
        ciamDefinitionStatus="active")),
    ("xFlagEnabled", dict(
        ciamDefinitionNumber=4, ciamValueType="bool", ciamPortability="intent",
        ciamPurpose="Whether the feature is on")),
    ("xRolloutPercent", dict(
        ciamDefinitionNumber=5, ciamValueType="int", ciamPortability="intent", ciamMinValue=0, ciamMaxValue=100,
        ciamUnit="percent", ciamPurpose="Share of users who get the feature")),
)
RECORD_TYPES = (
    ("xFeatureFlag", dict(
        ciamDefinitionNumber=1, ciamRecordKind="structural", ciamRequiredField="xFlagEnabled",
        ciamOptionalField=["xRolloutPercent", "description"], ciamPurpose="A feature switch of the login experience",
        ciamValueSource="pingfederate: authentication policy switches")),
)
FEATURE_FLAGS = (("passkey-enrollment", "TRUE", 25, "Offer passkey enrollment after sign-in"),
                 ("legacy-kba-recovery", "FALSE", None, "Knowledge-based account recovery (being retired)"))
# the values the estate's records carry: integration token lifetimes
TOKEN_LIFETIMES = MappingProxyType({"tech-pubs": 60, "mobile-ops": 30})


def definitions():
    file = "22-custom-schema"
    return (*(spec(file, f"cn={name},{CUSTOM}", ["top", "ciamFieldDefinition"], cn=name, ciamOwner=owner("ciam-platform"),
                   **attrs) for name, attrs in FIELDS),
            *(spec(file, f"cn={name},{CUSTOM}", ["top", "ciamRecordTypeDefinition"], cn=name,
                   ciamOwner=owner("ciam-platform"), **attrs) for name, attrs in RECORD_TYPES))


def feature_flags():
    return tuple(spec("90-feature-flags", f"cn={cn},{FLAGS}", ["top", "xFeatureFlag"], cn=cn, xFlagEnabled=on,
                      xRolloutPercent=pct, description=desc, ciamOwner=owner("ciam-platform"))
                 for cn, on, pct, desc in FEATURE_FLAGS)

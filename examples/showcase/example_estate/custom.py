"""Custom definitions fixture data: fields and a record type the operator defines for the record itself
(22-custom-schema), and records of that type (90-feature-flags). The fields are used on owners, environments and
integrations elsewhere in the estate."""
from .common import CUSTOM, FLAGS, owner, spec
from .config import TOKEN_LIFETIME

# name -> definition attributes (the metadata says what, which values, which records, where it lives, why)
FIELDS = (
    ("xCostCenter", dict(
        ciamDefinitionNumber=1, ciamValueType="string", ciamPortability="meta", ciamCarriedBy="ciamParty",
        ciamPattern="^CC-[0-9]{4}$", ciamExample="CC-1001", ciamPurpose="Cost center billed for the team's usage",
        ciamValueSource="finance: cost-center register", ciamPiiClass="none")),
    ("xDataResidency", dict(
        ciamDefinitionNumber=2, ciamValueType="enum:us|us-gov|eu|ca", ciamPortability="binding",
        ciamCarriedBy="ciamEnvironment", ciamOverridable="TRUE",
        ciamPurpose="Jurisdiction the environment's identity data must stay in",
        ciamDocumentation="https://wiki.example-aero.test/security/data-residency",
        ciamValueSource=["terraform: azurerm_resource_group.location", "terraform: aws provider region"])),
    ("xTokenLifetimeMinutes", dict(
        ciamDefinitionNumber=3, ciamValueType="int", ciamPortability="intent", ciamCarriedBy="ciamIntegration",
        ciamMinValue=5, ciamMaxValue=1440, ciamUnit="minutes", ciamDefaultValue=60,
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
# the values the estate's records carry: owner cost centers, environment residency, integration token lifetimes
COST_CENTERS = {"ciam-platform": "CC-1001", "customer-portal-team": "CC-2040", "supplier-portal-team": "CC-2041"}
RESIDENCY = {"source": "us", "target": "us-gov"}
TOKEN_LIFETIMES = {"tech-pubs": 60, "mobile-ops": 30}


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

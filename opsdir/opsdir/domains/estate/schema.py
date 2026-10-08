"""Estate domain schema: the cloud accounts the environments run in and how the estate's resources are marked. A cloud
(infrastructure's ciamCloud) may name its account (an AWS account, an Azure subscription, a Google Cloud project) and
the organization above it (the auxiliary class ciamCloudAccount); an environment its resource group and how sensitive
its data is and the residency it is held to (ciamEnvironmentPlacement); a party the cost center its spending is charged
to (ciamChargedParty). The tag policy (under ou=tag-policy) says which tags every resource rendered for an environment
carries and where each value comes from, so the renderers tag and the importers can say what the cloud has untagged.
The region catalog (under ou=regions) holds each provider's regions as the provider lists them, fetched with the
provider's own command (an adapter's prerequisite) and managed from then on like any other record; a residency (under
ou=residencies) is the estate's own classification of where data may be held, listing the catalog regions it allows,
so residency values are the estate's to define yet every environment names one that exists. A cloud may say its
clients use FIPS 140 validated endpoints (ciamCloudEndpoints). The cloud security services an environment runs
(ciamSecurityService: threat detection, vulnerability scanning, configuration recording, posture assessment) are
bindings: what each watches or assesses, where its findings go and how long it keeps its records."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import CLASSIFICATIONS, REGION_STATUSES, SECURITY_AREAS, SECURITY_KINDS, STANDARD_ID, TAG_SOURCES

ATTRIBUTES = (
    AttributeDef(482, 'ciamAccountRef', 'string', 'binding', True,
                 "The cloud account a cloud's environments run in: an AWS account ID, an Azure subscription ID, a "
                 "Google Cloud project ID"),
    AttributeDef(483, 'ciamOrganizationRef', 'string', 'binding', True,
                 'The organization the account belongs to: an AWS organization, an Azure tenant, a Google Cloud '
                 'organization or folder'),
    AttributeDef(484, 'ciamCostCenter', 'string', 'meta', True,
                 "The cost center a party's spending is charged to (resources of environments it owns are tagged "
                 "with it where the tag policy says so)"),
    AttributeDef(485, 'ciamDataClassification', enum_type(CLASSIFICATIONS), 'meta', True,
                 "How sensitive an environment's data is: public, internal, confidential, restricted"),
    AttributeDef(486, 'ciamTagKey', 'string', 'meta', True,
                 'The key of a tag (a label on Google Cloud) every resource rendered for an environment carries',
                 (("X-PATTERN", r"[A-Za-z][A-Za-z0-9_.:/=+@-]{0,62}"),)),
    AttributeDef(487, 'ciamTagSource', enum_type(TAG_SOURCES), 'meta', True,
                 "Where a tag rule takes its value in each environment: the environment's owner, that owner's cost "
                 "center, the environment's data classification, the environment (cloud/env), its cloud, or the "
                 "rule's own value (literal: ciamTagValue)"),
    AttributeDef(488, 'ciamTagValue', 'string', 'meta', True,
                 "A literal tag rule's value"),
    AttributeDef(489, 'ciamRegionName', 'string', 'meta', True,
                 "A cloud region's name as its provider shows it (Europe (Ireland), West Europe, Belgium)"),
    AttributeDef(490, 'ciamGeography', 'string', 'meta', True,
                 "Where a cloud region is, as its provider places it (a geography, country or continent), when the "
                 "provider says"),
    AttributeDef(491, 'ciamRegionStatus', enum_type(REGION_STATUSES), 'observed', True,
                 "A cloud region as its provider lists it: available, opt-in (open only to accounts that opt in) or "
                 "not-listed (no longer listed; kept so what names it keeps its link)"),
    AttributeDef(492, 'ciamResidencyRef', 'dn', 'intent', True,
                 "The residency an environment's data is held to (a ciamResidency under ou=residencies)"),
    AttributeDef(493, 'ciamAllowedRegion', 'dn', 'intent', False,
                 "A cloud region a residency allows data to be held in (a ciamCloudRegion of the region catalog)"),
    AttributeDef(494, 'ciamFipsEndpoints', 'bool', 'binding', True,
                 "Whether a cloud's clients (renderers' providers, the products' SDKs) use the provider's FIPS 140 "
                 "validated endpoints"),
    AttributeDef(499, 'ciamSecurityKind', enum_type(SECURITY_KINDS), 'binding', True,
                 "What a cloud security service does: threat-detection, vulnerability-scanning, config-recording "
                 "(resources' configuration and its changes) or posture (assessment against compliance frameworks and "
                 "the cloud's own baseline)"),
    AttributeDef(500, 'ciamSecurityCoverage', enum_type(SECURITY_AREAS), 'binding', False,
                 "What a threat-detection or vulnerability-scanning service watches: control-plane, identity, network, "
                 "compute, containers, storage, databases, key-vaults, applications"),
    AttributeDef(501, 'ciamComplianceStandard', 'string', 'binding', False,
                 "A compliance framework a posture service assesses the estate against, by a neutral id the clouds "
                 "share (nist-800-53-r5, nist-800-171-r2, fedramp-high, cmmc-l2, cis: its cloud's CIS benchmark)",
                 (("X-PATTERN", STANDARD_ID),)),
    AttributeDef(502, 'ciamSecurityBaseline', 'string', 'binding', False,
                 "A cloud's own security baseline a posture service assesses, by the name its adapter gives it: "
                 "one cloud's baseline never stands in for another's",
                 (("X-PATTERN", STANDARD_ID),)),
    AttributeDef(503, 'ciamFindingsRole', 'string', 'intent', True,
                 "The role of the binding a security service's findings (or recorded configuration) go to: an alert "
                 "channel, a log destination, an object store, a stream (a topic); none: they stay in the service"),
)
CLASSES = (
    ClassDef(103, 'ciamCloudAccount', 'top', 'AUXILIARY', (), ('ciamAccountRef', 'ciamOrganizationRef'),
             "Added to a cloud: the account its environments run in and the organization above it"),
    ClassDef(104, 'ciamEnvironmentPlacement', 'top', 'AUXILIARY', (),
             ('ciamResourceGroup', 'ciamDataClassification', 'ciamResidencyRef'),
             "Added to an environment: the resource group its resources go in (where the cloud has them), how "
             "sensitive its data is and the residency it is held to"),
    ClassDef(105, 'ciamChargedParty', 'top', 'AUXILIARY', (), ('ciamCostCenter',),
             "Added to a party: the cost center its spending is charged to"),
    ClassDef(106, 'ciamTagRule', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTagKey', 'ciamTagSource'), ('ciamTagValue',),
             "One tag of the estate's tag policy (under ou=tag-policy): its key and where its value comes from in "
             "each environment"),
    ClassDef(107, 'ciamRegionCatalog', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamCloudProvider'), (),
             "One provider's regions (under ou=regions, named after the provider): its ciamCloudRegion entries"),
    ClassDef(108, 'ciamCloudRegion', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('ciamRegionName', 'ciamGeography', 'ciamRegionStatus', 'ciamCloudEnvironment'),
             "A region of a provider's catalog, named by the provider's region code (eu-west-1, westeurope, "
             "europe-west1): its name, where it is, its status and partition"),
    ClassDef(109, 'ciamResidency', 'ciamObject', 'STRUCTURAL', ('cn',), ('ciamAllowedRegion',),
             "A residency the estate defines (under ou=residencies): where data held to it may be, as the catalog "
             "regions it allows (any provider's)"),
    ClassDef(110, 'ciamCloudEndpoints', 'top', 'AUXILIARY', (), ('ciamFipsEndpoints',),
             "Added to a cloud: how its clients reach the provider's APIs (FIPS 140 validated endpoints)"),
    ClassDef(112, 'ciamSecurityService', 'ciamBinding', 'STRUCTURAL', ('ciamSecurityKind',),
             ('ciamSecurityCoverage', 'ciamComplianceStandard', 'ciamSecurityBaseline', 'ciamAuditScope',
              'ciamAllRegions', 'ciamFindingsRole', 'ciamRetentionDays', 'ciamProviderRef', 'ciamManagedBy'),
             "A cloud security service an environment runs (threat detection, vulnerability scanning, configuration "
             "recording, posture assessment): what it watches or assesses, one account or the whole organization, "
             "every region or one, where its findings go, how long it keeps its records (ciamRetentionDays), and who "
             "keeps it when the platform team doesn't"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)

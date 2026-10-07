"""Estate domain schema: the cloud accounts the environments run in and how the estate's resources are marked. A cloud
(infrastructure's ciamCloud) may name its account (an AWS account, an Azure subscription, a Google Cloud project) and
the organization above it (the auxiliary class ciamCloudAccount); an environment its resource group and how sensitive
its data is (ciamEnvironmentPlacement); a party the cost center its spending is charged to (ciamChargedParty). The tag
policy (under ou=tag-policy) says which tags every resource rendered for an environment carries and where each value
comes from, so the renderers tag and the importers can say what the cloud has untagged."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import CLASSIFICATIONS, TAG_SOURCES

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
)
CLASSES = (
    ClassDef(103, 'ciamCloudAccount', 'top', 'AUXILIARY', (), ('ciamAccountRef', 'ciamOrganizationRef'),
             "Added to a cloud: the account its environments run in and the organization above it"),
    ClassDef(104, 'ciamEnvironmentPlacement', 'top', 'AUXILIARY', (), ('ciamResourceGroup', 'ciamDataClassification'),
             "Added to an environment: the resource group its resources go in (where the cloud has them) and how "
             "sensitive its data is"),
    ClassDef(105, 'ciamChargedParty', 'top', 'AUXILIARY', (), ('ciamCostCenter',),
             "Added to a party: the cost center its spending is charged to"),
    ClassDef(106, 'ciamTagRule', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTagKey', 'ciamTagSource'), ('ciamTagValue',),
             "One tag of the estate's tag policy (under ou=tag-policy): its key and where its value comes from in "
             "each environment"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)

"""Cloud governance fixture data (data file 15-tag-policy; the rest is used by governance and infrastructure): the
estate's tag policy, the cost center each party is charged to, how sensitive each environment's data is, and the cloud
account each cloud's environments run in (as the exports show them).

  tag policy   Owner (the environment's owner), CostCenter (that owner's cost center), DataClassification (the
               environment's), Environment (cloud/env): every resource rendered carries them (AWS default tags,
               Azure tags, Google Cloud default labels); every import names the resources the cloud reports without
               them (the source's predate the policy)
  accounts     source: AWS account 111122223333; target: the Azure subscription its exports show; standby: project
               example-aero-ciam-standby
  planted      the target environment records no data classification: its DataClassification tag has no value
"""
from types import MappingProxyType

from .common import R, spec

TAG_POLICY = f"ou=tag-policy,{R}"
# (cn, tag key, where its value comes from)
TAG_RULES = (("owner", "Owner", "owner"), ("cost-center", "CostCenter", "cost-center"),
             ("data-classification", "DataClassification", "classification"),
             ("environment", "Environment", "environment"))
COST_CENTERS = MappingProxyType({"ciam-platform": "CC-1001", "customer-portal-team": "CC-2040",
                                 "supplier-portal-team": "CC-2041"})
# environment -> data classification (the target has none yet: planted)
CLASSIFICATION = MappingProxyType({"source": "confidential", "stage": "internal", "standby": "confidential"})
ACCOUNTS = MappingProxyType({"source": "111122223333", "target": "00000000-0000-0000-0000-000000000000",
                             "standby": "example-aero-ciam-standby"})


def entries():
    return tuple(spec("15-tag-policy", f"cn={cn},{TAG_POLICY}", ["top", "ciamTagRule"], cn=cn, ciamTagKey=key,
                      ciamTagSource=source, description=f"Every rendered resource carries {key}")
                 for cn, key, source in TAG_RULES)

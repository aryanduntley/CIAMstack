"""An estate with a tag policy, for the estate domain's tests and the cloud adapters': two environments of the mini
estate owned by a party with a cost center, alpha classified (and its cloud's account recorded when asked), beta not;
tag rules for every source."""
from opsdir.core.interchange.ldif import LdifRecord
from network_fixtures import ALPHA, BETA, context, entry, model

PARTY = "cn=platform,ou=owners,dc=ciam-ops"
OU = "dn: ou={0},dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: {0}\n"


def rule(cn, key, source, value=None):
    return entry("ou=tag-policy,dc=ciam-ops", cn, "ciamTagRule", ciamTagKey=key, ciamTagSource=source,
                 **({"ciamTagValue": value} if value else {}))


RULES = (rule("owner", "Owner", "owner"), rule("cost-center", "CostCenter", "cost-center"),
         rule("classification", "DataClass", "classification"), rule("environment", "Environment", "environment"),
         rule("cloud", "Cloud", "cloud"), rule("estate", "Estate", "literal", "example"))


def _owned(env, classification="confidential", account=None):
    """Change records making env owned by the platform party, classified, and its cloud's account recorded."""
    cloud = env.split(",", 1)[1]
    return (LdifRecord(env, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                           ("replace", "ciamOwner", (PARTY,)),
                                           *((("replace", "ciamDataClassification", (classification,)),)
                                             if classification else ()))),
            *((LdifRecord(cloud, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                                ("replace", "ciamAccountRef", (account,)))),) if account else ()))


def estate(cost_center="CC-1234", beta_classification=None, rules=RULES, account=None, extra=()):
    party = (f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\nobjectClass: ciamChargedParty\ncn: platform\n"
             f"ciamOwnerKind: team\n" + (f"ciamCostCenter: {cost_center}\n" if cost_center else ""))
    d, alpha, beta = model(tree=(OU.format("owners"), OU.format("tag-policy"), party, *rules),
                           changes=(*_owned(ALPHA, account=account), *_owned(BETA, beta_classification), *extra))
    return context(d, alpha, beta, cutover="2026-12-01"), d, alpha, beta

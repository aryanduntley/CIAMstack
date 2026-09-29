"""Where PingAM's own entries live: ou=pingam, a branch per kind, a container per realm (named by the realm's
identity service), then the journey or policy set, then its nodes or policies."""
from opsdir.core.naming import branch, rdn_safe

PINGAM = branch("pingam")
JOURNEYS = branch("journeys", PINGAM)
POLICY_SETS = branch("policy-sets", PINGAM)
dn_safe = rdn_safe       # AM names with DN special characters are not imported


def realm_container(base, service_cn):
    return f"ou={service_cn},{base}"


def journey_dn(service_cn, tree):
    return f"cn={tree},{realm_container(JOURNEYS, service_cn)}"


def node_dn(journey, node_id):
    return f"cn={node_id},{journey}"


def policy_set_dn(service_cn, name):
    return f"cn={name},{realm_container(POLICY_SETS, service_cn)}"


def policy_dn(policy_set, name):
    return f"cn={name},{policy_set}"

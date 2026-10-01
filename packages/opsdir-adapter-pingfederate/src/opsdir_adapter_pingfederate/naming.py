"""Where PingFederate's own entries live: ou=pingfederate, a branch per kind, each object named by its id."""
from opsdir.core.naming import branch

PINGFEDERATE = branch("pingfederate")
DATA_STORES = branch("data-stores", PINGFEDERATE)
VALIDATORS = branch("credential-validators", PINGFEDERATE)
IDP_ADAPTERS = branch("idp-adapters", PINGFEDERATE)
SELECTORS = branch("authentication-selectors", PINGFEDERATE)
CONTRACTS = branch("policy-contracts", PINGFEDERATE)
POLICIES = branch("authentication-policies", PINGFEDERATE)
FRAGMENTS = branch("policy-fragments", PINGFEDERATE)
DEFAULT_POLICY = f"cn=default,{POLICIES}"            # the authentication policies' settings; its trees below it
# what a reference to a PingFederate object of a kind is named under (kinds as the importer reads them)
BASES = {"datastore": DATA_STORES, "validator": VALIDATORS, "idp-adapter": IDP_ADAPTERS, "selector": SELECTORS,
         "contract": CONTRACTS, "fragment": FRAGMENTS}


def named(base, name):
    return f"cn={name},{base}"

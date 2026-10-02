"""Where PingFederate's own entries live: ou=pingfederate, a branch per kind, each object named by its id."""
from types import MappingProxyType

from opsdir.core.naming import branch

SERVER_ROLES = ("pf-engine", "pf-admin")      # ciamServerRole / ciamTargetRole values this adapter defines
PINGFEDERATE = branch("pingfederate")
DATA_STORES = branch("data-stores", PINGFEDERATE)
VALIDATORS = branch("credential-validators", PINGFEDERATE)
IDP_ADAPTERS = branch("idp-adapters", PINGFEDERATE)
SELECTORS = branch("authentication-selectors", PINGFEDERATE)
CONTRACTS = branch("policy-contracts", PINGFEDERATE)
POLICIES = branch("authentication-policies", PINGFEDERATE)
FRAGMENTS = branch("policy-fragments", PINGFEDERATE)
TOKEN_MANAGERS = branch("access-token-managers", PINGFEDERATE)
OIDC_POLICIES = branch("oidc-policies", PINGFEDERATE)
NOTIFICATION_PUBLISHERS = branch("notification-publishers", PINGFEDERATE)
CAPTCHA_PROVIDERS = branch("captcha-providers", PINGFEDERATE)
SETTINGS = branch("settings", PINGFEDERATE)
AUTH_SERVER = f"cn=oauth-auth-server,{SETTINGS}"     # the authorization server's settings (scopes, grants, ...)
RESOURCES = branch("resources", PINGFEDERATE)          # resources held as is, a container per resource type
STORAGE = f"cn=storage,{SETTINGS}"                    # which store backs clients, grants, sessions (hivemodule.xml)
DISCOVERY_ROLE = "pf-cluster-discovery"              # where an environment's nodes find each other (a binding)
DISCOVERY_KEY_ROLE = "pf-cluster-discovery-key"      # the storage key AZURE_PING reads the container with
DEFAULT_POLICY = f"cn=default,{POLICIES}"            # the authentication policies' settings; its trees below it
# what a reference to a PingFederate object of a kind is named under (kinds as the importer reads them)
BASES = MappingProxyType({"datastore": DATA_STORES, "validator": VALIDATORS, "idp-adapter": IDP_ADAPTERS,
                          "selector": SELECTORS, "contract": CONTRACTS, "fragment": FRAGMENTS,
                          "access-token-manager": TOKEN_MANAGERS, "oidc-policy": OIDC_POLICIES})


def named(base, name):
    return f"cn={name},{base}"

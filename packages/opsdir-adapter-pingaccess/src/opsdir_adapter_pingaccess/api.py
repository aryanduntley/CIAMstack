"""PingAccess's Admin API v3 as this adapter reads and writes it: every vendor form the adapter relies on, in one place.
Data only.

UNVERIFIED. The forms below follow Ping's PingAccess 8.2-9.1 documentation (research note 3076, read 2026-10-15),
which describes the objects and most fields but doesn't establish the exact endpoint spellings, field names, paging
parameters or the configuration export's envelope for 9.1.1. Nothing here was checked against a live PingAccess or
its installed OpenAPI document (OPENAPI below). The acceptance items (README Known limits) are:
  - the installed OpenAPI 2.0 document of each supported version: every path, field and value below checked
  - a sanitized real configuration export (GET /config/export): its envelope, section names and how resources and
    secrets are written
A form found to differ is corrected here; the rest of the adapter reads it from this module.

Documented and relied on as such: the base path, the X-XSRF-Header, the Auditor role's read access (everything but
/config/*, /backup and agent configuration), the product's default ports and the heartbeat path.
"""
from collections import namedtuple
from types import MappingProxyType

API = "/pa-admin-api/v3"
XSRF = (("X-XSRF-Header", "PingAccess"),)
OPENAPI = f"{API}/api-docs/pa/api-docs-v2.json"       # the installed release's own schema (OpenAPI 2.0)
VERSION = "version"                                   # GET /version: {"version": "<product version>"}
PAGING = ("page", "numberPerPage")                    # a collection's paging parameters (page origin 1)
PAGE_SIZE = 200
ITEMS = "items"                                       # a collection response: {"items": [...]}
ID, NAME = "id", "name"                               # every object's numeric id and its name
NAME_FIELDS = MappingProxyType({"keyPairs": "alias", "certificates": "alias"})    # objects named otherwise
NO_REFERENCE = (None, 0)                              # a reference field naming nothing

# One collection of the Admin API (or a settings object): path relative to API ("{application}" the application's id
# for its resources); kind, the record entry it becomes (opsdir_adapter_pingaccess.naming.KINDS); bound, whether it is
# environment-bound (keys, trust, listeners, cluster nodes, agents: held, never rendered); settings, whether it is one
# object rather than a list. In the order objects are created: each after those it names (REFERENCES).
Collection = namedtuple("Collection", ("path", "kind", "bound", "settings"), defaults=(False, False))

COLLECTIONS = (
    Collection("certificates", "held", bound=True),
    Collection("trustedCertificateGroups", "held", bound=True),
    Collection("keyPairs", "held", bound=True),
    Collection("httpsListeners", "held", bound=True),
    Collection("engineListeners", "held", bound=True),
    Collection("engines", "held", bound=True),
    Collection("adminConfig", "held", bound=True, settings=True),
    Collection("adminConfig/replicaAdmins", "held", bound=True),
    Collection("agents", "held", bound=True),
    Collection("sidebandClients", "held", bound=True),
    Collection("availabilityProfiles", "held"),
    Collection("loadBalancingStrategies", "held"),
    Collection("siteAuthenticators", "held"),
    Collection("accessTokenValidators", "held"),
    Collection("pingfederate/runtime", "held", settings=True),
    Collection("oidc/provider", "held", settings=True),
    Collection("rules", "rule"),
    Collection("rulesets", "rule-set"),
    Collection("sites", "site"),
    Collection("virtualhosts", "virtual-host"),
    Collection("identityMappings", "identity-mapping"),
    Collection("webSessions", "web-session"),
    Collection("applications", "application"),
    Collection("applications/{application}/resources", "resource"),
)
# the fields naming other objects by id, by collection: ((field path, the collection it names), ...), a path's "*" any
# list item or object member
REFERENCES = MappingProxyType({
    "trustedCertificateGroups": ((("certificateIds", "*"), "certificates"),),
    "httpsListeners": ((("keyPairId",), "keyPairs"),),
    "engineListeners": ((("trustedCertificateGroupId",), "trustedCertificateGroups"),),
    "sites": ((("trustedCertificateGroupId",), "trustedCertificateGroups"),
              (("availabilityProfileId",), "availabilityProfiles"),
              (("loadBalancingStrategyId",), "loadBalancingStrategies"),
              (("siteAuthenticatorIds", "*"), "siteAuthenticators")),
    "virtualhosts": ((("keyPairId",), "keyPairs"), (("trustedCertificateGroupId",), "trustedCertificateGroups")),
    "webSessions": ((("clientCredentials", "keyPairId"), "keyPairs"),),
    "pingfederate/runtime": ((("trustedCertificateGroupId",), "trustedCertificateGroups"),),
    "applications": ((("siteId",), "sites"), (("agentId",), "agents"), (("virtualHostIds", "*"), "virtualhosts"),
                     (("webSessionId",), "webSessions"), (("identityMappingIds", "*"), "identityMappings"),
                     (("accessValidatorId",), "accessTokenValidators")),
})
# Policy: an application's or resource's {"Web": [{"type", "id"}], "API": [...]}, rules and rule sets in order; a rule
# set's members are its "policy" ids, rules or rule sets by its "elementType"
POLICY = "policy"
POLICY_TYPES = MappingProxyType({"Rule": "rules", "Ruleset": "rulesets"})
ELEMENT_TYPE = "elementType"
RESOURCES = "applications/{application}/resources"
APPLICATION_ID = "applicationId"                      # a resource's application, where an export lists them apart

# Web sessions: PingAccess as an OpenID Connect relying party
CLIENT_ID = ("clientCredentials", "clientId")
CREDENTIALS_TYPE = ("clientCredentials", "credentialsType")
# how the session's client authenticates, as the standard token endpoint methods it can be registered with
AUTH_METHODS = MappingProxyType({"SECRET": ("client_secret_basic", "client_secret_post"),
                                 "CERTIFICATE": ("tls_client_auth", "self_signed_tls_client_auth"),
                                 "PRIVATE_KEY_JWT": ("private_key_jwt",)})
LOGIN_TYPE = "oidcLoginType"
IMPLICIT_LOGINS = ("POST", "x_post")                  # the implicit-flow login types (the code flow is "Code")
PKCE = "pkceChallengeType"
NO_PKCE = (None, "", "OFF")
# where the OpenID provider the web sessions sign in with is configured: (settings path, its issuer field)
ISSUERS = (("pingfederate/runtime", "issuer"), ("oidc/provider", "issuer"))

# Identity mappings: what reaches the application about the user
CLASS_NAME = "className"
HEADER_MAPPING = "com.pingidentity.pa.identitymappings.HeaderIdentityMapping"
JWT_MAPPING = "com.pingidentity.pa.identitymappings.JwtIdentityMapping"
HEADER_FIELDS = (("configuration", "attributeHeaderMappings", "*", "headerName"),    # a header mapping's headers
                 ("configuration", "headerName"))                                    # a JWT mapping's header
ATTRIBUTE_FIELD = "attributeName"

# Sites and virtual hosts: what differs per environment
TARGETS = "targets"                                   # a site's ["host:port", ...]
SECURE = "secure"                                     # whether the site is reached over TLS
HOST, PORT = "host", "port"                           # a virtual host's
CONTEXT_ROOT = "contextRoot"                          # an application's path

# Secrets: a hidden field {"value", "encryptedValue"}: withheld whole, never its ciphertext
ENCRYPTED = "encryptedValue"
HIDDEN = "value"

# The configuration export (GET /config/export; Administrator only, so never collected): {"version", "data":
# {section: [items]}} with the export's encryption material beside them, removed on import and never stored
EXPORT_DATA = "data"
EXPORT_VERSION = "version"
EXPORT_KEY_MATERIAL = ("encryptionKey", "masterKeys", "masterKey", "exportKey")
# an export section's name -> the collection whose items it holds (both spellings where the documentation varies)
EXPORT_SECTIONS = MappingProxyType({
    **{c.path: c.path for c in COLLECTIONS if "{" not in c.path},
    "resources": RESOURCES, "virtualHosts": "virtualhosts", "ruleSets": "rulesets", "ruleSetGroups": "rulesets",
    "pingFederateRuntime": "pingfederate/runtime", "oidcProvider": "oidc/provider",
    "replicaAdmins": "adminConfig/replicaAdmins"})

# Documented: the product's default ports and its heartbeat
ADMIN_PORT, CLUSTER_PORT, ENGINE_PORT, AGENT_PORT, SIDEBAND_PORT = 9000, 9090, 3000, 3030, 3020
HEARTBEAT = "/pa/heartbeat.ping"
# never requested: they need Administrator, or generate key material when read
NEVER_READ = ("config/", "backup", "agents/{id}/config", "engines/{id}/config")


def collection(path):
    """The Collection at a path, or None."""
    return next((c for c in COLLECTIONS if c.path == path), None)

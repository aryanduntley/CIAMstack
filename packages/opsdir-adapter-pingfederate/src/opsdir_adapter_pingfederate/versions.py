"""PingFederate versions: which one an environment runs (what its renders follow), and what changes between releases
(contract.VersionChange; milestone 86, from the vendor's release notes, research 2403): what the record holds that each
change touches, so the planner names it when a move upgrades PingFederate. Pure."""
from opsdir.core.contract import VersionChange
from opsdir.core.directory import children, one, rdn_value
from opsdir.core.jsondata import held_json
from opsdir.core.versions import holds
from opsdir.domains.compute.workloads import role_versions
from .naming import DATA_STORES, SERVER_ROLES
from .schema import HOLDERS

PINGS_OWN = ("com.pingidentity.", "org.sourceid.")      # the packages of PingFederate's own plugin classes


def pingfederate_version(m):
    """(the PingFederate version environment m runs, the first by server or workload name, or None; the other
    versions it runs). Its servers' and, on Kubernetes, its workload bindings' (compute.role_versions)."""
    versions = tuple(dict.fromkeys(v for _, v in role_versions(m, SERVER_ROLES)))
    return (versions[0], versions[1:]) if versions else (None, ())


def runs_in(m, versions):
    """Whether the PingFederate version environment m runs (pingfederate_version; none recorded: the newest release)
    is in a PEP 440 range: what a render for some versions only (13.1's client authentication) asks."""
    version, _ = pingfederate_version(m)
    return holds(versions, (version,) if version else ())


def jdbc_stores(d, m, role):
    """The record's JDBC data stores (the Admin API validates their driver and URL from 13.1.3)."""
    return tuple(one(s, "cn") for s in children(d, DATA_STORES, "pingfedDataStore")
                 if (one(s, "pingfedStoreType") or "").upper() == "JDBC") if role in SERVER_ROLES else ()


def _pairs(value):
    """Every (key, value) a JSON value holds, at any depth."""
    if isinstance(value, dict):
        return tuple(p for k, v in value.items() for p in ((k, v), *_pairs(v)))
    return tuple(p for v in value for p in _pairs(v)) if isinstance(value, list) else ()


def _settings(e):
    """Every (key, value) of an object's held Admin API settings (its policy tree too)."""
    return (*_pairs(held_json(e, "pingfedConfig")), *_pairs(held_json(e, "pingfedPolicyTree")))


def touching(test):
    """A VersionChange.touches naming the objects holding Admin API settings (HOLDERS) that test(entry, settings
    pairs) picks: for PingFederate's server roles, () for others."""
    def touches(d, m, role):
        return tuple(dict.fromkeys(rdn_value(e) for e in d.entries.values()
                                   if any(c in e.classes for c in HOLDERS) and test(e, _settings(e)))) \
            if role in SERVER_ROLES else ()
    return touches


def has_setting(key, test=bool):
    """A touching test: the settings hold key with a value test passes (non-empty by default)."""
    return lambda e, kv: any(k == key and test(v) for k, v in kv)


def outside_plugins(e, kv):
    """A touching test: a plugin instance of a class outside PingFederate's own packages (custom, third-party, or one
    of Ping's separately installed integration kits); one whose class the export didn't name ('unknown') isn't."""
    kind = one(e, "pingfedPluginType") or "unknown"
    return "pingfedPlugin" in e.classes and kind != "unknown" and not kind.startswith(PINGS_OWN)


VERSION_CHANGES = (
    # from the vendor's release notes (research 2403, 2957), oldest first; a change to what settings PingFederate
    # holds mean names the objects holding them, for the planner's upgrade check and the renders' problems
    VersionChange(">=12.0", "conditions comparing with 'multi-value contains DN' ignore letter case",
                  "settings using that condition", "action", "Check the rules that told DNs apart by letter case only.",
                  touching(lambda e, kv: any(v == "MULTIVALUE_CONTAINS_DN" for _, v in kv))),
    VersionChange(">=12.1", "a request naming a resource (resource indicators) fails unless an access token manager "
                  "lists it in its Resource URIs", "access token managers", "action", "List the resources clients ask "
                  "for in the token managers' Resource URIs (selectionSettings.resourceUris).",
                  touching(lambda e, kv: one(e, "pingfedPluginKind") == "access-token-manager"
                           and not has_setting("resourceUris")(e, kv))),
    VersionChange(">=12.1", "a refresh grant is no longer revoked when an access token mapping's issuance criteria "
                  "fail (the token is still refused)", "access token mappings with issuance criteria", "action",
                  "Decide whether keeping the grant meets the revocation the criteria stood for.",
                  touching(lambda e, kv: one(e, "pingfedResourceType") == "/oauth/accessTokenMappings"
                           and has_setting("issuanceCriteria",
                                           lambda v: isinstance(v, dict) and any(v.values()))(e, kv))),
    VersionChange(">=12.2", "the cluster's JGroups thread pool is set in run.properties "
                  "(pf.cluster.thread.pool.max.threads)", "clustered nodes", "info", "Nothing to carry over: the "
                  "render writes run.properties for the target's version; tune the pool there if needed."),
    VersionChange(">=12.2", "provisioning's Flag Comparison Value is compared without letter case",
                  "SP connections provisioning users", "action",
                  "Check the flags whose letter case decided who is provisioned.",
                  touching(has_setting("flagComparisonValue"))),
    VersionChange(">=12.3", "runtime-request.log and admin-request.log replace request.log", "log collection",
                  "info", "The log sources follow the target's version; move outside log readers too."),
    VersionChange(">=12.3", "the Admin API spec no longer has tokenEndpointAttributeContract.inherited (Ping's "
                  "go-client spec from 12.3.0.3); whether PingFederate still takes it isn't documented",
                  "access token managers holding it", "action", "The spec check names each body carrying it; where it "
                  "is true the contract is the parent's: drop the contract from the held settings to inherit it.",
                  touching(has_setting("tokenEndpointAttributeContract",
                                 lambda v: isinstance(v, dict) and "inherited" in v))),
    VersionChange(">=12.3", "a persistent grant past its idle timeout is no longer used while its lifetime lasts",
                  "settings with a grant idle timeout", "action", "Check what relied on reusing idle grants; set the "
                  "idle timeout to the reauthentication wanted.", touching(has_setting("persistentGrantIdleTimeout"))),
    VersionChange(">=13.0", "the Admin API's request schemas change with the release", "every Admin API request the "
                  "render writes", "info", "The render checks each request against the spec of the target's "
                  "version; requests it rejects are named before the cutover."),
    VersionChange(">=13.0", "plugins depending on Jersey 1 stop PingFederate from working",
                  "plugin instances of classes outside PingFederate's own packages", "action", "Check that each "
                  "plugin's (and integration kit's) version supports 13.0 before the upgrade.",
                  touching(outside_plugins)),
    VersionChange(">=13.0", "an OIDC IdP connection expecting a JARM response fails on a plain one",
                  "IdP connections expecting JARM", "action",
                  "Check that each partner returns the secured response its connection expects.",
                  touching(has_setting("jwtSecuredAuthorizationResponseModeType",
                                       lambda v: v not in (None, "DISABLED")))),
    VersionChange(">=13.1", "a pushed authorization request's request_uri can be used again until the PAR Reference "
                  "Timeout expires (when no consent details are shown)", "the authorization server's settings",
                  "action", "Review the PAR Reference Timeout and consent settings against that window.",
                  touching(lambda e, kv: "pingfedSettings" in e.classes and rdn_value(e) == "oauth-auth-server"
                           and not has_setting("parStatus", lambda v: v == "DISABLED")(e, kv))),
    VersionChange(">=13.1", "the aud claim of private_key_jwt client authentication is handled differently",
                  "OAuth clients authenticating with private_key_jwt", "action", "Test each client's assertion "
                  "audience (issuer, base URL, token endpoint base URL) against the target before the cutover.",
                  touching(lambda e, kv: "pingfedHeldSettings" in e.classes
                           and any(v == "PRIVATE_KEY_JWT" for _, v in kv))),
    VersionChange(">=13.1", "custom and third-party plugins must be Jakarta-compatible versions",
                  "plugin instances of classes outside PingFederate's own packages", "action", "Install "
                  "13.1-compatible versions of these plugins (and integration kits) before the target starts.",
                  touching(outside_plugins)),
    VersionChange(">=13.1.2", "an IdP connection handling failures locally sends its errors to the authentication "
                  "policy's Fail branch, not an error page", "IdP connections handling failures locally", "action",
                  "Review the Fail branch of the policies using them: it now receives these failures.",
                  touching(has_setting("handleFailuresLocally", lambda v: v is True))),
    VersionChange(">=13.1.3", "the Admin API validates JDBC data stores' driver class and URL", "JDBC data stores",
                  "action", "Check each store's driver and URL against the drivers 13.1.3 allows before the "
                  "cutover: the Admin API rejects the others.", jdbc_stores),
)

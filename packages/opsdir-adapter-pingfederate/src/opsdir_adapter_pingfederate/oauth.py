"""PingFederate as an OAuth authorization server: OIDC policies, the authorization server's settings and what an OAuth
client is issued tokens by, read from the Admin API into the record and rendered back (environment-neutral). Pure.

  /oauth/openIdConnect/policies    -> pingfedOidcPolicy (cn: its id): the ID token it issues (lifetime, claims, scope
                                      mappings), linked to the access token manager it names
  /oauth/authServerSettings        -> pingfedSettings cn=oauth-auth-server: scopes (common and exclusive, listed in
                                      pingfedScope), scope groups, grant and code lifetimes, persistent grant contract
  an OAuth client's                -> its integration (federation domain) gains auxiliary class pingfedClient, linked
    defaultAccessTokenManagerRef,     to the token manager and OIDC policy (pingfedUses); rendered back as PingFederate
    oidcPolicy.policyGroup            writes them

Access token managers are plugin instances (opsdir_adapter_pingfederate.plugins); the key pairs a JWT token manager
signs with are certificates carrying PingFederate's key pair id (pingfedKeyPairId).
"""

from opsdir.core.directory import children, get, make_entry, merged_attrs, one, rdn_value, values
from opsdir.core.jsondata import canonical, held_json
from opsdir.core.naming import rdn_safe
from .naming import AUTH_SERVER, OIDC_POLICIES, named
from .objects import NOT_EXPORTED, links, why_unresolved
from .withheld import filled, withheld_settings

OWNED = ("cn", "pingfedUses", "pingfedConfig")
SETTINGS_OWNED = ("cn", "pingfedScope", "pingfedConfig", "pingfedWithheld")


def _id(ref):
    return ref.get("id") if isinstance(ref, dict) else None


def oidc_policy_refs(policy):
    """(kind, id) of the access token manager an OIDC policy names."""
    atm = _id(policy.get("accessTokenManagerRef"))
    return (("access-token-manager", atm),) if atm else ()


def client_refs(client):
    """(kind, id) of the access token manager and OIDC policy an OAuth client is issued tokens by."""
    atm = _id(client.get("defaultAccessTokenManagerRef"))
    oidc = _id((client.get("oidcPolicy") or {}).get("policyGroup"))
    return (*((("access-token-manager", atm),) if atm else ()), *((("oidc-policy", oidc),) if oidc else ()))


def scopes(settings):
    """The scopes an authorization server defines: common, then exclusive, each once."""
    return tuple(dict.fromkeys(s.get("name") for key in ("scopes", "exclusiveScopes")
                               for s in settings.get(key) or () if isinstance(s, dict) and s.get("name")))


# ------------------------------------------------------------------ import
def oidc_policy_entry(d, item, exported):
    """(DN, entry, notices) for one OIDC policy, or (None, None, notices) when its id can't name one."""
    pid = item.get("id")
    label = f"OIDC policy {item.get('name') or pid}"
    if not rdn_safe(pid or ""):
        return None, None, (f"{label}: its id can't name an entry, not imported",)
    uses, lost = links(d, oidc_policy_refs(item), exported)
    dn = named(OIDC_POLICIES, pid)
    config = {k: v for k, v in item.items() if k != "id"}
    owned = {"cn": (pid,), "pingfedUses": uses, "pingfedConfig": (canonical(config),)}
    return dn, make_entry(dn, ("top", "ciamObject", "pingfedOidcPolicy"), merged_attrs(get(d, dn), owned, OWNED)), \
        tuple(f"{label}: names {why_unresolved(d, k, i, NOT_EXPORTED)}" for k, i in lost)


def auth_server_entry(d, settings, patterns):
    """(DN, entry): the authorization server's settings, its scopes listed."""
    config, held = withheld_settings(settings, patterns)
    owned = {"cn": ("oauth-auth-server",), "pingfedScope": scopes(settings), "pingfedConfig": (canonical(config),),
             "pingfedWithheld": held}
    return AUTH_SERVER, make_entry(AUTH_SERVER, ("top", "ciamObject", "pingfedSettings"),
                                   merged_attrs(get(d, AUTH_SERVER), owned, SETTINGS_OWNED))


def oauth_groups(d, found, patterns, exported):
    """(groups, notices) for the export's OIDC policies and authorization server settings."""
    parts = [oidc_policy_entry(d, p, exported) for p in found.get("oidc-policy", ())]
    server = [auth_server_entry(d, s, patterns) for s in found.get("auth-server", ())[:1]]
    return ((*((dn, (e,)) for dn, e, _ in parts if dn), *((dn, (e,)) for dn, e in server)),
            tuple(n for _, _, ns in parts for n in ns))


def client_links(d, client, exported):
    """(DNs of the token manager and OIDC policy an OAuth client names, notices for those neither the export nor the
    record has)."""
    uses, lost = links(d, client_refs(client), exported)
    return uses, tuple(f"client {client.get('clientId')}: names {why_unresolved(d, k, i, NOT_EXPORTED)}"
                       for k, i in lost)


# ------------------------------------------------------------------ render
def client_view(d, i):
    """What an OAuth client's integration names PingFederate's way: defaultAccessTokenManagerRef and the OIDC policy."""
    uses = [get(d, dn) for dn in values(i, "pingfedUses")]
    atm = next((rdn_value(e) for e in uses if e is not None and one(e, "pingfedPluginKind") == "access-token-manager"),
               None)
    oidc = next((rdn_value(e) for e in uses if e is not None and "pingfedOidcPolicy" in e.classes), None)
    return {**({"defaultAccessTokenManagerRef": {"id": atm}} if atm else {}),
            **({"oidcPolicy": {"policyGroup": {"id": oidc}}} if oidc else {})}


def oidc_policy_body(p):
    """An OIDC policy as the Admin API takes it (POST /oauth/openIdConnect/policies)."""
    return {"id": rdn_value(p), **held_json(p, "pingfedConfig")}


def auth_server_body(m):
    """The authorization server's settings as the Admin API takes them (PUT /oauth/authServerSettings), withheld values
    from their credential role in environment m; None when the record has none."""
    server = get(m.d, AUTH_SERVER)
    return filled(m, server, held_json(server, "pingfedConfig")) if server is not None else None

"""The federation domain's integrations as PingFederate's Admin API takes them: SAML SP connections, OAuth clients and
SAML IdP connections. Pure.

An integration read from PingFederate holds its own settings as the Admin API writes them (auxiliary class
pingfedHeldSettings, secrets withheld: opsdir_adapter_pingfederate.withheld). It is rendered from them, for each
environment (withheld values from its credential role), with every path the record's standard facts own deleted and
put back from the record, so an edit in the record wins and a removed fact leaves no trace:

  SP connection   entityId; the default assertion consumer endpoint's URL and binding (others kept); the attribute
                  contract's extended attributes and their fulfillment: the record's claims, each keeping how
                  PingFederate fulfils it, a new one from the user directory, a removed one gone from every mapping
  OAuth client    clientId, redirectUris, grantTypes (PingFederate's list kept when it names the same grants),
                  requireProofKeyForCodeExchange, clientAuth.type, the scope restriction, the token manager and OIDC
                  policy it is issued tokens by
  IdP connection  its id (pingfedConnectionId), entityId, the JIT user repository's base DN

An integration the record made itself holds nothing: it gets the record's facts and only PingFederate's harmless
defaults (an assertion lifetime of 5 minutes either side); what the version's spec still requires (an IdP connection's
identity mapping and JIT repository, say) is named by the render's problems, never invented.
"""
from types import MappingProxyType

from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.jsondata import held_json
from opsdir.domains.directory.user_schema import attribute_records
from opsdir.domains.federation.services import claims
from .oauth import client_view
from .withheld import filled

USER_DIRECTORY = MappingProxyType({"type": "LDAP_DATA_STORE", "id": "ciam-user-directory"})
# standard value -> PingFederate Admin API name
GRANT_TYPES = MappingProxyType({"authorization_code": "AUTHORIZATION_CODE", "client_credentials": "CLIENT_CREDENTIALS",
                                "refresh_token": "REFRESH_TOKEN",
                                "urn:ietf:params:oauth:grant-type:device_code": "DEVICE_CODE",
                                "urn:ietf:params:oauth:grant-type:token-exchange": "TOKEN_EXCHANGE",
                                "urn:ietf:params:oauth:grant-type:jwt-bearer": "EXTENSION",
                                "urn:ietf:params:oauth:grant-type:saml2-bearer": "EXTENSION"})
# PingFederate grant names standing for several standard grants: what the record can't say on its own
AMBIGUOUS_GRANTS = MappingProxyType({pf: tuple(std for std, v in GRANT_TYPES.items() if v == pf)
                                     for pf in set(GRANT_TYPES.values())
                                     if sum(v == pf for v in GRANT_TYPES.values()) > 1})
CLIENT_AUTH = MappingProxyType({"none": "NONE", "client_secret_basic": "SECRET", "client_secret_post": "SECRET",
                                "client_secret_jwt": "SECRET", "private_key_jwt": "PRIVATE_KEY_JWT",
                                "tls_client_auth": "CLIENT_CERT", "self_signed_tls_client_auth": "CLIENT_CERT"})
BINDINGS = MappingProxyType({"HTTP-POST": "POST", "HTTP-Redirect": "REDIRECT", "HTTP-Artifact": "ARTIFACT",
                             "SOAP": "SOAP"})
# protocol type -> the Admin API collection of its PingFederate object
COLLECTIONS = MappingProxyType({"saml2-sp": "/idp/spConnections", "oidc-client": "/oauth/clients",
                                "saml2-idp": "/sp/idpConnections"})


def _held(m, i):
    """The PingFederate settings an integration holds, for environment m ({} when it holds none)."""
    return filled(m, i, held_json(i, "pingfedConfig")) if "pingfedHeldSettings" in i.classes else {}


def _owned(held, key, value, given=True):
    """{key: value} when the record gives the value (or there is nothing held, or the held settings have the key): an
    owned field the held settings leave out and the record says nothing of stays out, so a render imports back
    unchanged."""
    return {key: value} if given or not held or key in held else {}


def _ordered(held_names, names):
    """The record's names in the held order, the record's new ones after."""
    return [n for n in held_names if n in names] + [n for n in names if n not in held_names]


def _unrecordable(d, extended, fulfillment):
    """The held claims the record can't hold (fulfilled from a value no user-schema record names): PingFederate's
    alone, kept as they are."""
    attrs = attribute_records(d)
    return {n for n in extended if (((fulfillment.get(n) or {}).get("value")) or "").lower() not in attrs}


def _fulfilled(fulfillment, names, gone, first, claimed):
    """A mapping's attribute fulfillment: the claims removed from the record gone, and, in the first mapping, each of
    the record's claims fulfilled as PingFederate held it or from the user directory."""
    kept = {k: v for k, v in fulfillment.items() if k not in gone}
    defaults = {n: {"source": dict(USER_DIRECTORY), "value": attr} for n, attr, _ in claimed}
    subject = {} if fulfillment else {"SAML_SUBJECT": {"source": dict(USER_DIRECTORY), "value": "uid"}}
    return {**subject, **kept, **({n: kept.get(n) or defaults[n] for n in names if n in kept or n in defaults}
                                  if first else {})}


SP_DEFAULTS = MappingProxyType({"protocol": "SAML20", "enabledProfiles": ("SP_INITIATED_SSO",),
                                "assertionLifetime": MappingProxyType({"minutesBefore": 5, "minutesAfter": 5})})


def _plain(value):
    """A default as JSON: mappings as dicts, tuples as lists."""
    if isinstance(value, (dict, MappingProxyType)):
        return {k: _plain(v) for k, v in value.items()}
    return [_plain(v) for v in value] if isinstance(value, (list, tuple)) else value


def sp_connection(m, i):
    """A SAML service provider integration as an SP connection (PUT /idp/spConnections/<id>)."""
    d, held = m.d, _held(m, i)
    owners = tuple(rdn_value(get(d, o)) for o in values(i, "ciamOwner"))
    claimed = claims(d, i)
    browser = held.get("spBrowserSso") or _plain(SP_DEFAULTS)
    endpoints = list(browser.get("ssoServiceEndpoints") or ())
    default = next((e for e in endpoints if e.get("isDefault")), endpoints[0] if endpoints else None)
    acs = {**(default or {}), "binding": BINDINGS[one(i, "ciamSamlBinding", "HTTP-POST")], "url": one(i, "ciamAcsUrl"),
           "isDefault": True} if one(i, "ciamAcsUrl") else default
    contract = browser.get("attributeContract") or {"coreAttributes": [{"name": "SAML_SUBJECT"}]}
    extended = {a.get("name"): a for a in contract.get("extendedAttributes") or ()}
    mappings = list(browser.get("adapterMappings") or ({},))
    unrecordable = _unrecordable(d, extended, mappings[0].get("attributeContractFulfillment") or {})
    names = _ordered(list(extended), [n for n, _, _ in claimed] + [n for n in extended if n in unrecordable])
    gone = {n for n in extended if n not in names}
    return {
        **held, "id": held.get("id") or rdn_value(i), **({} if held else {"name": rdn_value(i), "active": True}),
        "entityId": one(i, "ciamEntityId"),
        **({} if held or not owners else {"contactInfo": {"company": ", ".join(owners)}}),
        "spBrowserSso": {
            **browser, "ssoServiceEndpoints": [*([acs] if acs else []), *(e for e in endpoints if e is not default)],
            "attributeContract": {**contract, "extendedAttributes": [extended.get(n) or {"name": n} for n in names]},
            "adapterMappings": [{**mp, "attributeContractFulfillment": _fulfilled(
                mp.get("attributeContractFulfillment") or {}, names, gone, n == 0, claimed)}
                for n, mp in enumerate(mappings)]}}


def _scope_restriction(i, held):
    scopes = list(values(i, "ciamScope"))
    if scopes:
        return {"restrictScopes": True, "restrictedScopes": scopes}
    return {"restrictScopes": False, "restrictedScopes": []} if held.get("restrictScopes") else {}


def oauth_client(m, i):
    """An OIDC client integration as an OAuth client (PUT /oauth/clients/<client id>), with the token manager and
    OIDC policy it is issued tokens by."""
    held = _held(m, i)
    recorded = values(i, "ciamGrantType")
    unrecordable = [g for g in held.get("grantTypes") or () if g in AMBIGUOUS_GRANTS
                    and not any(std in recorded for std in AMBIGUOUS_GRANTS[g])]
    grants = list(dict.fromkeys((*(GRANT_TYPES[g] for g in recorded), *unrecordable)))
    kept = held.get("grantTypes")
    auth = one(i, "ciamTokenAuthMethod")
    client_auth = {**(held.get("clientAuth") or {}), **({"type": CLIENT_AUTH[auth]} if auth else {})}
    pkce = one(i, "ciamPkceRequired") == "TRUE"
    return {
        **held, "clientId": one(i, "ciamClientId"),
        **({} if held else {"name": rdn_value(i), "enabled": True}),
        **_owned(held, "redirectUris", list(values(i, "ciamRedirectUri")), bool(values(i, "ciamRedirectUri"))),
        "grantTypes": kept if isinstance(kept, list) and set(kept) == set(grants) else grants,
        **_owned(held, "requireProofKeyForCodeExchange", pkce, pkce),
        **({"clientAuth": client_auth} if client_auth else {}), **_scope_restriction(i, held), **client_view(m.d, i)}


def idp_connection(m, i):
    """A partner identity provider integration as an IdP connection (PUT /sp/idpConnections/<id>), under the id
    PingFederate knows it by."""
    held = _held(m, i)
    browser = held.get("idpBrowserSso") if held else {"protocol": "SAML20"}
    base = one(i, "ciamJitBaseDn")
    jit = (browser or {}).get("jitProvisioning") or {}
    repository = jit.get("userRepository") or {"type": "LDAP"}
    jit_part = {"jitProvisioning": {**jit, "userRepository": {**repository, "baseDn": base}}} if base else {}
    return {
        **held, "id": one(i, "pingfedConnectionId") or held.get("id") or rdn_value(i),
        **({} if held else {"name": rdn_value(i), "active": True}), "entityId": one(i, "ciamEntityId"),
        **({"idpBrowserSso": {**(browser or {}), **jit_part}} if browser is not None or jit_part else {})}


BUILDERS = MappingProxyType({"saml2-sp": sp_connection, "oidc-client": oauth_client, "saml2-idp": idp_connection})


def integration_body(m, i):
    """(collection, id, body) of an integration PingFederate serves, for environment m (its protocol type's)."""
    kind = one(i, "ciamProtocolType")
    body = BUILDERS[kind](m, i)
    return COLLECTIONS[kind], body.get("id") or body.get("clientId"), body

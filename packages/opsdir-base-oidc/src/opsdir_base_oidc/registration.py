"""OAuth 2.0 / OpenID Connect client metadata (RFC 7591, OpenID Connect Dynamic Client Registration 1.0 section 2)
for a recorded OIDC client: the standard form of the contract an application has with the platform."""
from opsdir.core.directory import one, rdn_value, values
from opsdir.domains.federation.schema import GRANT_TYPES
from opsdir.domains.federation.services import in_order

AUTHORIZATION_CODE = "authorization_code"


def response_types(grants):
    """The response types a client with these grant types uses (the code flow only; no implicit flow)."""
    return ["code"] if AUTHORIZATION_CODE in grants else []


def client_metadata(i):
    """RFC 7591 client metadata of an oidc-client integration; fields the record doesn't hold are left out, except
    response_types (an empty list says the client uses no redirect flow; left out it would default to code)."""
    grants = in_order(GRANT_TYPES, values(i, "ciamGrantType"))
    fields = (("client_id", one(i, "ciamClientId")), ("client_name", rdn_value(i)),
              ("redirect_uris", list(values(i, "ciamRedirectUri"))),
              ("post_logout_redirect_uris", list(values(i, "ciamPostLogoutRedirectUri"))),
              ("grant_types", list(grants)), ("response_types", response_types(grants)),
              ("token_endpoint_auth_method", one(i, "ciamTokenAuthMethod")),
              ("scope", " ".join(values(i, "ciamScope")) or None))
    return {k: v for k, v in fields if v not in (None, []) or k == "response_types"}

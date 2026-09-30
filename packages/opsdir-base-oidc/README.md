# opsdir-base-oidc

The OAuth 2.0 / OpenID Connect base: client registration metadata and the provider's discovery document, rendered from the federation domain. A library, not an adapter: federation product adapters (PingFederate, PingAM) build on it and register themselves.

Environment-neutral files, via `render.oidc_files(d, services, endpoints)`:

| File | Holds |
|---|---|
| `oidc/clients/<integration>.json` | Each OIDC client's metadata (RFC 7591): client ID and name, redirect and post-logout redirect URIs, grant and response types, token endpoint auth method, scope. |
| `oidc/discovery/<service>.json` | Each identity service's provider metadata (OpenID Connect Discovery 1.0), the document it serves at `/.well-known/openid-configuration`: its issuer, the product's endpoints under the service's base URL, and what it supports, derived from the record (the service's scopes and signing algorithms, RS256 always included; the grant types, auth methods, claims and PKCE its clients use). |

The product supplies `OidcEndpoints` (paths; `None` where it has none) and which identity services it serves. Values use the protocols' own names (the federation domain's standard vocabulary); a product adapter maps them to its API's names.

In this repository: `scripts/dev-install.sh`.

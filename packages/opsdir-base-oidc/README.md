# opsdir-base-oidc

The OAuth 2.0 / OpenID Connect base: client registration metadata and the provider's discovery document, rendered from the federation domain. A library, not an adapter: federation product adapters (`opsdir-adapter-pingfederate`, `opsdir-adapter-pingam`) build on it and register themselves.

**Applies to** whatever the product adapter using it applies to: the product supplies which identity services it serves and its endpoint paths (`OidcEndpoints`: authorization, token, userinfo, JWKS, end session; `None` where it has none).

**Depends on** `opsdir` only.

## What it renders

Environment-neutral files, via `render.oidc_files(d, services, endpoints)`:

| From the record | Rendered as |
|---|---|
| Each OIDC client (`oidc-client` integration) the given services serve: client ID, name, redirect and post-logout redirect URIs, grant types, token endpoint auth method, DPoP binding, scopes | `oidc/clients/<integration>.json`: RFC 7591 client metadata (`registration.client_metadata`): `client_id`, `client_name`, `redirect_uris`, `post_logout_redirect_uris`, `grant_types` (in the standard vocabulary's order), `response_types` (`["code"]` with the authorization code grant, else `[]`: no implicit flow; always written, since left out it would default to `code`), `token_endpoint_auth_method`, `dpop_bound_access_tokens` (when `ciamDpopBound` is TRUE), `scope` (space-joined); other fields the record doesn't hold are left out |
| Each given identity service with an issuer (`ciamOidcIssuer`), and the clients it serves | `oidc/discovery/<service>.json`: OpenID Provider metadata (OpenID Connect Discovery 1.0), the document it serves at `/.well-known/openid-configuration`: `issuer`, the product's endpoints under the service's base URL, and what it supports, derived from the record: `scopes_supported` (the service's and its clients'), `response_types_supported`, `grant_types_supported`, `subject_types_supported` (`public`), `id_token_signing_alg_values_supported` (the service's `ciamSigningAlg`, RS256 always included), `token_endpoint_auth_methods_supported`, `claims_supported` (its clients' claims) and `code_challenge_methods_supported` (`S256` when a client requires PKCE); empty optional lists are left out |

Values use the protocols' own names (the federation domain's standard vocabulary); a product adapter maps them to its API's names. `render.FORMATS` declares their format (`oidc/*.json`, JSON) for the products' `formats`.

```python
from opsdir_base_oidc.discovery import OidcEndpoints, discovery_document
from opsdir_base_oidc.registration import client_metadata, response_types
from opsdir_base_oidc.render import oidc_files, FORMATS
```

Not rendered: JWKS (key material is never held), signed or encrypted metadata, a client's secret.

## What it reads back

Nothing: no importer. The product adapters read their products' own clients into the same federation domain.

## Schema, vocabulary, roles and checks

None of its own: it reads the core federation domain's integrations and identity services and their vocabularies (grant types, auth methods, signing algorithms). No required roles, planner checks, reference schemes or secret patterns.

## Known limits

- **Only what the record holds** is published: optional discovery fields (ACR values, request objects, PAR, mTLS aliases, ...) aren't rendered.
- **Code flow only**: response types come from the authorization code grant; implicit and hybrid flows aren't rendered.
- **Not served by opsdir**: the documents describe what the product should publish; checking them against a live provider is part of the testing plan (milestone 7.2).

## Tests

`tests/test_base_oidc.py`: client metadata as RFC 7591 in the standard's order, discovery deriving what the provider supports from the record, only services with an issuer getting a discovery document. The products' renders are exercised by their own tests and the showcase's golden outputs.

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-base-oidc/tests
```

In this repository: `opsdir/scripts/dev-install.sh`.

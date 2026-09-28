# opsdir-adapter-pingfederate

opsdir adapter for PingFederate: SP connections, OIDC clients and IdP connections as Admin API shaped JSON, and, on `opsdir-base-saml` and `opsdir-base-oidc`, the standard documents at PingFederate's endpoint paths.

Applies to environments with servers whose `ciamProductVersion` is PingFederate. Environment-neutral outputs:

- `pingfederate/sp-connections.json`, `oidc-clients.json`, `idp-connections.json`: the federation domain's integrations, standard values mapped to PingFederate's names (grant types, client authentication, bindings). An illustrative subset of the Admin API, not yet validated against a live `/pf-admin-api/v1`.
- `saml/sp/`, `saml/partner-idp/`: every SAML partner's metadata as recorded; `oidc/clients/`: every OIDC client's registration metadata.
- `saml/idp/<service>.xml`, `oidc/discovery/<service>.json`: the IdP metadata and OpenID provider metadata of the identity services its servers serve (`ciamTargetRole` `pf-engine` or `pf-admin`), with PingFederate's default endpoint paths (`/idp/SSO.saml2`, `/as/authorization.oauth2`, `/as/token.oauth2`, `/pf/JWKS`, ...).

Defines the server roles `pf-engine` and `pf-admin`. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingfederate`); nothing in the opsdir core changes. In this repository: `scripts/dev-install.sh`.

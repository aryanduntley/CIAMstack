# opsdir-base-saml

The SAML 2.0 base: standard metadata (OASIS SAML 2.0 metadata) rendered from the federation domain. A library, not an adapter: federation product adapters (PingFederate, PingAM) build on it and register themselves.

Environment-neutral files, via `render.saml_files(d, services, endpoints)`:

| File | Holds |
|---|---|
| `saml/sp/<integration>.xml` | Each SAML service provider we federate with, as the record describes it: entity ID, ACS URL and binding, NameID formats, the attributes it receives (its claim names). |
| `saml/partner-idp/<integration>.xml` | Each partner identity provider, as the record describes it: entity ID, SSO URL, NameID formats. |
| `saml/idp/<service>.xml` | The platform's own identity provider (`ciamIdentityService` with an entity ID), with SSO and SLO endpoints at the product's paths under the service's base URL. |

The first two are the partners' contracts in the standard's form, importable into any SAML product; the last is what partners are given. The product supplies `SamlEndpoints` (bindings and paths) and which identity services it serves. `KeyDescriptor` needs the certificate itself, which the record never holds, so the certificates the record links are listed by name, key role and SHA-256 fingerprint.

`metadata.py` builds entity descriptors from plain values; `xmltext.py` is a small, pure XML writer (immutable elements, deterministic text).

In this repository: `scripts/dev-install.sh`.

# opsdir-base-saml

The SAML 2.0 base: standard metadata (OASIS SAML 2.0 metadata) rendered from the federation domain. A library, not an adapter: federation product adapters (`opsdir-adapter-pingfederate`, `opsdir-adapter-pingam`) build on it and register themselves.

**Applies to** whatever the product adapter using it applies to: the product supplies which identity services it serves and its endpoint paths (`SamlEndpoints`: `((binding, path), ...)` for SSO and SLO); the base renders those services' partners and the services themselves.

**Depends on** `opsdir` only (no XML library: `xmltext.py` is its own writer).

## What it renders

Environment-neutral files, via `render.saml_files(d, services, endpoints)`:

| From the record | Rendered as |
|---|---|
| Each SAML service provider (`saml2-sp` integration) the given services serve: entity ID, ACS URL and binding (`ciamSamlBinding`, default `HTTP-POST`), NameID formats, the claims it receives, the certificates it uses | `saml/sp/<integration>.xml`: an `SPSSODescriptor` with one default `AssertionConsumerService` and, when it receives claims, an `AttributeConsumingService` (service name: the integration's name) listing them as `RequestedAttribute` (basic name format) |
| Each partner identity provider (`saml2-idp` integration): entity ID, SSO URL (`ciamSsoUrl`) and binding (default `HTTP-Redirect`), NameID formats, certificates | `saml/partner-idp/<integration>.xml`: an `IDPSSODescriptor` (no `SingleSignOnService` without an SSO URL) |
| Each given identity service with an entity ID (`ciamEntityId`): the product's SSO and SLO paths under its base URL, NameID formats, certificates | `saml/idp/<service>.xml`: an `IDPSSODescriptor`, `WantAuthnRequestsSigned="false"`, SLO then NameID formats then SSO endpoints |

The first two are the partners' contracts in the standard's form, importable into any SAML product; the last is what partners are given. Bindings are the standard's (`HTTP-POST`, `HTTP-Redirect`, `HTTP-Artifact`, `SOAP` as `urn:oasis:names:tc:SAML:2.0:bindings:<binding>`); NameID formats `unspecified`, `emailAddress`, `persistent`, `transient`. `KeyDescriptor` needs the certificate itself, which the record never holds, so the certificates the record links (`ciamUsesCertificate`) are listed in comments by name, key role and SHA-256 fingerprint, for whoever adds them. The XML is byte-stable (`xmltext.py`: immutable elements, deterministic attribute order, two-space indentation, escaped text). `render.FORMATS` declares their format (`saml/*.xml`, XML) for the products' `formats`.

`metadata.py` builds entity descriptors from plain values (`sp_descriptor`, `idp_descriptor`, `binding_urn`):

```python
from opsdir_base_saml.render import SamlEndpoints, saml_files, FORMATS
from opsdir_base_saml.metadata import sp_descriptor, idp_descriptor
from opsdir_base_saml.xmltext import element, document
```

Not rendered: signed metadata, `KeyDescriptor` (the certificates), organization and contact elements, an SP's own SLO.

## What it reads back

Nothing: no importer. The product adapters read their products' own configuration (PingFederate's connections, AM's entities) into the same federation domain.

## Schema, vocabulary, roles and checks

None of its own: it reads the core federation domain's integrations and identity services. No required roles, planner checks, reference schemes or secret patterns.

## Known limits

- **No certificates in the metadata**: partners need the certificate material added from where it is kept (the record holds facts and references only).
- **One ACS per service provider** (the record's ACS URL and binding).
- **Validated against the schema's element order** in the tests, not against a SAML product importing it (milestone 7.2).

## Tests

`tests/test_base_saml.py`: the writer escaping and deterministic, SP metadata well-formed standard metadata, IdP metadata ordering its elements as the schema does, the record rendering partners and the given services at the product's paths. The products' renders are exercised by their own tests and the showcase's golden outputs.

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-base-saml/tests
```

In this repository: `opsdir/scripts/dev-install.sh`.

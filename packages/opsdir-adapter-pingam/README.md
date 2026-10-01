# opsdir-adapter-pingam

opsdir adapter for PingAM (ForgeRock AM): realms, OAuth2/OIDC clients, SAML, authentication journeys and policy sets, rendered from the record and imported from Amster exports.

- **Realms are identity services.** A realm is one of the platform's identity services with the auxiliary class `pingamRealm` (`pingamRealmPath`: `/`, `/customers`, ...); integrations say which one they are registered with (`ciamServedBy`).
- **Standard where the concept is standard.** OAuth2/OIDC clients and SAML partners are the federation domain's integrations; the standard SAML metadata, client registrations and discovery documents are rendered by `opsdir-base-saml` and `opsdir-base-oidc` at AM's endpoint paths for each realm.
- **AM's own vocabulary here.** Journeys (`pingamJourney`, one `pingamNode` per node: type, display name, settings, outcomes) and policy sets (`pingamPolicySet`, `pingamPolicy`) live under `ou=pingam`, in this package's schema (OID arc `1.3.6.1.4.1.32473.3.1`).
- **Render** (`am/`, environment-neutral): Amster-shaped entities per realm: `global/Realms`, `OAuth2Clients`, `AuthTree` and one file per node, `Applications` and `Policies`. The shapes follow Amster exports but are not yet validated against a live AM.
- **Import**: `opsdir import --change CHG-… pingam /path/to/amster-export` reads clients, journeys and policy sets into the record; every other entity (service settings) is captured as a config file, held setting by setting and rebuilt byte for byte. A realm is imported only when the record has its identity service. Values that may be secret are withheld and named; client secrets are never read.
- **Planner check**: a journey that starts at, or leads to, a node it doesn't have is a blocker.
- **Required roles**: `subnet-am`, `am-service`, `am-admin-password`, `am-keystore`, `am-ds-bind-password`. Server role: `am`. Products: PingAM 7–8, ForgeRock AM 7.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingam`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

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

## Collecting from PingAM (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter pingam --amster-key PATH` runs Amster's `export-config` and imports its export
(`opsdir_adapter_pingam.collect`). The environment declares AM's URL (`ciamCollectionSource`: `ciamImporter:
pingam/amster`, `ciamSourceRef: https://am.example.test/am`); the private key Amster signs in with is your existing key
file, whose public key AM trusts (`authorized_keys`), given when collecting and never stored. Amster runs a script in a
private work directory (connect with the key, `export-config --failOnError` into the directory, exit), and the files
it writes are the export; the directory is removed after. No transport key is configured, so encrypted passwords are
not exported. Needs Amster on the path. Least privilege: Amster's key-based connection signs in as an administrative
user (AM's `amAdmin` session): keep the key on the operator's workstation only, its public key trusted only from the
addresses collection runs from.

## Egress through an explicit proxy

When an environment's egress passes a proxy clients must be told about (a `ciamProxy` with `ciamProxyAddress` that isn't a firewall), PingAM needs its HTTP client's advanced server properties `org.forgerock.openam.httpclienthandler.system.proxy.uri` (`http://<host>:<port>`, which takes precedence over the JVM's proxy) and `org.forgerock.openam.httpclienthandler.system.nonProxyHosts` (comma-separated), and the standard Java proxy properties in its container's JVM options (`JAVA_OPTS`, setenv.sh) for what doesn't use that client. The record holds neither place, so the planner names what to set.


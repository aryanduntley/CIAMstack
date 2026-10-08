# opsdir-adapter-pingidm

opsdir adapter for PingIDM (ForgeRock IDM): managed objects, connectors, sync mappings and schedules, rendered from the record and imported from an IDM project directory.

- **Held as entries** (`ou=pingidm`, this package's schema, OID arc `1.3.6.1.4.1.32473.3.2`): managed objects (`pingidmManagedObject`: schema and settings), connectors (`pingidmConnector`), mappings (`pingidmMapping`: source, target, properties and policies) and schedules (`pingidmSchedule`), in IDM's own JSON, with values that may be secret withheld.
- **Connectors per environment.** A connector names the binding role of the system it reaches (`pingidmTargetRole`, e.g. the directory's `ds-ldaps-service`) and the secret role of its credentials (`pingidmCredentialRole`); each environment renders its provisioner file with its own host and `${secret:<ref-uri>}`. The host is `configurationProperties.host`, or, for a database connector, the hosts of its JDBC `configurationProperties.url` (the record keeps the URL without them, `jdbc:postgresql:///hr`, and their common port as `pingidmPort`; an environment that binds the role several times renders every host, in `ciamHostOrder`). The account a connector binds to the directory as is linked to its consumer record (`pingidmConsumer`).
- **Render**: `pingidm/conf/managed.json`, `sync.json` and `schedule-*.json` (environment-neutral), `provisioner.openicf-*.json` (per environment).
- **Import**: `opsdir import --change CHG-… pingidm PROJECT_DIR` reads `conf/`: the files above become entries (a connector host, or a JDBC URL's hosts, that is a role in the record (a service name, an external system's host) becomes that role; the bind account is matched to a consumer record); every other `conf/` file, and `resolver/*.properties` (boot.properties), is captured as a config file; scripts and UI files are named as code (record them with `opsdir bundle`). Credential roles are never guessed: set them with a change.
- **Planner check**: mappings or reconciliation schedules that name what the deployment doesn't have, and connectors without a credential role or whose roles the target doesn't bind, are blockers; a connector with a fixed host is an action, with a fix (`external-host:connector/<name>`) that records its `host` (or its JDBC URL's hosts, one binding each) as the source's `ciamExternalHost` of a role you give, so the next import names the role.
- **Required roles**: `subnet-idm`, `idm-admin-password`, `idm-keystore`. Server role: `idm`. Products: PingIDM 7–8, ForgeRock IDM 7.

The files follow IDM's `conf/` layout but are not yet validated against a live IDM. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingidm`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## Collecting from PingIDM (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter pingidm` reads the project's configuration over IDM's REST API, read-only,
and imports it like a saved `conf/` directory (`opsdir_adapter_pingidm.collect`): `GET /openidm/config` lists the
objects, `GET /openidm/config/<id>` reads each, saved as `conf/<id>.json` (a factory configuration's instance after a
dash: `provisioner.openicf/ldap` -> `conf/provisioner.openicf-ldap.json`) without the `_id` the API adds. The
environment declares where (`ciamCollectionSource`: `ciamImporter: pingidm/project`, `ciamSourceRef` IDM's URL,
`ciamCredentialRole` and `ciamLoginName` for the account, `ciamCaRole` for the trust anchor); the password is resolved
when collecting and sent as `X-OpenIDM-Username` / `X-OpenIDM-Password`, never stored. `resolver/` properties aren't
served over REST and aren't collected; encrypted values (`$crypto`) stay as IDM holds them and the importer withholds
them. Least privilege: an internal user whose role `access.json` allows `read` on `config/*` only (else
`openidm-admin`).

## Egress through an explicit proxy

When an environment's egress passes a proxy clients must be told about (a `ciamProxy` with `ciamProxyAddress` that isn't a firewall), PingIDM's HTTP client (external REST, the identity provider service) is told to use the JVM's proxy, `openidm.http.client.proxy.useSystem=true` in `resolver/boot.properties`, with the standard Java proxy properties in the JVM options it starts with (`OPENIDM_OPTS`). The JVM's proxy is used, not `openidm.http.client.proxy.uri`, because only it honours the hosts reached directly (`http.nonProxyHosts`), so connectors to the platform's own services stay off the proxy. The importer captures `resolver/*.properties` with the `conf/` files, so the planner compares `boot.properties` with the record and offers a fix (`opsdir fix`) that adds the setting when it is missing; it names the JVM options, which the record can't confirm.


# opsdir-adapter-pingidm

opsdir adapter for PingIDM (ForgeRock IDM): an IDM deployment's managed objects, connectors, sync mappings and schedules, rendered from the record as IDM's `conf/` files (connectors per environment), read back from an IDM project directory, and collected over IDM's REST API.

**Applies to** environments where PingIDM or ForgeRock IDM runs: a server, or a Kubernetes workload's binding, whose `ciamProductVersion` starts with `PingIDM` or `ForgeRock IDM` (`runs_product`). Supported: PingIDM `>=7,<9`, ForgeRock IDM `>=7,<8`. A product adapter: it defines the server role `idm` and declares its roles for the kits that deploy it, which find them by product (`Adapter.roles`: server `idm`, keystore `idm-keystore`).

**Depends on** `opsdir` only. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingidm`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## What it renders

`render.py`. The files follow IDM's `conf/` layout but are not validated against a live IDM.

| From the record (under `ou=pingidm`) | Rendered as |
|---|---|
| Managed objects (`pingidmManagedObject`: schema, settings), in `pingidmPosition` order | `pingidm/conf/managed.json` (environment-neutral) |
| Sync mappings (`pingidmMapping`: source, target, settings), in order | `pingidm/conf/sync.json` (environment-neutral) |
| Schedules (`pingidmSchedule`: enabled, settings) | `pingidm/conf/schedule-<name>.json` (environment-neutral) |
| Connectors (`pingidmConnector`: `connectorRef` from `pingidmBundle`, `pingidmBundleVersion`, `pingidmConnectorName`; settings) | `pingidm/conf/provisioner.openicf-<name>.json`, per environment |

**Connectors per environment.** A connector names the binding role of the system it reaches (`pingidmTargetRole`, e.g. the directory's `ds-ldaps-service`) and the secret role of its credentials (`pingidmCredentialRole`); each environment renders its provisioner file with its own host and `${secret:<ref-uri>}`. The host is `configurationProperties.host` (the role's binding's `ciamFqdn`), or, for a database connector whose import found its hosts in the JDBC `configurationProperties.url`, the hosts of that URL (the record keeps the URL without them, `jdbc:postgresql:///hr`, and their common port as `pingidmPort`; an environment that binds the role several times renders every host, in `ciamHostOrder`). A role the environment doesn't bind renders as `UNBOUND:<role>`, and a withheld value no credential role supplies as `${withheld}` (the planner blocks on both). A connector with no target role keeps its fixed host as recorded.

The product profile (`render.PROFILE`) places `pingidm/conf/` under a deployment kit's `conf/` and captured `files/pingidm/` (the other `conf/` files, `resolver/`) at the instance root.

**Not rendered:** IDM's other `conf/` files and `resolver/*.properties` are captured files (below), written back by the core's captured-file render; scripts and UI files are code (`opsdir bundle`), not configuration.

## What it reads back

### IDM project: `pingidm/project`

```bash
opsdir import --change CHG-… pingidm PROJECT_DIR        # pingidm/project; --dry-run first
```

Reads an IDM project directory (`project.py`):

| File | Recorded | Match key |
|---|---|---|
| `conf/managed.json` | one `pingidmManagedObject` per object (its schema in `pingidmSchema`, other settings in `pingidmConfig`), in file order | name |
| `conf/provisioner.openicf-<name>.json` | `pingidmConnector`: `connectorRef` as `pingidmConnectorName`, `pingidmBundle`, `pingidmBundleVersion`; a host (`configurationProperties.host`, else the hosts of a JDBC `configurationProperties.url`) that is a role in the record (a service name, an external system's host) becomes that role (`pingidmTargetRole`; a JDBC URL's common port `pingidmPort`) and leaves the settings; the bind account (`configurationProperties.principal`) linked to its directory consumer record (`pingidmConsumer`) | file name |
| `conf/sync.json` | one `pingidmMapping` per mapping (source, target, the rest of its settings), in file order | name |
| `conf/schedule-<name>.json` | `pingidmSchedule` (enabled, settings) | file name |
| every other `conf/` file (JSON, properties), and `resolver/*.properties` (`boot.properties`: ports, hosts, the HTTP client's proxy) | a captured config file (configuration domain): `idm.<path>` at repository path `pingidm/<path>`, deployed to role `idm`, held setting by setting | path |

The importer owns what it reads; what the record adds to its entries (a connector's credential role, owners) is kept. Credential roles are never guessed: set them with a change. Values that may be secret are withheld (`pingidmWithheld`, JSON Pointers): IDM's encrypted values (`{"$crypto": ...}`) whole, and what opsdir renders in their place, so a rendered file imports back unchanged (`reads_back`: `project` over `pingidm/*`). Notices name a connector whose credentials are withheld without a credential role, a connector with no host that is a service name in the record (it reaches the same place from every environment), a `conf/` file in a format that isn't captured, code (`script/`, `ui/`, `bundle/`, `connectors/`, `.js`, `.groovy`, `.py`, `.sh`, `.jar`: record it as a bundle with `opsdir bundle`), and files that aren't IDM configuration.

### Collecting from PingIDM (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter pingidm` reads the project's configuration over IDM's REST API, read-only, and imports it like a saved `conf/` directory (`collect.py`, collector `project`): `GET /openidm/config` lists the objects, `GET /openidm/config/<id>` reads each (`Accept-API-Version: resource=1.0`), saved as `conf/<id>.json` (a factory configuration's instance after a dash: `provisioner.openicf/ldap` -> `conf/provisioner.openicf-ldap.json`) without the `_id` the API adds. The environment declares where (`ciamCollectionSource`: `ciamImporter: pingidm/project`, `ciamSourceRef` IDM's URL (the first readable source, its first location), `ciamCredentialRole` and `ciamLoginName` for the account, `ciamCaRole` for the trust anchor); the password is resolved when collecting and sent as `X-OpenIDM-Username` / `X-OpenIDM-Password`, never stored. A source's unbound credential or trust anchor is named and nothing is read. `resolver/` properties aren't served over REST and aren't collected; encrypted values (`$crypto`) stay as IDM holds them and the importer withholds them. Least privilege: an internal user whose role `access.json` allows `read` on `config/*` only (else `openidm-admin`).

## Schema, vocabulary and secret patterns

Schema under this package's OID arc `1.3.6.1.4.1.32473.3.2` (prefix `pingidm`, `schema.py`): 14 attributes; classes `pingidmManagedObject`, `pingidmConnector`, `pingidmMapping`, `pingidmSchedule`, under `ou=managed-objects`, `ou=connectors`, `ou=mappings`, `ou=schedules` of `ou=pingidm` (`naming.py`). Settings are kept as IDM writes them (JSON).

Vocabulary it owns: `ciamServerRole` and `ciamTargetRole` value `idm`. It owns no reference schemes and no secret patterns. Format: `pingidm/conf/*.json` (JSON).

## Roles, server roles and planner checks

**Required roles**: `subnet-idm`, `idm-admin-password`, `idm-keystore`. The connectors' credential roles are reported to the core's role checks (`roles_used`: `checks.connector_roles`).

**Server role** `idm`:

- **Listeners** (ports matrix, `listeners.py`): the REST API, HTTPS 8443 for the operators (IDM's default; the record holds no port for it; from 8.1 IDM bundles no administration UI), and the ports its connectors reach through a service name's role (the connector's own `port`, else the service's).
- **Logs** (`logs.py`, under the openidm directory): the audit topics `audit/access.audit.json` (access), `activity`, `authentication`, `sync` (audit) and `config` (admin) as JSON lines, and `logs/openidm*.log` as text (its format differs by version). The reconciliation topic isn't on by default, so it isn't declared.
- **Signals** (`signals.py`, at `/openidm/metrics/prometheus` once `conf/metrics.json` enables metrics): `heap-used`, `idm_jvm_memory_usage_used{location="heap"}` from 8.0, `idm_jvm_memory_usage_heap_used` before.
- **Detections** (`detections.py`, offered as alert rules a person adopts: core observability detections; validation documented): from 7.1, `brute-force`, 10 authentication events with `result` `FAILED` for one `principal` within any 5 minutes, T1110.001, sev3, and `password-spray`, 10 principals failing from one `context.ipAddress` within any 10 minutes, T1110.003, sev2 (authentication topic; the selector is the result alone, as no one sign-in event name is established); from 7.2, `config-change`, every config event (`eventName` `config` or `CONFIG`: the guides give both) with its `userId` and `objectId`, T1556, sev3. Not declared: administrator sign-in failures (`context.component` isn't guaranteed on a failure), key changes (no config object is documented for secrets or session keys).
- **Endpoints** the edge treats specially, by the servers' recorded `ciamProductVersion` (none recorded: the newest release): standalone self-service reset and registration (`/openidm/selfservice/reset`, `/openidm/selfservice/registration`) before 8.0 only; health `/openidm/info/ping` before 8.1, `/openidm/health/ready` from 8.1.
- **Egress through an explicit proxy** (`proxy.py`): when an environment's egress passes a proxy clients must be told about (a `ciamProxy` with `ciamProxyAddress` that isn't a firewall), PingIDM's HTTP client (external REST, the identity provider service) is told to use the JVM's proxy, `openidm.http.client.proxy.useSystem=true` in `resolver/boot.properties`, with the standard Java proxy properties in the JVM options it starts with (`OPENIDM_OPTS`). The JVM's proxy is used, not `openidm.http.client.proxy.uri`, because only it honours the hosts reached directly (`http.nonProxyHosts`), so connectors to the platform's own services stay off the proxy. The importer captures `resolver/*.properties` with the `conf/` files, so the planner compares `boot.properties` with the record and offers a fix (`opsdir fix`) that adds the setting when it is missing; it names the JVM options, which the record can't confirm.

**Planner check** `check_idm` (`checks.py`):

| Reports | Fix offered |
|---|---|
| Blocker: a mapping whose source or target names a connector (`system/<connector>/...`) or managed object (`managed/<object>`) the record doesn't have; a reconciliation schedule (`invokeContext.action: reconcile`) naming a mapping it doesn't have | |
| Blocker: a connector with withheld credentials but no credential role | `credential-role:connector/<name>` (choose the secret role) |
| Blocker: a connector's target or credential role the target environment doesn't bind | |
| Action: a connector with a fixed host (no target role) | `external-host:connector/<name>`: record its `host` (or its JDBC URL's hosts, one binding each) as the source's `ciamExternalHost` of a role you give, so the next import names the role |

Otherwise one line says the mappings and schedules refer only to what IDM has.

### Upgrades during a move

A migration may upgrade the product within the supported range. The planner names each server role's version jump, from the oldest version the source runs to the newest the target runs, and every change below that the jump crosses (the source version lacks it, the target's has it), at its effect, when it applies to the record. A target outside the range is a blocker, a downgrade an action. From the vendor's release notes (`versions.py`).

| Since | Change | Effect | Named when |
|---|---|---|---|
| 8.0 | standalone self-service (password reset, registration, KBA) is removed | blocker | the record holds captured self-service configuration (`pingidm/conf/selfservice*`) |
| 8.0 | the Office 365, .NET Active Directory and Scripted CREST connectors are removed | blocker | the record holds connectors of those bundles or implementations |
| 8.0 | logging moves from java.util.logging to Logback (conf/logback.xml); conf/logging.properties is no longer read | action | the record holds captured `conf/logging.properties` |
| 8.0 | Jetty 12: conf/jetty.xml is removed (webserver.json and webserver.listener-*.json configure the listeners) | info | always |
| 8.0 | the embedded DS repository is removed | info | always |
| 7.5.3, 8.0.2 | the Oracle datasource template uses UCP (a service-name URL, connectionWaitTimeout) | info | the record holds captured JDBC datasources (`conf/datasource.jdbc-*.json`) |
| 8.1 | Java 21 is required | action | the IDM servers' host baseline records an older JDK (`ciamJdk`) |
| 8.1 | /openidm/info/ping and /openidm/health are deprecated (/openidm/health/live and /ready) | info | always |
| 8.1 | the legacy admin UI is no longer bundled | info | always |

## Known limits

- **Not validated against a live IDM.** The rendered `conf/` files follow IDM's layout; loading them, and collecting from a real IDM, are part of the testing plan (milestone 7.2).
- **Modeled**: managed objects, connectors, mappings and schedules; everything else in `conf/` and `resolver/` is held as captured files, scripts and UI as bundles.
- **Names**: a managed object, mapping, connector or schedule whose name can't be a record name (it holds a DN special character, or has none) is not imported; a notice names it and its file. Connector and schedule names come from their file names (`provisioner.openicf-NAME.json`, `schedule-NAME.json`).
- **One credential role per connector**: all its withheld values take that role's reference.
- **Listener port** is IDM's default, not recorded.

## Tests

`tests/test_pingidm.py`: registration and applies from the servers' products; a connector to the directory naming its role and consumer and withholding its credentials; a connector to an unknown host named; mappings, schedules and the rest of `conf/`; names that can't be record names named in notices; `resolver/` properties captured and other files named; connectors rendered per environment; the render reading back unchanged; the planner's findings; a connector whose host is in a JDBC URL named by the fix and rendered with each environment's hosts; endpoints by the recorded version; what an upgrade to IDM 8 touches; the connectors' credential roles. `tests/test_pingidm_collect.py` (the listing, then each object where the project keeps it, with `X-OpenIDM-*` headers), `tests/test_pingidm_listeners.py`, `tests/test_pingidm_proxy.py`. `tests/idm-project/` is the sample project.

`tests/test_pingidm_store.py` (marker `integration`, Postgres via `OPSDIR_TEST_DSN`): a project imported under an approved change, the store accepting every entry and holding no credential, a re-import changing nothing.

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-pingidm/tests
opsdir/.venv/bin/python -m pytest -m integration packages/opsdir-adapter-pingidm/tests
```

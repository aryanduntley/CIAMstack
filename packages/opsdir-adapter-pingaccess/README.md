# opsdir-adapter-pingaccess

opsdir adapter for PingAccess: what PingAccess protects (applications and their resources, the sites behind them, virtual hosts, web sessions, identity mappings, rules and rule sets) held in the record by name, with what differs per environment (hosts, client ids, secrets) taken from each environment's bindings; rendered per environment as Admin API requests; read back from Admin API reads (collected read-only with an Auditor credential) or a saved configuration export; and checked by the planner.

**Applies to** environments where PingAccess runs: a server, or a Kubernetes workload's binding, whose `ciamProductVersion` starts with `PingAccess` (`runs_product`). Supported versions `>=8.2,<10`. A product adapter: it defines the server roles `pa-admin` (the administrative node) and `pa-engine` (the engines) and declares them for the kits that deploy it (`Adapter.roles`: server `pa-admin`, `pa-engine`); where it runs (servers, Kubernetes) is other adapters'.

**Depends on** `opsdir` only. PingAccess is an OpenID Connect relying party here: the client it signs users in as is the federation domain's `oidc-client` integration, which the identity provider's adapter (PingFederate, PingAM) renders on `opsdir-base-oidc`; this adapter renders nothing standard of its own. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingaccess`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

**Unverified vendor forms.** Every Admin API path, field name, value, paging parameter and the export's envelope the adapter uses is in one data module, `api.py`, taken from Ping's PingAccess 8.2-9.1 documentation and **not checked against a live PingAccess or its installed OpenAPI document** (see Known limits for the acceptance items). The tests are built from the documented shapes (`tests/admin-api/`, `tests/export/`, made up).

## What it renders

Per environment (`render.py`); nothing environment-neutral.

### Admin API requests: `pingaccess/admin-api/requests.json`

```json
{"pingAccess": "PingAccess 9.1.1", "adminApi": "v3", "verified": false,
 "openApi": "/pa-admin-api/v3/api-docs/pa/api-docs-v2.json", "problems": [],
 "requests": [{"method": "PUT", "path": "/sites/${pingaccess-id:sites/portal-backend}", "createWith": "POST /sites",
               "body": {"name": "portal-backend", "targets": ["portal-backend.example.test:8443"], ...}}, ...]}
```

| From the record | Rendered as |
|---|---|
| Objects held as is that aren't environment-bound (`paHeld`): availability profiles, load balancing strategies, site authenticators, access token validators, the token provider's settings (`pingfederate/runtime`, `oidc/provider`) | their collection's requests, first |
| Rules and rule sets (`paRule`) | `/rules`, then `/rulesets` (a rule set's members by reference) |
| Sites (`paSite`) | `/sites`: `targets` from the bindings of the site's backend role (`paBackendRole`), each `<ciamFqdn>:<paPort, else the binding's ciamPort>` in host order (`ciamHostOrder`), `UNBOUND:<role>[:<port>]` where the environment binds none; a site with no role keeps its fixed targets |
| Virtual hosts (`paVirtualHost`) | `/virtualhosts`: `host` the `ciamFqdn` of its service name role (`paServiceRole`), `UNBOUND:<role>` where the environment binds none |
| Identity mappings, web sessions (`paIdentityMapping`, `paWebSession`) | `/identityMappings`, `/webSessions`: a session's `clientCredentials.clientId` the `ciamClientId` of its integration (`paIntegration`), so an edit in the record wins |
| Applications and their resources (`paApplication`, `paResource`) | `/applications` (`contextRoot` from `paContextRoot`), then `/applications/${pingaccess-id:applications/<app>}/resources` |

- **Order and references.** An object comes after those it names (`api.COLLECTIONS`). PingAccess assigns every object's id itself, so the record names objects by name: in paths and bodies an object named by id is `${pingaccess-id:<collection>/<name>}` (a virtual host's name is `<service role or host>:<port>`, a settings object's `settings`). **Applying them** is the operator's pipeline's job (opsdir never writes to PingAccess): in order, a PUT to the object's path, and where it doesn't exist yet the `createWith` POST; the pipeline keeps the id each object gets (by its collection and name) and replaces every `${pingaccess-id:...}` with it before sending a request that names it. A settings object is a PUT.
- **Secrets are never values**: `${secret:<reference>}` (the reference the object's credential role, `paCredentialRole`, binds in this environment), `UNBOUND:<role>`, or `${withheld}` while no credential role is set (the planner blocks on both). A hidden field renders as `{"value": "${secret:...}"}`; the pipeline puts the value in at apply time.
- **Not rendered**: environment-bound objects (`paEnvironmentBound`: certificates, trusted certificate groups, key pairs, HTTPS and engine listeners, engines, the admin node and replica admins, agents, sideband clients), created in each environment from its own key material, CAs and nodes; a server profile's `data.json` (the export's envelope is unverified, and importing one replaces the whole configuration); the nodes' own files (`run.properties`, `bootstrap.properties`, `pa.jwk`, `fips-mode.properties`, the log configuration: capture them with `opsdir capture`); the license.
- **`problems`**: secrets withheld with no credential role; references naming an object the record doesn't hold; roles the environment doesn't bind.

### Applications PingAccess takes over (`takeover.py`)

The neutral protected-application layer (core domain `webaccess`; opsdir's README, Protected web applications) holds
what any product protects. An environment can have PingAccess enforce an application another product (or an
operator) recorded: its override of the application's `ciamEnforcedByRole` is `pa-engine`. PingAccess then renders it
in that environment, with every object named after it:
- a site `<app>-backend` (targets from `ciamBackendRole`, its port, `secure` from `ciamBackendTls`);
- a virtual host `<role>:443` per published role (one the record's PingAccess already has is reused);
- a web session `<app>-session`:
  - the client id of `ciamSignInAs`;
  - the credentials type its token endpoint methods allow;
  - the client secret from `ciamCredentialRole`;
  - PKCE when the integration requires it;
  - the idle and maximum timeouts in minutes;
- a header identity mapping `<app>-headers` (each header contract's attribute or claim);
- the access rules it can test:
  - a web session attribute, OAuth scope or network range rule (negated for a denial);
  - rule sets for several tests or included rules;
  - a signed-in user is the session itself;
- the application (`contextRoot` from the base path) and its resources (path patterns, a prefix as a wildcard;
  methods; anonymous or unprotected; their rules).

A PingAccess application whose neutral application another role enforces in the environment is left out of its render
there (the product taking it over renders it). What PingAccess can't express of a taken-over application is a render
note for its owners:
- a rule it can't test (a directory group, a user, an LDAP filter, an IPv6 range, a custom rule) is a **blocker**:
  rendered without it, the application would admit more than the record says;
- sign-on PingAccess doesn't do itself (a form, a certificate, custom code: the identity service must offer it) is an
  action;
- a translated pattern is a note;
- a secret with no credential role is a blocker.

The plan's `protect:pa/<application>` fix writes the target's override for an application nothing there would protect.

### Render notes (`Adapter.notes`, as data in `NOTES.md` / `NOTES.json`)

| Severity | Subject | Says |
|---|---|---|
| action | `pingaccess/admin-api/requests.json` | the paths and fields are unverified for the environment's version: check them against `/pa-admin-api/v3/api-docs/pa/api-docs-v2.json` on the admin node before applying |
| action | `environment-bound objects` | not rendered: create `<collection> <names>; ...` in the environment before applying the requests |
| blocker | `<collection> <name>` | its secrets are withheld and no credential role supplies them |
| note | `server profile`, `node files` | what isn't rendered, and what to do instead |

## What it reads back

Two importers, the same record from either; the importer owns what it reads, and what the record adds to an entry (owners, its credential role) is kept. A collection read replaces what the record holds for it (an object it no longer has is removed); a collection nothing was read for is left as it is.

### Admin API reads: `pingaccess/admin-api`

```bash
opsdir collect --env CLOUD/ENV --adapter pingaccess/admin-api     # read-only (below), or save the responses yourself
opsdir import --change CHG-… pingaccess/admin-api DIR/            # --dry-run first
```

Reads `<collection>.json` or `<collection>/page-<n>.json` (`{"items": [...]}`, pages joined), a settings object as `<path>.json`, `applications/<id>/resources[/page-<n>].json` (each resource given its application), `version.json` (`{"version"}`), and this adapter's own rendered `requests.json` in any folder (each request's body an item of the collection its `createWith`, else its path, names), so a render reads back unchanged (`reads_back`: `admin-api` over `pingaccess/admin-api/*.json`).

### A saved configuration export: `pingaccess/export`

```bash
curl -u Administrator:… -H 'X-XSRF-Header: PingAccess' https://pa-admin:9000/pa-admin-api/v3/config/export > export/pa.json
opsdir import --change CHG-… pingaccess/export export/
```

The export needs an Administrator (no read-only role may export), so opsdir never collects it: an administrator saves it. Its envelope is taken as `{"version", "data": {section: [items]}}` or the sections at the top level; sections map to collections by name (`api.EXPORT_SECTIONS`, both spellings where the documentation varies); resources in a section of their own (with their application's id) or inside their application. The export's encryption material (`encryptionKey`, `masterKeys`, ...: what `PORTABLE_INSECURE` exports embed, or anything key-like beside the sections) is dropped and named in a notice, never stored. Several exports of different versions read at once record no source version, and say so.

### The neutral layer (`neutral.py`)

Every import also projects PingAccess's applications, resources and rules onto the neutral protected-application
layer (`ciamProjectedFrom` names the PingAccess entry):
- An application becomes `ciamProtectedApp`, enforced by `pa-engine`:
  - the context root is its base path;
  - its virtual hosts' service roles are what it is published as;
  - its site gives the backend role, port and TLS;
  - sign-on: `oidc` through its web session's integration, served by the identity service of the session's issuer
    (an API application: `token`);
  - the session's idle and maximum timeouts become seconds;
  - its identity mappings give the header contracts it sets;
  - its Web (or API) policy gives its rules.
- A resource becomes `ciamPathResource`: path patterns (wildcard or regex; older path prefixes as prefix), methods
  (`*` as every method), anonymous or unprotected, its policy.
- A rule becomes `ciamAccessRule`:
  - a web session attribute rule tests an attribute, an OAuth scope rule a scope, a network range rule a network
    (negated: deny);
  - a rule set includes its members, all or any;
  - any other rule is `custom`.

What the record adds to the neutral entries (an owner, a credential role) is kept; another product's or an operator's
entry at the same name is never changed (the import names the differences). The read-back of a render leaves out the
requests rendered for taken-over applications and adds back those of applications handed to another product in that
environment (`render.own_requests`), so a render still reads back unchanged.

### What is recorded

| Admin API | Recorded (under `ou=pingaccess`) | What differs per environment |
|---|---|---|
| `/applications`, their `/resources` | `paApplication` under `ou=applications`, its `paResource`s below it; `paContextRoot` (a contract) | |
| `/sites` | `paSite` under `ou=sites` | targets whose hosts are one role in the record (a service name, an external system's `ciamExternalHost`, a managed database, or a rendered `UNBOUND:<role>`) with one port become `paBackendRole` and `paPort`, and leave the settings; others stay, fixed |
| `/virtualhosts` | `paVirtualHost` under `ou=virtual-hosts`, named `<role or host>:<port>` | a host that is a role in the record becomes `paServiceRole` |
| `/webSessions` | `paWebSession` under `ou=web-sessions`: linked to the `oidc-client` integration with its client id (`paIntegration`; the id then leaves the settings), and to the OpenID provider PingAccess's token provider names (`paIssuer`, from `pingfederate/runtime` or `oidc/provider`) | |
| `/identityMappings` | `paIdentityMapping` under `ou=identity-mappings`, linked to the header contracts (edge domain) naming the headers it sets (`paHeaderContract`) | |
| `/rules`, `/rulesets` | `paRule` under `ou=rules` and `ou=rule-sets` (`paRuleKind`) | |
| every other collection read | `paHeld` under `ou=<collection>,ou=held` (`paObjectType`), environment-bound ones marked (`paEnvironmentBound`) | the whole object |

- **Names, not ids.** Each object's settings (`paConfig`) keep the objects they name as `${pingaccess-id:<collection>/<name>}` (an application's site, virtual hosts, web session, identity mappings and policy; a rule set's members; a site's trust group, availability profile and authenticators; ...: `api.REFERENCES`), and the record links them by DN (`paUses`). The settings drop PingAccess's ids. An id the import doesn't hold the object for is kept as the id and named.
- **Secrets** (`withheld.py`): a hidden field (`{"value", "encryptedValue"}`) has its value withheld and its ciphertext dropped (the export encrypts secrets with the deployment's own key, so neither carries over); a setting whose name says it holds a secret (`sharedSecret`, `password`, `privateKey`) is withheld whole; so is anything the registered patterns or the randomness test flag. The record keeps only where each was (`paWithheld`); each environment renders the reference of the object's credential role.
- **Source version** (`paSourceVersion`): the version `version.json` or the export names; a render read back records none and keeps the record's.
- **Notices** name: the version; fixed sites and virtual hosts; clients no integration has; headers no header contract names; secrets withheld without a credential role; ids the import doesn't hold; names that can't name an entry (a DN special character, a slash, a duplicate); resources without their application; the export's dropped encryption material and sections it doesn't read; files that aren't Admin API responses.

### Collecting from PingAccess (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter pingaccess` reads the Admin API read-only (`collect.py`, collector `admin-api`). The environment declares where:

```ldif
dn: cn=pa-admin,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops
objectClass: ciamCollectionSource
ciamBindingRole: collect-pa-admin
ciamImporter: pingaccess/admin-api
ciamSourceRef: https://pa-admin.example.test:9000
ciamCredentialRole: pa-auditor            # a binding whose ciamRefUri references the Auditor's password
ciamLoginName: opsdir-auditor
ciamCaRole: pa-admin-ca                   # a binding whose ciamRefUri references the admin port's CA certificate (PEM)
```

opsdir resolves the credential and the CA certificate when collecting (held in memory, never stored) and sends only GETs, each with `X-XSRF-Header: PingAccess`, from an explicit list: `/version`, each collection of `api.COLLECTIONS` page by page (`page`, `numberPerPage`: another page while the last came back full and differed from the one before it, so a PingAccess that ignores paging stops after two), each settings object, then each application's resources. A collection the version doesn't have (404) is left out. **Access**: an Auditor (Ping documents its read access to everything but `/config/*`, `/backup` and agent configuration). An Admin API that validates OAuth tokens is read with `ciamCredentialScheme: bearer` (the token minted outside opsdir and rotated there; opsdir never requests one); other schemes are named and nothing is read. **Never requested**: the configuration export (Administrator only), backups, agent and engine configuration downloads (they generate key material).

## Schema, vocabulary and secret patterns

Schema under this package's OID arc `1.3.6.1.4.1.32473.3.5` (prefix `pa`, `schema.py`): attributes `paConfig`, `paWithheld`, `paCredentialRole`, `paSourceVersion`, `paObjectType`, `paUses`, `paContextRoot` (a contract), `paServiceRole`, `paPort`, `paBackendRole`, `paIntegration`, `paIssuer` (a contract), `paHeaderContract`, `paEnvironmentBound`, `paRuleKind`; classes `paApplication`, `paResource`, `paSite`, `paVirtualHost`, `paWebSession`, `paIdentityMapping`, `paRule`, `paHeld`.

Vocabulary it owns: `ciamServerRole` and `ciamTargetRole` values `pa-admin`, `pa-engine`. It owns no reference schemes and no secret patterns. Format: `pingaccess/admin-api/*.json` (JSON).

## Roles, server roles and planner checks

**Required roles**: none of its own (a site's backend role, a virtual host's service role and a credential role are checked where named).

**Server roles** `pa-admin`, `pa-engine`:

- **Listeners** (ports matrix, `listeners.py`; Ping's documented defaults, the record holds no listener ports): `pa-engine` 3000 (HTTPS, clients); `pa-admin` 9000 (console and API, admin) and 9090 (cluster configuration, from the engines and a replica admin), from 9.1 9095 (cluster certificate rotation); `pa-engine` 3030 (agents) and 3020 (sideband) only where the record holds agents or sideband clients; and the ports its sites reach on the applications behind service names.
- **Endpoints** (`naming.ENDPOINTS`): the heartbeat `/pa/heartbeat.ping` on the engines' port 3000 and the admin node's 9000, so load balancer health checks probe it there.
- **Logs** (`logs.py`, what a log route ships): text files under the install root's `log/`, as Ping's monitoring guide lists them for 8.2 through 9.1. On both roles `pingaccess.log` (kind `error`); on `pa-admin` the admin API's audit log `pingaccess_api_audit.log` (`admin`); on `pa-engine` the audit logs of what the engines serve (`audit`): `pingaccess_engine_audit.log` (resources whose Audit setting is on), `pingaccess_agent_audit.log`, `pingaccess_sideband_client_audit.log` and `pingaccess_sideband_audit.log` (only with sideband enabled: `sideband.http.enabled`, off by default). JSON (8.3 on), audit to a database and the optional appenders (error-only, HAR, CEF, Splunk) are Log4j2 changes, not declared.

**Planner check** `check_pingaccess` (`checks.py`), when the target runs PingAccess:

| Reports | Fix offered |
|---|---|
| Blocker: a web session that can't sign users in: its client is no integration in the record; its issuer is no identity service's `ciamOidcIssuer`; it authenticates to the token endpoint in a way its integration isn't registered for (`credentialsType` `SECRET` as `client_secret_basic`/`client_secret_post`, `CERTIFICATE` as `tls_client_auth`/`self_signed_tls_client_auth`, `PRIVATE_KEY_JWT` as `private_key_jwt`, against the integration's `ciamTokenAuthMethod`); its integration requires PKCE and it sends no challenge | |
| Blocker: withheld secrets no credential role supplies, or whose role the target doesn't bind | |
| Blocker: an object naming one the record doesn't hold (PingAccess refuses it) | |
| Blocker: a virtual host's service role, or a site's backend role, the target doesn't bind | |
| Blocker: the target runs no engine (`pa-engine`) | |
| Action: a web session using the implicit flow (`oidcLoginType` `POST` or `x_post`): move it to `Code` | |
| Action: a site sending requests to fixed hosts from every environment | `external-host:pa-site/<name>`: record the hosts as the source's `ciamExternalHost` of a role you give, so the next import names the role |
| Action: a header an identity mapping sets that no header contract names | `header-contract:pa/<mapping>/<header>`: record it (kind `identity`, set by `pa-engine`, trusted by the server roles behind the applications using it), so the edge's header check guards it (spoofable until `ciamStripsInbound` is confirmed) |

Otherwise one line says every web session signs users in with clients and OpenID providers the record has. The environment-bound objects to create in the target reach the plan as the render's note (above), as do the unverified requests. The edge domain's `check_headers` covers the header contracts themselves (a setter the target doesn't run, a spoofable identity header).

### Upgrades during a move

A migration may upgrade PingAccess within the supported range; the planner names the changes between the source's and the target's versions (`versions.py`, dated: research note 3076, Ping's 8.2 and 9.1 documentation read 2026-10-15):

| Since | Change | Effect | Named when |
|---|---|---|---|
| 8.2.1 (April 2025) | FIPS mode uses Bouncy Castle FIPS 2.0 (FIPS 140-3), and key pairs in FIPS mode are PEM only (no PKCS#12) | info | key pairs the record holds |
| 9.1 (June 2026) | rotating the cluster's certificates uses a temporary port, 9095, between the admin node and the engines | action | always |

Import of a configuration export is a restore: Ping documents it from the same or an earlier version (API v3, 5.0 on); sources at 6.2 or earlier upgrade through 6.3.

## Known limits

- **Acceptance items (unverified vendor forms, `api.py`).** Before relying on a render or an import for a version, check against that version's installed OpenAPI document (`/pa-admin-api/v3/api-docs/pa/api-docs-v2.json`) and a sanitized real export: every collection path (most are documented as concepts, not as paths for 9.1.1), the field names the adapter reads and writes (`api.REFERENCES`, `CLIENT_ID`, `CREDENTIALS_TYPE`, `LOGIN_TYPE`, `PKCE`, `HEADER_FIELDS`, `TARGETS`, `HOST`, `CONTEXT_ROOT`, the hidden field's `value`/`encryptedValue`), the identity mapping class names, the policy shape (`{"Web": [{"type", "id"}], "API": [...]}`, a rule set's `elementType` and member ids), the paging parameters and their origin, `/version`'s answer, whether a POST may carry an id, and the export's envelope, section names, how it lists resources and how it writes secrets and encryption material. A difference is corrected in `api.py`.
- **Not validated against a live PingAccess**: the requests follow the documented JSON; applying them in a test PingAccess is part of the testing plan (milestone 7.2).
- **Environment-bound objects are held, not rendered**: key pairs, certificates, trust groups, listeners, engines, the admin and replica nodes, agents and sideband clients are created per environment.
- **No server profile**: `data.json` isn't rendered (its placement differs between Ping's profile documentation and its baseline repository, and the envelope is unverified).
- **Neutral projection and takeover forms are unverified** (research note 3133; deferred note on `api.py`).
  - Ping's 9.1 documentation describes resource access, wildcard and regex patterns, rule sets succeeding on all or
    any, negation and web session timeouts, but not their JSON names. Acceptance items: `pathPatterns`/`pathPrefixes`,
    `WILDCARD`/`REGEX`, `methods`, `anonymous`, `unprotected`, the `negate` key, the rule class names, the success
    criteria values, `caseSensitivePath`, `applicationType`, `idleTimeoutInMinutes`/`sessionTimeoutInMinutes` and
    resource ordering (not projected: most specific first).
  - Applications sharing a web session share its timeouts.
  - A governed edit of a PingAccess entry doesn't change its neutral projection until the next import.
- **Logs as documented, not observed**: the log files come from Ping's 8.2-9.1 documentation (research 2026-10-16), whose Logging page says `logs/` in its prose and `log/` in its `log4j2.xml` example; the adapter follows the example (Ping's shipped `log4j2.xml` wasn't found to check). Confirm on a real install, with the default `conf/log4j2.xml`, which files each role writes (a replica admin's is unstated). The server log's stack traces have no documented first-line pattern, so a multi-line record is read line by line. The garbage-collection log (on by default; `GC_FILE` in `bin/run.sh`) isn't declared, since its path isn't documented. HAR audit logs aren't declared either: they can hold credentials.
- **One OpenID provider**: the issuer of the token provider's settings (`pingfederate/runtime`, else `oidc/provider`) is recorded on every web session.
- **Agents** are held as is, their shared secrets withheld; their configuration downloads are never read.

## Tests

`tests/test_pingaccess.py`: registration and applies from the servers' products; objects named by name and naming each other by reference; hosts that are roles in the record and fixed ones; the web session linked to its client and provider and its secret withheld (no ciphertext in the record); environment-bound objects held and marked; the requests rendered per environment in order and read back unchanged; render notes; the planner's findings (unbound roles, withheld secrets, a fixed site, a header with no contract and its fix, a session authenticating otherwise than its client is registered, a target running no engine); what an upgrade touches. `tests/test_pingaccess_collect.py`: the collector's requests, credential and trust anchor, paging, schemes, and that what it collects imports like the saved responses; a saved export importing the same record with its encryption material dropped. `tests/test_pingaccess_listeners.py`: listeners and the heartbeat. The logs each server role writes are in `tests/test_pingaccess.py`. `tests/admin-api/` and `tests/export/` are made-up, in the documented shapes.

`tests/test_pingaccess_store.py` (marker `integration`, Postgres via `OPSDIR_TEST_DSN`): Admin API reads imported under an approved change, a re-import changing nothing.

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-pingaccess/tests
opsdir/.venv/bin/python -m pytest -m integration packages/opsdir-adapter-pingaccess/tests
```

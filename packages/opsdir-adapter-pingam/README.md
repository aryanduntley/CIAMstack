# opsdir-adapter-pingam

opsdir adapter for PingAM (ForgeRock AM): every realm AM serves rendered as Amster-importable entities (OAuth2/OIDC clients, authentication journeys and their nodes, policy sets and policies) and, on `opsdir-base-saml` and `opsdir-base-oidc`, the standard SAML and OIDC documents at AM's endpoint paths; Amster exports read back into the record, and collected with Amster.

**Applies to** environments where PingAM or ForgeRock AM runs: a server, or a Kubernetes workload's binding, whose `ciamProductVersion` starts with `PingAM` or `ForgeRock AM` (`runs_product`). Supported: PingAM `>=7,<9`, ForgeRock AM `>=7,<8`. A product adapter: it defines the server role `am`; its realms are the identity services AM's servers serve (`ciamTargetRole` `am`). PingAM 8 serves journeys only (authentication modules and chains were removed in 8.0) and needs an external directory for its configuration and identities (embedded DS is gone): `am-ds-bind-password` is that directory's bind password.

**Depends on** `opsdir`, `opsdir-base-saml` and `opsdir-base-oidc` (the standard documents). Collection needs Amster on the path. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingam`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## The record's model

- **Realms are identity services.** A realm is one of the platform's identity services with the auxiliary class `pingamRealm` (`pingamRealmPath`: `/`, `/customers`, ...); integrations say which one they are registered with (`ciamServedBy`).
- **Standard where the concept is standard.** OAuth2/OIDC clients and SAML partners are the federation domain's integrations.
- **AM's own vocabulary here.** Journeys (`pingamJourney`, one `pingamNode` per node: type, display name, settings, outcomes, version) and policy sets (`pingamPolicySet`, `pingamPolicy`) live under `ou=journeys,ou=pingam` and `ou=policy-sets,ou=pingam`, a container per realm named by its identity service (`naming.py`).

## What it renders

Environment-neutral only (`render.py`; no per-environment render): for every realm AM serves (`realms`: the identity services of servers of role `am`).

| From the record | Rendered as |
|---|---|
| A realm below the root (its path, the host of its `ciamBaseUrl`) | `am/global/Realms/<name>.json`: name, parent path, active, the host as its alias |
| The OIDC clients registered with the realm (`oidc-client` integrations served by it) | `am/realms/<realm>/OAuth2Clients/<client id>.json`: client type (`Public` when `ciamTokenAuthMethod` is `none`, else `Confidential`), name, redirect URIs, scopes, grant types, token endpoint auth method, post-logout redirect URIs, each set on the client (`inherited: false`); an `x-opsdir` block with the claims, PKCE and MFA requirement |
| Each journey (`pingamJourney`) | `am/realms/<realm>/AuthTree/<tree>.json`: entry node, enabled, the node map (type, version where held, display name, outcomes; nodes inside a page node left out of it), its other settings |
| Each journey node (`pingamNode`) | `am/realms/<realm>/<NodeType>/<node id>.json`: its settings, `_type` with its version (PingAM 8.1+, where the record holds one), the withheld settings named in `x-opsdir` |
| Each policy set and its policies | `am/realms/<realm>/Applications/<set>.json`, `am/realms/<realm>/Policies/<name>.json` |
| The realm's SAML partners and its hosted IdP | `saml/sp/`, `saml/partner-idp/`, `saml/idp/<service>.xml` (opsdir-base-saml): SSO `/am/SSORedirect/metaAlias[/<realm>]/idp` and `/am/SSOPOST/...`, SLO `/am/IDPSloRedirect/...` and `/am/IDPSloPOST/...` |
| The realm's OIDC clients and provider | `oidc/clients/`, `oidc/discovery/<service>.json` (opsdir-base-oidc): `/am/oauth2[/realms/root/realms/<realm>...]` `/authorize`, `/access_token`, `/userinfo`, `/connect/jwk_uri`, `/connect/endSession` |

`<realm>` is the realm's directory in an Amster export: `root`, `root-customers`, ... (`realms.export_dir`). Every entity is `{"metadata": {realm, entityType, entityId, pathParams}, "data": {"_id", ...}}`. The JSON follows the shape of Amster exports but is not validated against a live AM. Client secrets and withheld node settings are never rendered: each environment supplies them. The product profile (`render.PROFILE`) places `am/` and captured `files/am/` under a deployment kit's `config/` (Amster's `import-config --path`); `opsdir-adapter-forgeops` puts them in its amster config profile.

**Not rendered:** entities the record captures as files (below) are written back by the core's captured-file render, not here; nothing per environment (realm settings that differ per environment live in those captured files and their bindings).

## What it reads back

### Amster export: `pingam/amster`

```bash
opsdir import --change CHG-… pingam /path/to/amster-export        # pingam/amster; --dry-run first
```

Reads every Amster entity file (`.json` with `metadata` and `data`) of an `export-config` directory (`amster.py`). A realm's entities are imported only when the record has the realm: an identity service with `pingamRealmPath` equal to the realm's path (whoever serves it). The realms an export mentions are those its entities live in and those its `global/Realms` entities define; each one the record lacks is named and its entities are not imported.

| Amster entity | Recorded | Match key |
|---|---|---|
| `OAuth2Clients` | An `oidc-client` integration registered with the realm (`ciamServedBy`): client ID, redirect URIs, grant types and token endpoint auth method in the standard vocabulary, scopes (AM's `scope\|description` cut to the scope), post-logout redirect URIs. An integration the record already has keeps everything AM doesn't hold (owners, claims, children) | client ID |
| `AuthTree` and the nodes it (and its page nodes) uses | `pingamJourney` (entry node, enabled, other settings) and one `pingamNode` per node (type, display name, outcomes as `outcome=node id`, settings, version from the tree's node map or the node's `_type`, PingAM 8.1+) | realm and tree name; node id |
| `Applications`, `Policies` | `pingamPolicySet` (application type, settings) and its `pingamPolicy` entries (by `applicationName`) | realm and name |
| `global/Realms` | read only for the realms they define | |
| Every other entity (service settings, global or in an imported realm) | A captured config file (configuration domain): `am.<path>` at repository path `am/<path>`, deployed to role `am`, held setting by setting and rebuilt byte for byte | path |

Identity and bookkeeping fields (`_id`, `_rev`, `_type`, `createdBy`, `creationDate`, `lastModifiedBy`, `lastModifiedDate`) and opsdir's own `x-opsdir` annotations are not settings. Values that may be secret are withheld (`pingamWithheld`, JSON Pointers; a rendered node's `x-opsdir.withheld` is kept withheld) and named; client secrets (`userpassword`) are never read. Notices name grant types outside the standard vocabulary (not imported), a client's secret not imported, a node the tree lists with no exported settings, names holding a DN special character (not imported), realms the record doesn't have, and files that aren't Amster entities. The adapter's render reads back unchanged (`reads_back`: `amster` over `am/*`).

### Collecting from PingAM (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter pingam --amster-key PATH` runs Amster's `export-config` and imports its export (`collect.py`, collector `amster`). The environment declares AM's URL (`ciamCollectionSource`: `ciamImporter: pingam/amster`, `ciamSourceRef: https://am.example.test/am`; the first readable source, its first location). The private key Amster signs in with is your existing key file, whose public key AM trusts (`authorized_keys`), given when collecting and never stored. Amster runs a script in a private work directory (`connect <url> -k <key>`, `export-config --path <dir>/export --failOnError`, `:exit`), and the files it writes are the export; the directory is removed after. No transport key is configured, so encrypted passwords are not exported (the importer withholds what it recognizes as secret anyway). Without `--amster-key` it says so and runs nothing; a source's unbound roles are named. Least privilege: Amster's key-based connection signs in as an administrative user (AM's `amAdmin` session): keep the key on the operator's workstation only, its public key trusted only from the addresses collection runs from.

## Schema, vocabulary and secret patterns

Schema under this package's OID arc `1.3.6.1.4.1.32473.3.1` (prefix `pingam`, `schema.py`): 14 attributes; classes `pingamRealm` (auxiliary, on an identity service), `pingamJourney`, `pingamNode`, `pingamPolicySet`, `pingamPolicy`. `pingamRealmPath` is `/` or `/`-separated names of letters, digits, `_` and `-`. Node, tree, set and policy settings are kept as AM writes them (JSON).

Vocabulary it owns: `ciamServerRole` and `ciamTargetRole` value `am`. Secret pattern `am-session-token`: an AM session token (the `iPlanetDirectoryPro` cookie value, `AQIC5` followed by 40 or more characters), refused by the store anywhere in the record. It owns no reference schemes. Formats: `am/*.json` (JSON), and the bases' `saml/*.xml`, `oidc/*.json`.

## Roles, server roles and planner checks

**Required roles**: `subnet-am`, `am-service`, `am-admin-password`, `am-keystore`, `am-ds-bind-password`.

**Server role** `am`:

- **Listener** (ports matrix): HTTPS 8443 for clients (AM's default; the record holds no port for it).
- **Logs** (`logs.py`): the audit service's JSON files `var/audit/*.json` under AM's base directory (JSON lines; events whose `eventName` starts with `AM-ACCESS` are access, the others audit). Debug logs aren't declared: the docs disagree on their directory.
- **Signals** (`signals.py`, at the Prometheus endpoint `/metrics/prometheus/0.0.4` once the Monitoring service's prometheus configuration is enabled): `login-failures`, authentication flows ending in failure per second (`am_authentication_count{outcome="failure"}`).
- **Endpoints** the edge treats specially (`realms.ENDPOINTS`, in any realm): sign-in `/am/json/realms/*/authenticate` (password reset and registration run through it too), token `/am/oauth2/access_token` and `/am/oauth2/realms/*/access_token`, the hosted IdP's SAML posts `/am/SSOPOST/metaAlias/*`, readiness `/am/json/health/ready`.
- **Egress through an explicit proxy** (`proxy.py`): when an environment's egress passes a proxy clients must be told about (a `ciamProxy` with `ciamProxyAddress` that isn't a firewall), AM needs its HTTP client's advanced server properties `org.forgerock.openam.httpclienthandler.system.proxy.uri` (`http://<host>:<port>`, which takes precedence over the JVM's proxy) and `org.forgerock.openam.httpclienthandler.system.nonProxyHosts` (comma-separated), and the standard Java proxy properties in its container's JVM options (`JAVA_OPTS`, setenv.sh) for what doesn't use that client. The record holds neither place, so the planner names what to set. From PingAM 8.1 an Http Client service instance a script opts into can set its own proxy, overriding these.

**Planner check** `check_journeys` (`checks.py`): a journey of a realm AM serves that starts at a node it doesn't have, or whose outcome leads to one (AM's static success and failure nodes end a journey), is a blocker; otherwise one line says every journey is complete.

### Upgrades during a move

A migration may upgrade the product within the supported range. The planner names each server role's version jump, from the oldest version the source runs to the newest the target runs, and every change below that the jump crosses (the source version lacks it, the target's has it), at its effect, when it applies to the record. A target outside the range is a blocker, a downgrade an action. From the vendor's release notes (`versions.py`).

| Since | Change | Effect | Named when |
|---|---|---|---|
| 8.0 | authentication chains and modules are removed (8.0 can re-enable them over REST only, 8.1 not at all) | blocker | the record holds captured Amster chain and module entities (`am/realms/*/AuthenticationChains/`, `*Module/`) |
| 8.0 | the embedded configuration and identity store is removed | info | always |
| 8.0 | the legacy audit event handler is removed | action | the record holds captured audit logging configuration (`am/global/Audit*/`, `am/realms/*/Audit*/`) |
| 8.1 | journey nodes carry versions (Amster exports versioned node folders) | info | the record holds journeys |
| 8.1 | the "Authentication by Module Instance" policy condition is deprecated and evaluates to false | action | the record holds policies with an `AuthScheme` condition |
| 8.1 | the certificate collector and validation nodes validate the full chain by default | action | the record holds journeys with `CertificateCollectorNode` or `CertificateValidationNode` |

## Known limits

- **Not validated against a live AM.** The rendered entities follow the shape of Amster exports; importing them with Amster, and collecting from a real AM, are part of the testing plan (milestone 7.2). The `x-opsdir` block on clients and nodes is opsdir's annotation, not an AM field.
- **Clients**: only the standard registration is rendered (type, name, redirect URIs, scopes, grants, auth method, post-logout URIs); AM's other client settings aren't held, and a client's secret comes from its environment.
- **SAML**: hosted and remote entity providers are rendered as standard metadata only, not as Amster entities.
- **Nothing per environment** is rendered; the listener port is AM's default, not recorded.
- **Least privilege**: Amster signs in as an administrative user; whether a less-privileged Amster account suffices is open for live validation (7.2).

## Tests

`tests/test_pingam.py`: registration and applies from the servers' products; clients as standard integrations registered with their realm; journeys holding every node with its outcomes and secrets withheld; policy sets without bookkeeping; other entities captured and unknown realms named; importing again changing nothing; the render as Amster entities and standard documents at AM's paths, reading back unchanged; a journey leading to a node it doesn't have blocked; an 8.1 node version held and rendered back; what an upgrade to AM 8 touches. `tests/test_pingam_collect.py` (Amster's export in a private directory with the operator's key; without the key nothing runs), `tests/test_pingam_listeners.py`, `tests/test_pingam_proxy.py`. `tests/amster-export/` is a made-up export (fictional `example.test` names).

`tests/test_pingam_store.py` (marker `integration`, Postgres via `OPSDIR_TEST_DSN`): an export imported under an approved change, the store accepting every entry, nothing secret stored, a re-import changing nothing.

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-pingam/tests
opsdir/.venv/bin/python -m pytest -m integration packages/opsdir-adapter-pingam/tests
```

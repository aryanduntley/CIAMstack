# opsdir-adapter-pinggateway

opsdir adapter for PingGateway (ForgeRock Identity Gateway): the routes that protect applications, rendered for each environment from the record and read back from a gateway configuration directory (saved, or collected from Git or a ConfigMap).

**Applies to** environments where PingGateway or ForgeRock Identity Gateway runs: a server, or a Kubernetes workload's binding, whose `ciamProductVersion` starts with `PingGateway` or `ForgeRock Identity Gateway` (`runs_product`). Supported: PingGateway `>=2023,<2027`, ForgeRock Identity Gateway `>=7,<8`. A product adapter: it defines the server role `ig` and declares it for the kits that deploy it, which find it by product (`Adapter.roles`: server `ig`). What depends on the version follows the servers' recorded `ciamProductVersion` (none recorded: the newest release).

**Depends on** `opsdir` only. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pinggateway`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## What it renders

Per environment (`render.py`); nothing environment-neutral.

| From the record | Rendered as |
|---|---|
| Each route (`pinggwRoute` under `ou=routes,ou=pinggateway`): its name, condition (`pinggwCondition`), handler chain and other settings (`pinggwConfig`, secrets withheld) | `pinggateway/routes/<name>.json` |
| The route's backend role (`pinggwBackendRole`) and scheme (`pinggwBackendScheme`, default `https`) | its `baseURI`: `<scheme>://<the role's binding's ciamFqdn>[:<its ciamPort>]` (a port left out when it is the scheme's default), `UNBOUND:<role>` where the environment binds none (or the binding has no `ciamFqdn`) |

A route with no backend role keeps the `baseURI` it was imported with: a fixed backend. Withheld values are rendered as opsdir's in-place placeholders. The gateway's own settings (`config/config.json`, `admin.json`) are captured config files, rendered with the environment's other captured files. The product profile (`render.PROFILE`) places `pinggateway/routes/` under a deployment kit's `config/routes/` and captured `files/pinggateway/` at the instance root. The routes follow the gateway's JSON but are not validated against a live gateway.

### Applications the gateways take over (`takeover.py`)

The neutral protected-application layer (core domain `webaccess`; opsdir's README, Protected web applications) holds
what any product protects. An environment can have its gateways enforce an application another product (or an operator)
recorded: its override of the application's `ciamEnforcedByRole` is `ig`. PingGateway then renders a route for it,
`pinggateway/routes/<application>.json`:
- **condition**: the hosts of its published service names and its base path (`^<base>(?:/|$)`);
- **baseURI**: from its backend role;
- **session**: `JwtSessionManager`, with the idle limit as the session timeout;
- **chain**:
  - an `AuthorizationCodeOAuth2ClientFilter` for its integration's client id and the issuer of the identity service
    serving it, inside a `ConditionalFilter` skipping its anonymous and unprotected paths;
  - an `AllowOnlyFilter` with each path resource as a rule (paths as regular expressions, methods);
  - a `ConditionEnforcementFilter` per access rule (a claim test on `contexts.oauth2Info.userInfo`, `not()` for a
    denial; a resource's inside a `ConditionalFilter` on its paths);
  - a `HeaderFilter` (`REQUEST`, `replace`, so the client's own copy goes) for the header contracts it sets;
  - then `ReverseProxyHandler`.

A route projected from an application another role enforces in the environment is left out of its render there. What
PingGateway can't express is a render note for the application's owners:
- a rule it can't test (a directory group, user, filter, scope or network) is a **blocker**: rendered without it, the
  route admits more than the record says;
- the maximum session lifetime (PingGateway has one session timeout) is an action;
- so is the client secret, read from the gateway's secrets provider (the note names the credential role's
  reference).

The routes' listeners include the taken-over applications' backends. The read-back of a render leaves taken-over routes
out (`takeover.own_routes`): read, they would become the gateway's own routes, which is what a cutover does. The plan's
`protect:pinggateway/<application>` fix writes the target's override for an application nothing there would protect.

## What it reads back

### Gateway configuration: `pinggateway/config`

```bash
opsdir import --change CHG-… pinggateway CONFIG_DIR       # pinggateway/config; --dry-run first
```

Reads a gateway configuration directory (`gateway.py`):

| Files | Recorded | Match key |
|---|---|---|
| `routes/*.json` | `pinggwRoute`, named by the route's `name` (else its file name): its condition; a `baseURI` whose host is a service name in the record (or a rendered `UNBOUND:<role>`) becomes that binding's role (`pinggwBackendRole`, with its scheme) and leaves the settings; the OAuth 2.0 client its client filter signs users in as (`AuthorizationCodeOAuth2ClientFilter`, or IG 7's `OAuth2ClientFilter`, anywhere in its chain) linked to the integration with that client ID (`pinggwIntegration`); the first OpenID provider it trusts (an `issuer` or `wellKnownEndpoint` URL, the well-known suffix removed) as `pinggwIssuer`; the rest as `pinggwConfig`, values that may be secret withheld (`pinggwWithheld`) | name |
| `config/*.json` | captured config files (configuration domain): `ig.<path>` at repository path `pinggateway/<path>`, deployed to role `ig` | path |

The importer owns what it reads; what the record adds to a route (owners) is kept. Notices name a client ID no integration has, a route trusting more than one OpenID provider (the first is recorded), a backend that is no service name (the route goes to the same place from every environment), routes that aren't JSON, names with a DN special character (not imported), and files outside `routes/` and `config/`. The adapter's render reads back unchanged (`reads_back`: `config` over `pinggateway/*`).

Each route is also projected onto the neutral protected-application layer (`neutral.py`; `ciamProjectedFrom` names the route), as an application enforced by `ig`:
- the base path comes from a literal `request.uri.path` test in its condition (else `/`, and a notice);
- it is published as the service name of its condition's host test;
- its backend role and scheme;
- sign-on `oidc` through the integration its client filter signs in as, served by the identity service of the issuer it trusts;
- its session manager's timeout is the idle limit;
- the header contracts of the headers its `HeaderFilter`s set.

Its resources are each `AllowOnlyFilter` rule (else one, every path), and the paths a `ConditionalFilter` keeps the sign-in from (anonymous). Its `ConditionEnforcementFilter`s become access rules `<route>-<n>`: a claim test an attribute test, `not()` a denial, anything else custom.

### Collecting (`opsdir collect`)

The adapter declares no collector of its own: its configuration is collected through the core's configuration sources, once the estate setting `collect-from-git` (or `collect-from-kubernetes`) is on. A collection source with `ciamImporter: pinggateway/config` and `ciamSourceRef: git+https://host/org/repo.git?ref=main&dir=<the directory holding config/ and routes/>` (a shallow clone, with the operator's own Git credentials), or a ConfigMap of routes (`k8s://<context>/<namespace>/configmap/<name>?prefix=routes/`, never Secrets), is read by `opsdir collect --env CLOUD/ENV --adapter pinggateway/config` and imported like the saved directory. The showcase's end-to-end test proves a clone gives the same import as the saved directory (`examples/showcase/tests/unit/test_collected_sources.py`). In production mode the gateway serves no routes over its REST interface, so there is no API to read them from.

## Schema, vocabulary and secret patterns

Schema under this package's OID arc `1.3.6.1.4.1.32473.3.3` (prefix `pinggw`, `schema.py`): attributes `pinggwCondition`, `pinggwBackendRole`, `pinggwBackendScheme` (`http`, `https`), `pinggwIntegration`, `pinggwIssuer` (a contract), `pinggwConfig`, `pinggwWithheld`; class `pinggwRoute`.

Vocabulary it owns: `ciamServerRole` and `ciamTargetRole` value `ig`. It owns no reference schemes and no secret patterns. Format: `pinggateway/routes/*.json` (JSON).

## Roles, server roles and planner checks

**Required roles**: `subnet-ig`, `ig-service`, `ig-keystore`.

**Server role** `ig`:

- **Listeners** (ports matrix, `listeners.py`): HTTPS 8443 for clients (the estate's convention: the product's default connector is 8080; the record holds no port for it); from 2025.3 the admin connector 8085 (admin endpoints and health checks); and the ports its routes reach on the applications behind service names.
- **Logs** (`logs.py`): `logs/route-system.log` under the instance directory (`$HOME/.openig` unless `start.sh` is given another), text. Audit files are written only where a route's audit service names a directory, so none are declared.
- **Endpoints** the edge treats specially (`naming.ENDPOINTS`): the health check, by version: `/openig/ping` on the client port before 2025.3, `/ping` from 2025.3 and `/health/startup` from 2025.6, both on the admin port 8085 (`Endpoint.port`), so the provider adapters that render load balancer health checks probe it there.
- **Egress through an explicit proxy** (`proxy.py`): when an environment's egress passes a proxy clients must be told about (a `ciamProxy` with `ciamProxyAddress` that isn't a firewall), PingGateway needs `config.json`'s heap object named `ProxyOptions` (the default of every `ClientHandler` and `ReverseProxyHandler`) as `SystemProxyOptions`, and the standard Java proxy properties in the JVM options it starts with. The JVM's proxy is used, not a `CustomProxyOptions` URI, because only it honours the hosts reached directly: the routes' own backends stay off the proxy. The record can't confirm either, so the planner names what to set.

**Planner check** `check_routes` (`checks.py`):

| Reports | Fix offered |
|---|---|
| Blocker: a route signing users in as a client ID no integration in the record has, or trusting an OpenID provider that is no identity service's `ciamOidcIssuer` | |
| Blocker: a route whose backend role the target doesn't bind | |
| Action: a route to a fixed backend (a `baseURI`, no backend role) | `external-host:route/<name>`: record the base URI's host (and port) as the source's `ciamExternalHost` of a role you give, so the next import names the role |

Otherwise one line says every route signs users in with clients and OpenID providers the record has.

### Upgrades during a move

A migration may upgrade the product within the supported range. The planner names each server role's version jump, from the oldest version the source runs to the newest the target runs, and every change below that the jump crosses (the source version lacks it, the target's has it), at its effect, when it applies to the record. A target outside the range is a blocker, a downgrade an action. From the vendor's release notes (`versions.py`).

| Since | Change | Effect | Named when |
|---|---|---|---|
| 7.2 | OAuth2ClientFilter is renamed AuthorizationCodeOAuth2ClientFilter | action | routes holding an `OAuth2ClientFilter` |
| 2023.6 | scripts load only from absolute paths or the base script directory | action | routes holding a `ScriptableFilter`, `ScriptableHandler` or `ScriptableThrottlingPolicy` |
| 2024.3 | inline heap objects can no longer be referenced by name, and objects that use secrets need a secretsProvider | info | always |
| 2025.3 | the admin endpoints move to the admin port 8085 without the /openig prefix (/ping; /health/startup from 2025.6) | info | always |
| 2025.3 | issuer repositories default to the new behaviour (useDeprecatedIssuerRepository false) | info | routes holding an `Issuer` or `IssuerRepository` |
| 2026.3 | the Docker image's directories move (/opt/ig to /opt/gateway, /var/ig to /var/gateway), the admin session cookie is IG_ADMIN_SESSIONID, and invalid configuration or routes fail startup | info | always |
| 2026.9 | ClientHandler and ReverseProxyHandler use HTTP/2 when protocolVersion is unset | action | routes whose `ClientHandler` or `ReverseProxyHandler` sets no `protocolVersion` (a backend speaking only HTTP/1.1 needs `"protocolVersion": "HTTP/1.1"`) |
| 2026.9 | UmaService resource actions require scopes | action | routes holding an `UmaService` |

## Known limits

- **Not validated against a live gateway.** The rendered routes follow the gateway's JSON; running them in a gateway is part of the testing plan (milestone 7.2).
- **One OpenID provider per route** is recorded (`pinggwIssuer`, the first found); the planner still checks every one the route's settings name.
- **Routes only** are modeled; the gateway's own settings are captured files, scripts are bundles.
- **The client listener** (8443) is the estate's convention, not recorded.

- **The neutral layer's forms follow PingGateway's 2026 reference, unverified against a running gateway** (research note 3133; deferred note on `routes.py`):
  - the `AllowOnlyFilter` page marks `from` required while its own example omits it, and calls a path a prefix while its example is a regex;
  - the sign-in's claims are a map in Ping's examples and an array of maps in the context reference;
  - the session managers' one timeout is taken as the idle limit;
  - the takeover route's registration reads its client secret from `SystemAndEnvSecretStore-1`.

## Tests

`tests/test_pinggateway.py`: registration and applies from the servers' products; a route naming its backend role, client and provider; a route to an unknown host keeping it and saying so; routes rendered per environment and read back unchanged; the planner's findings; what an upgrade touches in the routes. `tests/test_pinggateway_listeners.py` (HTTPS, the admin connector from 2025.3, what the routes reach, the health endpoint by version), `tests/test_pinggateway_proxy.py`. `tests/gateway-config/` is a made-up configuration. The collection from Git is tested end to end in the showcase (`examples/showcase/tests/unit/test_collected_sources.py`).

`tests/test_pinggateway_store.py` (marker `integration`, Postgres via `OPSDIR_TEST_DSN`): a configuration imported under an approved change, a re-import changing nothing.

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-pinggateway/tests
opsdir/.venv/bin/python -m pytest -m integration packages/opsdir-adapter-pinggateway/tests
```

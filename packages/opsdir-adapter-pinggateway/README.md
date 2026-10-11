# opsdir-adapter-pinggateway

opsdir adapter for PingGateway (ForgeRock Identity Gateway): the routes that protect applications, rendered for each environment from the record and imported from a gateway configuration directory.

- **Routes as entries** (`ou=routes,ou=pinggateway`, this package's schema, OID arc `1.3.6.1.4.1.32473.3.3`): the condition a route handles, the gateway's own JSON for its handler chain (secrets withheld), and what it depends on: the binding role of the application it protects (`pinggwBackendRole`), the integration whose client it signs users in as (`pinggwIntegration`, the standard layer) and the OpenID provider it trusts (`pinggwIssuer`, a contract).
- **Render** (per environment): `pinggateway/routes/<name>.json`, the backend address from the environment's binding of the route's backend role. The gateway's own settings (`config/config.json`, `admin.json`) are captured config files, rendered with the environment's other captured files.
- **Import**: `opsdir import --change CHG-… pinggateway CONFIG_DIR` reads `routes/` and `config/`: a backend host that is a service name in the record becomes that role; client ids are matched to integrations and providers recorded. **Collected from Git** (`opsdir collect --env CLOUD/ENV --adapter pinggateway/config`, estate setting `collect-from-git` on): a collection source with `ciamImporter: pinggateway/config` and `ciamSourceRef: git+https://host/org/repo.git?ref=main&dir=<the directory holding config/ and routes/>` (or a ConfigMap of routes, `k8s://…?prefix=routes/`); the showcase's end-to-end test proves a clone gives the same import as the saved directory (`examples/showcase/tests/unit/test_collected_sources.py`).
- **Planner check**: a route whose backend role the target doesn't bind, or whose client or OpenID provider the record doesn't have, is a blocker; a route to a fixed backend is an action, with a fix (`external-host:route/<name>`) that records the base URI's host (and port) as the source's `ciamExternalHost` of a role you give, so the next import names the role.
- **Required roles**: `subnet-ig`, `ig-service`, `ig-keystore`. Server role: `ig`. Products: PingGateway 2023–2026 (current release 2026.9.0), ForgeRock Identity Gateway 7.
- **By version** (the servers' recorded `ciamProductVersion`; none recorded: the newest release): the health endpoint the edge probes is `/openig/ping` on the client port before 2025.3, `/ping` from 2025.3 and `/health/startup` from 2025.6, both on the admin connector, port 8085 (`Endpoint.port`): the cloud renderers point their load balancers' health checks there and admit them (AWS target groups and their security group rules, Azure load balancer and Application Gateway probes, Google Cloud health checks and their firewall rules; Front Door can't probe it through its origin: a comment). The ports matrix lists the admin connector (8085) for 2025.3+. The client listener (8443) is the estate's convention; the product's default connector is 8080. From 2026.9 `ClientHandler` and `ReverseProxyHandler` default to HTTP/2: a backend speaking only HTTP/1.1 needs `"protocolVersion": "HTTP/1.1"` on its handler. Route filters are read under both names, `AuthorizationCodeOAuth2ClientFilter` and IG 7's `OAuth2ClientFilter`.

The routes follow the gateway's JSON but are not yet validated against a live gateway. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pinggateway`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## Egress through an explicit proxy

When an environment's egress passes a proxy clients must be told about (a `ciamProxy` with `ciamProxyAddress` that isn't a firewall), PingGateway needs `config.json`'s heap object named `ProxyOptions` (the default of every `ClientHandler` and `ReverseProxyHandler`) as `SystemProxyOptions`, and the standard Java proxy properties in the JVM options it starts with. The JVM's proxy is used, not a `CustomProxyOptions` URI, because only it honours the hosts reached directly: the routes' own backends stay off the proxy. The record can't confirm either, so the planner names what to set.

## Upgrades during a move

A migration may upgrade the product within the supported range (PingGateway `>=2023,<2027`, ForgeRock Identity Gateway `>=7,<8`). The planner names each server role's version jump, from the oldest version the source runs to the newest the target runs, and every change below that the jump crosses (the source version lacks it, the target's has it), at its effect, when it applies to the record. A target outside the range is a blocker, a downgrade an action. From the vendor's release notes (`versions.py`).

| Since | Change | Effect | Named when |
|---|---|---|---|
| 7.2 | OAuth2ClientFilter is renamed AuthorizationCodeOAuth2ClientFilter | action | the record holds routes' OAuth 2.0 client filters |
| 2023.6 | scripts load only from absolute paths or the base script directory | action | the record holds routes' scriptable filters and handlers |
| 2024.3 | inline heap objects can no longer be referenced by name, and objects that use secrets need a secretsProvider | note | always |
| 2025.3 | the admin endpoints move to the admin port 8085 without the /openig prefix (/ping; /health/startup from 2025.6) | note | always |
| 2025.3 | issuer repositories default to the new behaviour (useDeprecatedIssuerRepository false) | note | the record holds routes trusting an OpenID provider |
| 2026.3 | the Docker image's directories move (/opt/ig to /opt/gateway, /var/ig to /var/gateway), the admin session cookie is IG_ADMIN_SESSIONID, and invalid configuration or routes fail startup | note | always |
| 2026.9 | ClientHandler and ReverseProxyHandler use HTTP/2 when protocolVersion is unset | action | the record holds routes' backend handlers |
| 2026.9 | UmaService resource actions require scopes | action | the record holds routes with an UmaService |

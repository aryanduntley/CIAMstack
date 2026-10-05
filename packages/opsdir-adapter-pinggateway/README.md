# opsdir-adapter-pinggateway

opsdir adapter for PingGateway (ForgeRock Identity Gateway): the routes that protect applications, rendered for each environment from the record and imported from a gateway configuration directory.

- **Routes as entries** (`ou=routes,ou=pinggateway`, this package's schema, OID arc `1.3.6.1.4.1.32473.3.3`): the condition a route handles, the gateway's own JSON for its handler chain (secrets withheld), and what it depends on: the binding role of the application it protects (`pinggwBackendRole`), the integration whose client it signs users in as (`pinggwIntegration`, the standard layer) and the OpenID provider it trusts (`pinggwIssuer`, a contract).
- **Render** (per environment): `pinggateway/routes/<name>.json`, the backend address from the environment's binding of the route's backend role. The gateway's own settings (`config/config.json`, `admin.json`) are captured config files, rendered with the environment's other captured files.
- **Import**: `opsdir import --change CHG-… pinggateway CONFIG_DIR` reads `routes/` and `config/`: a backend host that is a service name in the record becomes that role; client ids are matched to integrations and providers recorded.
- **Planner check**: a route whose backend role the target doesn't bind, or whose client or OpenID provider the record doesn't have, is a blocker; a route to a fixed backend is an action, with a fix (`external-host:route/<name>`) that records the base URI's host (and port) as the source's `ciamExternalHost` of a role you give, so the next import names the role.
- **Required roles**: `subnet-ig`, `ig-service`, `ig-keystore`. Server role: `ig`. Products: PingGateway 2023–2026, ForgeRock Identity Gateway 7.

The routes follow the gateway's JSON but are not yet validated against a live gateway. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pinggateway`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## Egress through an explicit proxy

When an environment's egress passes a proxy clients must be told about (a `ciamProxy` with `ciamProxyAddress` that isn't a firewall), PingGateway needs `config.json`'s heap object named `ProxyOptions` (the default of every `ClientHandler` and `ReverseProxyHandler`) as `SystemProxyOptions`, and the standard Java proxy properties in the JVM options it starts with. The JVM's proxy is used, not a `CustomProxyOptions` URI, because only it honours the hosts reached directly: the routes' own backends stay off the proxy. The record can't confirm either, so the planner names what to set.


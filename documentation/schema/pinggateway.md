# PingGateway (opsdir-adapter-pinggateway)

*Package · OID arc `1.3.6.1.4.1.32473.3.3` · 1 object classes · 7 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

PingGateway schema fragment, under this package's own OID arc: the gateway's routes. A route keeps its settings as the gateway writes them (JSON, secrets withheld); what differs per environment is not in them: the route names the binding role of the application it protects, and each environment renders its own backend address.

## Object classes

<a id="c-pinggwroute"></a>
### pinggwRoute

A gateway route: which requests it handles, how it protects them, where it sends them

OID `1.3.6.1.4.1.32473.3.3.2.1` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pinggwCondition`](#a-pinggwcondition) |  | `string` | single | When the route handles a request (the gateway expression) |
| [`pinggwBackendRole`](#a-pinggwbackendrole) |  | `string` | single | The binding role of the application the route protects: each environment renders its address |
| [`pinggwBackendScheme`](#a-pinggwbackendscheme) |  | `enum` | single | How the gateway reaches the application |
| [`pinggwIntegration`](#a-pinggwintegration) |  | `dn` | single | The integration whose client the route signs users in as (its OAuth 2.0 client filter) |
| [`pinggwIssuer`](#a-pinggwissuer) |  | `url` | single | The OpenID provider the route trusts (issuer or well-known URL) |
| [`pinggwConfig`](#a-pinggwconfig) |  | `json` | single | The route's other settings, as the gateway writes them (values that may be secret withheld) |
| [`pinggwWithheld`](#a-pinggwwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-pinggwbackendrole"></a>`pinggwBackendRole` | `1.3.6.1.4.1.32473.3.3.1.2` | `string` | intent | single |  | The binding role of the application the route protects: each environment renders its address |
| <a id="a-pinggwbackendscheme"></a>`pinggwBackendScheme` | `1.3.6.1.4.1.32473.3.3.1.3` | enum: `http`, `https` | intent | single |  | How the gateway reaches the application |
| <a id="a-pinggwcondition"></a>`pinggwCondition` | `1.3.6.1.4.1.32473.3.3.1.1` | `string` | intent | single |  | When the route handles a request (the gateway expression) |
| <a id="a-pinggwconfig"></a>`pinggwConfig` | `1.3.6.1.4.1.32473.3.3.1.6` | `json` | intent | single |  | The route's other settings, as the gateway writes them (values that may be secret withheld) |
| <a id="a-pinggwintegration"></a>`pinggwIntegration` | `1.3.6.1.4.1.32473.3.3.1.4` | `dn` | intent | single |  | The integration whose client the route signs users in as (its OAuth 2.0 client filter) |
| <a id="a-pinggwissuer"></a>`pinggwIssuer` | `1.3.6.1.4.1.32473.3.3.1.5` | `url` | contract | single |  | The OpenID provider the route trusts (issuer or well-known URL) |
| <a id="a-pinggwwithheld"></a>`pinggwWithheld` | `1.3.6.1.4.1.32473.3.3.1.7` | `string` | meta | multi |  | Settings withheld at import because they may be secret (JSON Pointer) |

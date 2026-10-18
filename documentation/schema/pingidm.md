# PingIDM (opsdir-adapter-pingidm)

*Package · OID arc `1.3.6.1.4.1.32473.3.2` · 4 object classes · 14 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

PingIDM schema fragment, under this package's own OID arc: an IDM deployment's managed objects, connectors, sync mappings and schedules. Settings are kept as IDM writes them (JSON), with values that may be secret withheld; what differs per environment is not in them: a connector names the binding role of the system it connects to and the secret role of its credentials, and each environment renders its own host and secret reference.

## Object classes

<a id="c-pingidmconnector"></a>
### pingidmConnector

A connector (provisioner) to a system IDM reads or writes

OID `1.3.6.1.4.1.32473.3.2.2.2` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingidmConnectorName`](#a-pingidmconnectorname) | yes | `string` | single | The connector's implementation (connectorRef.connectorName) |
| [`pingidmBundle`](#a-pingidmbundle) |  | `string` | single | The connector bundle (connectorRef.bundleName) |
| [`pingidmBundleVersion`](#a-pingidmbundleversion) |  | `string` | single | The bundle versions the connector accepts (connectorRef.bundleVersion) |
| [`pingidmTargetRole`](#a-pingidmtargetrole) |  | `string` | single | The binding role of the system the connector reaches: each environment renders its host from it |
| [`pingidmPort`](#a-pingidmport) |  | `int` | single | The port a connector reaches its target role on, when its hosts are in a JDBC URL |
| [`pingidmCredentialRole`](#a-pingidmcredentialrole) |  | `string` | single | The secret role holding the connector credentials: each environment renders its reference |
| [`pingidmConsumer`](#a-pingidmconsumer) |  | `dn` | single | The directory consumer record of the account the connector binds as |
| [`pingidmConfig`](#a-pingidmconfig) |  | `json` | single | The other settings, as IDM writes them (values that may be secret withheld) |
| [`pingidmWithheld`](#a-pingidmwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |

<a id="c-pingidmmanagedobject"></a>
### pingidmManagedObject

A managed object type (user, role, ...)

OID `1.3.6.1.4.1.32473.3.2.2.1` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingidmPosition`](#a-pingidmposition) | yes | `int` | single | Its place in the file IDM keeps it in (managed.json objects, sync.json mappings) |
| [`pingidmSchema`](#a-pingidmschema) |  | `json` | single | A managed object's schema, as IDM writes it |
| [`pingidmConfig`](#a-pingidmconfig) |  | `json` | single | The other settings, as IDM writes them (values that may be secret withheld) |
| [`pingidmWithheld`](#a-pingidmwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |

<a id="c-pingidmmapping"></a>
### pingidmMapping

A sync mapping: properties, situations and policies from a source to a target

OID `1.3.6.1.4.1.32473.3.2.2.3` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingidmPosition`](#a-pingidmposition) | yes | `int` | single | Its place in the file IDM keeps it in (managed.json objects, sync.json mappings) |
| [`pingidmSource`](#a-pingidmsource) | yes | `string` | single | A mapping's source (system/<connector>/<type>, managed/<object>) |
| [`pingidmTarget`](#a-pingidmtarget) | yes | `string` | single | A mapping's target |
| [`pingidmConfig`](#a-pingidmconfig) |  | `json` | single | The other settings, as IDM writes them (values that may be secret withheld) |
| [`pingidmWithheld`](#a-pingidmwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |

<a id="c-pingidmschedule"></a>
### pingidmSchedule

A schedule (reconciliation, a script, ...)

OID `1.3.6.1.4.1.32473.3.2.2.4` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingidmEnabled`](#a-pingidmenabled) |  | `bool` | single | Whether the schedule runs |
| [`pingidmConfig`](#a-pingidmconfig) |  | `json` | single | The other settings, as IDM writes them (values that may be secret withheld) |
| [`pingidmWithheld`](#a-pingidmwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-pingidmbundle"></a>`pingidmBundle` | `1.3.6.1.4.1.32473.3.2.1.5` | `string` | intent | single |  | The connector bundle (connectorRef.bundleName) |
| <a id="a-pingidmbundleversion"></a>`pingidmBundleVersion` | `1.3.6.1.4.1.32473.3.2.1.6` | `string` | intent | single |  | The bundle versions the connector accepts (connectorRef.bundleVersion) |
| <a id="a-pingidmconfig"></a>`pingidmConfig` | `1.3.6.1.4.1.32473.3.2.1.3` | `json` | intent | single |  | The other settings, as IDM writes them (values that may be secret withheld) |
| <a id="a-pingidmconnectorname"></a>`pingidmConnectorName` | `1.3.6.1.4.1.32473.3.2.1.4` | `string` | intent | single |  | The connector's implementation (connectorRef.connectorName) |
| <a id="a-pingidmconsumer"></a>`pingidmConsumer` | `1.3.6.1.4.1.32473.3.2.1.9` | `dn` | meta | single |  | The directory consumer record of the account the connector binds as |
| <a id="a-pingidmcredentialrole"></a>`pingidmCredentialRole` | `1.3.6.1.4.1.32473.3.2.1.8` | `string` | intent | single |  | The secret role holding the connector credentials: each environment renders its reference |
| <a id="a-pingidmenabled"></a>`pingidmEnabled` | `1.3.6.1.4.1.32473.3.2.1.13` | `bool` | intent | single |  | Whether the schedule runs |
| <a id="a-pingidmport"></a>`pingidmPort` | `1.3.6.1.4.1.32473.3.2.1.14` | `int` | intent | single | X-MIN `1`; X-MAX `65535` | The port a connector reaches its target role on, when its hosts are in a JDBC URL |
| <a id="a-pingidmposition"></a>`pingidmPosition` | `1.3.6.1.4.1.32473.3.2.1.1` | `int` | intent | single | X-MIN `0` | Its place in the file IDM keeps it in (managed.json objects, sync.json mappings) |
| <a id="a-pingidmschema"></a>`pingidmSchema` | `1.3.6.1.4.1.32473.3.2.1.2` | `json` | intent | single |  | A managed object's schema, as IDM writes it |
| <a id="a-pingidmsource"></a>`pingidmSource` | `1.3.6.1.4.1.32473.3.2.1.11` | `string` | intent | single |  | A mapping's source (system/<connector>/<type>, managed/<object>) |
| <a id="a-pingidmtarget"></a>`pingidmTarget` | `1.3.6.1.4.1.32473.3.2.1.12` | `string` | intent | single |  | A mapping's target |
| <a id="a-pingidmtargetrole"></a>`pingidmTargetRole` | `1.3.6.1.4.1.32473.3.2.1.7` | `string` | intent | single |  | The binding role of the system the connector reaches: each environment renders its host from it |
| <a id="a-pingidmwithheld"></a>`pingidmWithheld` | `1.3.6.1.4.1.32473.3.2.1.10` | `string` | meta | multi |  | Settings withheld at import because they may be secret (JSON Pointer) |

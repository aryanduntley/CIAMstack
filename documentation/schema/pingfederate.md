# PingFederate (opsdir-adapter-pingfederate)

*Package · OID arc `1.3.6.1.4.1.32473.3.4` · 14 object classes · 24 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

PingFederate schema fragment, under this package's own OID arc: PingFederate's own configuration objects, beyond what the standard bases describe (integrations, certificates and identity services are the federation and PKI domains'): data stores, plugin instances (validators, adapters, selectors, access token managers), authentication policy contracts, policies and fragments, OIDC policies, settings resources (the authorization server's). Each object keeps its settings as the Admin API writes them (JSON), with values that may be secret withheld; what differs per environment is not in them: an object names the binding role of the system it reaches and the secret role of its credentials, and each environment renders its own hosts and secret references.

## Object classes

<a id="c-pingfedauthpolicy"></a>
### pingfedAuthPolicy

An authentication policy tree (cn: its name), or a policy fragment (cn: its id)

OID `1.3.6.1.4.1.32473.3.4.2.5` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingfedPolicyTree`](#a-pingfedpolicytree) | yes | `json` | single | The policy's tree as PingFederate writes it (rootNode: each node's action and its children, by the result that leads to them) |
| [`pingfedPosition`](#a-pingfedposition) |  | `int` | single | Its place in the list PingFederate keeps it in (authentication policy trees) |
| [`pingfedEnabled`](#a-pingfedenabled) |  | `bool` | single | Whether the authentication policy tree is used |
| [`pingfedUses`](#a-pingfeduses) |  | `dn` | multi | PingFederate objects the settings name: a validator's data store, an adapter's validators, the adapters, selectors, contracts and fragments a policy runs |
| [`pingfedConfig`](#a-pingfedconfig) |  | `json` | single | The other settings, as the Admin API writes them (values that may be secret withheld) |
| [`pingfedSourceVersion`](#a-pingfedsourceversion) |  | `string` | single | The PingFederate version the object's settings were exported from (the bulk export's pfVersion): a render for another version names what changed between the two |

<a id="c-pingfedauthpolicyset"></a>
### pingfedAuthPolicySet

The authentication policies' own settings (cn: default): its trees are its children

OID `1.3.6.1.4.1.32473.3.4.2.4` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingfedConfig`](#a-pingfedconfig) |  | `json` | single | The other settings, as the Admin API writes them (values that may be secret withheld) |
| [`pingfedSourceVersion`](#a-pingfedsourceversion) |  | `string` | single | The PingFederate version the object's settings were exported from (the bulk export's pfVersion): a render for another version names what changed between the two |

<a id="c-pingfedclient"></a>
### pingfedClient

An OAuth client of PingFederate: the token manager and OIDC policy it is issued tokens by

OID `1.3.6.1.4.1.32473.3.4.2.10` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`pingfedUses`](#a-pingfeduses) |  | `dn` | multi | PingFederate objects the settings name: a validator's data store, an adapter's validators, the adapters, selectors, contracts and fragments a policy runs |

<a id="c-pingfedclusterdiscovery"></a>
### pingfedClusterDiscovery

Where an environment's PingFederate nodes find each other (role pf-cluster-discovery): the protocol chosen, and the bucket (NATIVE_S3_PING) or DNS name (DNS_PING) it needs; TCPPING needs neither

OID `1.3.6.1.4.1.32473.3.4.2.13` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`pingfedDiscoveryProtocol`](#a-pingfeddiscoveryprotocol) | yes | `vocab` | single | The JGroups discovery protocol an environment's PingFederate nodes find each other with, chosen per environment from the protocols the adapter renders (TCPPING, NATIVE_S3_PING, DNS_PING) |
| [`ciamStorageRef`](infrastructure.md#a-ciamstorageref) |  | `string` | single | Object storage location (bucket or container URI, e.g. s3://bucket, azblob://account/container, gs://bucket) |
| [`ciamFqdn`](infrastructure.md#a-ciamfqdn) |  | `fqdn` | single | Service DNS name consumers and partners use. Must stay stable across migrations |

<a id="c-pingfedconnection"></a>
### pingfedConnection

An integration that is a PingFederate partner connection (an IdP connection): the id policies name it by

OID `1.3.6.1.4.1.32473.3.4.2.6` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`pingfedConnectionId`](#a-pingfedconnectionid) | yes | `string` | single | The id PingFederate knows a partner connection by: what its authentication policies name |

<a id="c-pingfeddatastore"></a>
### pingfedDataStore

A data store PingFederate reads users or keeps state in (cn: its id): a directory, a database, a custom store

OID `1.3.6.1.4.1.32473.3.4.2.1` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingfedStoreType`](#a-pingfedstoretype) | yes | `string` | single | The data store's type, as PingFederate names it (LDAP, JDBC, CUSTOM) |
| [`pingfedTargetRole`](#a-pingfedtargetrole) |  | `string` | single | The binding role of the service the object reaches: each environment renders its host from it |
| [`pingfedPort`](#a-pingfedport) |  | `int` | single | The port the object reaches its target role on |
| [`pingfedCredentialRole`](#a-pingfedcredentialrole) |  | `string` | single | The secret role holding the credentials: each environment renders its reference |
| [`pingfedConsumer`](#a-pingfedconsumer) |  | `dn` | single | The directory consumer record of the account the object binds to the directory as |
| [`pingfedConfig`](#a-pingfedconfig) |  | `json` | single | The other settings, as the Admin API writes them (values that may be secret withheld) |
| [`pingfedWithheld`](#a-pingfedwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |
| [`pingfedSourceVersion`](#a-pingfedsourceversion) |  | `string` | single | The PingFederate version the object's settings were exported from (the bulk export's pfVersion): a render for another version names what changed between the two |

<a id="c-pingfedheldsettings"></a>
### pingfedHeldSettings

An integration (SP connection, IdP connection, OAuth client) with PingFederate's own settings held as the Admin API writes them (secrets withheld): rendered back with the record's standard facts in place

OID `1.3.6.1.4.1.32473.3.4.2.14` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`pingfedConfig`](#a-pingfedconfig) |  | `json` | single | The other settings, as the Admin API writes them (values that may be secret withheld) |
| [`pingfedWithheld`](#a-pingfedwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |
| [`pingfedCredentialRole`](#a-pingfedcredentialrole) |  | `string` | single | The secret role holding the credentials: each environment renders its reference |
| [`pingfedSourceVersion`](#a-pingfedsourceversion) |  | `string` | single | The PingFederate version the object's settings were exported from (the bulk export's pfVersion): a render for another version names what changed between the two |

<a id="c-pingfedkeypair"></a>
### pingfedKeyPair

A certificate of one of PingFederate's own key pairs: the id its token managers name it by

OID `1.3.6.1.4.1.32473.3.4.2.7` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`pingfedKeyPairId`](#a-pingfedkeypairid) | yes | `string` | single | The id PingFederate knows one of its key pairs by: what its token managers sign with |

<a id="c-pingfednode"></a>
### pingfedNode

A server that is a PingFederate node: its run.properties (mode, tags, listeners, other settings) and the cluster discovery protocol it uses

OID `1.3.6.1.4.1.32473.3.4.2.11` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`pingfedOperationalMode`](#a-pingfedoperationalmode) |  | `enum` | single | What a PingFederate node is in its cluster (run.properties pf.operational.mode) |
| [`pingfedNodeTags`](#a-pingfednodetags) |  | `string` | multi | A PingFederate node's tags (run.properties node.tags: what adaptive clustering groups it by) |
| [`pingfedListener`](#a-pingfedlistener) |  | `string` | multi | A port a PingFederate node listens on, by what for: runtime=9031, admin=9999, cluster=7600 |
| [`pingfedDiscovery`](#a-pingfeddiscovery) |  | `string` | single | The JGroups discovery protocol a node uses, as found on the node (bin/jgroups.properties, or an upgraded install's tcp.xml): TCPPING, NATIVE_S3_PING, DNS_PING, ... |
| [`pingfedCredentialRole`](#a-pingfedcredentialrole) |  | `string` | single | The secret role holding the credentials: each environment renders its reference |
| [`pingfedConfig`](#a-pingfedconfig) |  | `json` | single | The other settings, as the Admin API writes them (values that may be secret withheld) |
| [`pingfedWithheld`](#a-pingfedwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |

<a id="c-pingfedoidcpolicy"></a>
### pingfedOidcPolicy

An OpenID Connect policy (cn: its id): the ID token it issues, from the token manager it names

OID `1.3.6.1.4.1.32473.3.4.2.8` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingfedUses`](#a-pingfeduses) |  | `dn` | multi | PingFederate objects the settings name: a validator's data store, an adapter's validators, the adapters, selectors, contracts and fragments a policy runs |
| [`pingfedConfig`](#a-pingfedconfig) |  | `json` | single | The other settings, as the Admin API writes them (values that may be secret withheld) |
| [`pingfedSourceVersion`](#a-pingfedsourceversion) |  | `string` | single | The PingFederate version the object's settings were exported from (the bulk export's pfVersion): a render for another version names what changed between the two |

<a id="c-pingfedplugin"></a>
### pingfedPlugin

A plugin instance (cn: its id): a password credential validator, an IdP adapter, an authentication selector

OID `1.3.6.1.4.1.32473.3.4.2.2` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingfedPluginKind`](#a-pingfedpluginkind) | yes | `enum` | single | What a plugin instance is: a password credential validator, an IdP adapter, an authentication selector, an access token manager, a notification publisher, a CAPTCHA provider |
| [`pingfedPluginType`](#a-pingfedplugintype) | yes | `string` | single | The plugin an instance is (pluginDescriptorRef: its implementation's class name) |
| [`pingfedParent`](#a-pingfedparent) |  | `dn` | single | The instance a plugin instance inherits its settings from (parentRef) |
| [`pingfedUses`](#a-pingfeduses) |  | `dn` | multi | PingFederate objects the settings name: a validator's data store, an adapter's validators, the adapters, selectors, contracts and fragments a policy runs |
| [`pingfedCredentialRole`](#a-pingfedcredentialrole) |  | `string` | single | The secret role holding the credentials: each environment renders its reference |
| [`pingfedConfig`](#a-pingfedconfig) |  | `json` | single | The other settings, as the Admin API writes them (values that may be secret withheld) |
| [`pingfedWithheld`](#a-pingfedwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |
| [`pingfedSourceVersion`](#a-pingfedsourceversion) |  | `string` | single | The PingFederate version the object's settings were exported from (the bulk export's pfVersion): a render for another version names what changed between the two |

<a id="c-pingfedpolicycontract"></a>
### pingfedPolicyContract

An authentication policy contract (cn: its id): the attributes an authentication policy hands on

OID `1.3.6.1.4.1.32473.3.4.2.3` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingfedConfig`](#a-pingfedconfig) |  | `json` | single | The other settings, as the Admin API writes them (values that may be secret withheld) |
| [`pingfedSourceVersion`](#a-pingfedsourceversion) |  | `string` | single | The PingFederate version the object's settings were exported from (the bulk export's pfVersion): a render for another version names what changed between the two |

<a id="c-pingfedresource"></a>
### pingfedResource

An item of an Admin API resource the adapter does not model, held as the Admin API writes it (cn: its id; settings for a resource that is one object)

OID `1.3.6.1.4.1.32473.3.4.2.12` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingfedResourceType`](#a-pingfedresourcetype) | yes | `string` | single | The Admin API resource a held-as-is item comes from (/serverSettings, /oauth/accessTokenMappings, ...) |
| [`pingfedCredentialRole`](#a-pingfedcredentialrole) |  | `string` | single | The secret role holding the credentials: each environment renders its reference |
| [`pingfedConfig`](#a-pingfedconfig) |  | `json` | single | The other settings, as the Admin API writes them (values that may be secret withheld) |
| [`pingfedWithheld`](#a-pingfedwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |
| [`pingfedSourceVersion`](#a-pingfedsourceversion) |  | `string` | single | The PingFederate version the object's settings were exported from (the bulk export's pfVersion): a render for another version names what changed between the two |

<a id="c-pingfedsettings"></a>
### pingfedSettings

One of PingFederate's settings resources (cn: which: oauth-auth-server, ...), as the Admin API writes it

OID `1.3.6.1.4.1.32473.3.4.2.9` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingfedScope`](#a-pingfedscope) |  | `string` | multi | A scope the authorization server defines (common and exclusive scopes) |
| [`pingfedUses`](#a-pingfeduses) |  | `dn` | multi | PingFederate objects the settings name: a validator's data store, an adapter's validators, the adapters, selectors, contracts and fragments a policy runs |
| [`pingfedCredentialRole`](#a-pingfedcredentialrole) |  | `string` | single | The secret role holding the credentials: each environment renders its reference |
| [`pingfedConfig`](#a-pingfedconfig) |  | `json` | single | The other settings, as the Admin API writes them (values that may be secret withheld) |
| [`pingfedWithheld`](#a-pingfedwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer) |
| [`pingfedSourceVersion`](#a-pingfedsourceversion) |  | `string` | single | The PingFederate version the object's settings were exported from (the bulk export's pfVersion): a render for another version names what changed between the two |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-pingfedconfig"></a>`pingfedConfig` | `1.3.6.1.4.1.32473.3.4.1.6` | `json` | intent | single |  | The other settings, as the Admin API writes them (values that may be secret withheld) |
| <a id="a-pingfedconnectionid"></a>`pingfedConnectionId` | `1.3.6.1.4.1.32473.3.4.1.15` | `string` | intent | single |  | The id PingFederate knows a partner connection by: what its authentication policies name |
| <a id="a-pingfedconsumer"></a>`pingfedConsumer` | `1.3.6.1.4.1.32473.3.4.1.5` | `dn` | meta | single |  | The directory consumer record of the account the object binds to the directory as |
| <a id="a-pingfedcredentialrole"></a>`pingfedCredentialRole` | `1.3.6.1.4.1.32473.3.4.1.4` | `string` | intent | single |  | The secret role holding the credentials: each environment renders its reference |
| <a id="a-pingfeddiscovery"></a>`pingfedDiscovery` | `1.3.6.1.4.1.32473.3.4.1.21` | `string` | meta | single |  | The JGroups discovery protocol a node uses, as found on the node (bin/jgroups.properties, or an upgraded install's tcp.xml): TCPPING, NATIVE_S3_PING, DNS_PING, ... |
| <a id="a-pingfeddiscoveryprotocol"></a>`pingfedDiscoveryProtocol` | `1.3.6.1.4.1.32473.3.4.1.23` | vocab: `TCPPING` (pingfederate), `NATIVE_S3_PING` (pingfederate), `DNS_PING` (pingfederate) | binding | single |  | The JGroups discovery protocol an environment's PingFederate nodes find each other with, chosen per environment from the protocols the adapter renders (TCPPING, NATIVE_S3_PING, DNS_PING) |
| <a id="a-pingfedenabled"></a>`pingfedEnabled` | `1.3.6.1.4.1.32473.3.4.1.13` | `bool` | intent | single |  | Whether the authentication policy tree is used |
| <a id="a-pingfedkeypairid"></a>`pingfedKeyPairId` | `1.3.6.1.4.1.32473.3.4.1.16` | `string` | intent | single |  | The id PingFederate knows one of its key pairs by: what its token managers sign with |
| <a id="a-pingfedlistener"></a>`pingfedListener` | `1.3.6.1.4.1.32473.3.4.1.20` | `string` | intent | multi | X-PATTERN `^[a-z][a-z0-9-]*=[0-9]+$` | A port a PingFederate node listens on, by what for: runtime=9031, admin=9999, cluster=7600 |
| <a id="a-pingfednodetags"></a>`pingfedNodeTags` | `1.3.6.1.4.1.32473.3.4.1.19` | `string` | intent | multi |  | A PingFederate node's tags (run.properties node.tags: what adaptive clustering groups it by) |
| <a id="a-pingfedoperationalmode"></a>`pingfedOperationalMode` | `1.3.6.1.4.1.32473.3.4.1.18` | enum: `CLUSTERED_CONSOLE`, `CLUSTERED_ENGINE`, `STANDALONE` | intent | single |  | What a PingFederate node is in its cluster (run.properties pf.operational.mode) |
| <a id="a-pingfedparent"></a>`pingfedParent` | `1.3.6.1.4.1.32473.3.4.1.10` | `dn` | intent | single |  | The instance a plugin instance inherits its settings from (parentRef) |
| <a id="a-pingfedpluginkind"></a>`pingfedPluginKind` | `1.3.6.1.4.1.32473.3.4.1.8` | enum: `validator`, `idp-adapter`, `selector`, `access-token-manager`, `notification-publisher`, `captcha-provider` | intent | single |  | What a plugin instance is: a password credential validator, an IdP adapter, an authentication selector, an access token manager, a notification publisher, a CAPTCHA provider |
| <a id="a-pingfedplugintype"></a>`pingfedPluginType` | `1.3.6.1.4.1.32473.3.4.1.9` | `string` | intent | single |  | The plugin an instance is (pluginDescriptorRef: its implementation's class name) |
| <a id="a-pingfedpolicytree"></a>`pingfedPolicyTree` | `1.3.6.1.4.1.32473.3.4.1.14` | `json` | intent | single |  | The policy's tree as PingFederate writes it (rootNode: each node's action and its children, by the result that leads to them) |
| <a id="a-pingfedport"></a>`pingfedPort` | `1.3.6.1.4.1.32473.3.4.1.3` | `int` | intent | single | X-MIN `1`; X-MAX `65535` | The port the object reaches its target role on |
| <a id="a-pingfedposition"></a>`pingfedPosition` | `1.3.6.1.4.1.32473.3.4.1.12` | `int` | intent | single | X-MIN `0` | Its place in the list PingFederate keeps it in (authentication policy trees) |
| <a id="a-pingfedresourcetype"></a>`pingfedResourceType` | `1.3.6.1.4.1.32473.3.4.1.22` | `string` | intent | single |  | The Admin API resource a held-as-is item comes from (/serverSettings, /oauth/accessTokenMappings, ...) |
| <a id="a-pingfedscope"></a>`pingfedScope` | `1.3.6.1.4.1.32473.3.4.1.17` | `string` | intent | multi |  | A scope the authorization server defines (common and exclusive scopes) |
| <a id="a-pingfedsourceversion"></a>`pingfedSourceVersion` | `1.3.6.1.4.1.32473.3.4.1.24` | `string` | meta | single |  | The PingFederate version the object's settings were exported from (the bulk export's pfVersion): a render for another version names what changed between the two |
| <a id="a-pingfedstoretype"></a>`pingfedStoreType` | `1.3.6.1.4.1.32473.3.4.1.1` | `string` | intent | single |  | The data store's type, as PingFederate names it (LDAP, JDBC, CUSTOM) |
| <a id="a-pingfedtargetrole"></a>`pingfedTargetRole` | `1.3.6.1.4.1.32473.3.4.1.2` | `string` | intent | single |  | The binding role of the service the object reaches: each environment renders its host from it |
| <a id="a-pingfeduses"></a>`pingfedUses` | `1.3.6.1.4.1.32473.3.4.1.11` | `dn` | intent | multi |  | PingFederate objects the settings name: a validator's data store, an adapter's validators, the adapters, selectors, contracts and fragments a policy runs |
| <a id="a-pingfedwithheld"></a>`pingfedWithheld` | `1.3.6.1.4.1.32473.3.4.1.7` | `string` | meta | multi |  | Settings withheld at import because they may be secret (JSON Pointer) |

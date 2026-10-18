# PingAccess (opsdir-adapter-pingaccess)

*Package · OID arc `1.3.6.1.4.1.32473.3.5` · 8 object classes · 15 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

PingAccess schema fragment, under this package's own OID arc: what PingAccess protects and how. Each object keeps its settings as the Admin API writes them (JSON, secrets withheld, the objects it names by name instead of PingAccess's ids); what differs per environment is not in them: a virtual host names the service name role it answers as, a site the role of the application behind it, a web session the integration it signs users in as, and each environment renders its own hosts, client id and secret references. Keys, trust, listeners, cluster nodes and agents are held as environment-bound objects, never rendered.

## Object classes

<a id="c-paapplication"></a>
### paApplication

An application PingAccess protects: where it is reached, the site behind it, its web session, identity mappings and policy

OID `1.3.6.1.4.1.32473.3.5.2.1` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`paConfig`](#a-paconfig) |  | `json` | single | The object's settings as the Admin API writes them: secrets withheld, the objects it names as ${pingaccess-id:<collection>/<name>} |
| [`paWithheld`](#a-pawithheld) |  | `string` | multi | Settings withheld at import because they are or may be secret (JSON Pointer): their presence only |
| [`paCredentialRole`](#a-pacredentialrole) |  | `string` | single | The secret role whose binding references the object's withheld values in each environment |
| [`paSourceVersion`](#a-pasourceversion) |  | `string` | single | The PingAccess version the settings were read from |
| [`paUses`](#a-pauses) |  | `dn` | multi | The PingAccess objects the object's settings name (what PingAccess refuses it without) |
| [`paContextRoot`](#a-pacontextroot) |  | `string` | single | The path an application is reached at on its virtual hosts |

<a id="c-paheld"></a>
### paHeld

A PingAccess object held as is (not modeled): token provider, validators, keys, trust, listeners

OID `1.3.6.1.4.1.32473.3.5.2.8` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`paObjectType`](#a-paobjecttype) | yes | `string` | single | An object held as is: its Admin API collection (keyPairs, availabilityProfiles, ...) |
| [`paConfig`](#a-paconfig) |  | `json` | single | The object's settings as the Admin API writes them: secrets withheld, the objects it names as ${pingaccess-id:<collection>/<name>} |
| [`paWithheld`](#a-pawithheld) |  | `string` | multi | Settings withheld at import because they are or may be secret (JSON Pointer): their presence only |
| [`paCredentialRole`](#a-pacredentialrole) |  | `string` | single | The secret role whose binding references the object's withheld values in each environment |
| [`paSourceVersion`](#a-pasourceversion) |  | `string` | single | The PingAccess version the settings were read from |
| [`paUses`](#a-pauses) |  | `dn` | multi | The PingAccess objects the object's settings name (what PingAccess refuses it without) |
| [`paEnvironmentBound`](#a-paenvironmentbound) |  | `bool` | single | Whether an object held as is differs per environment (keys, trust, listeners, nodes, agents): created in each environment, never rendered |

<a id="c-paidentitymapping"></a>
### paIdentityMapping

What PingAccess tells an application about the user: headers or a signed JWT

OID `1.3.6.1.4.1.32473.3.5.2.6` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`paConfig`](#a-paconfig) |  | `json` | single | The object's settings as the Admin API writes them: secrets withheld, the objects it names as ${pingaccess-id:<collection>/<name>} |
| [`paWithheld`](#a-pawithheld) |  | `string` | multi | Settings withheld at import because they are or may be secret (JSON Pointer): their presence only |
| [`paCredentialRole`](#a-pacredentialrole) |  | `string` | single | The secret role whose binding references the object's withheld values in each environment |
| [`paSourceVersion`](#a-pasourceversion) |  | `string` | single | The PingAccess version the settings were read from |
| [`paUses`](#a-pauses) |  | `dn` | multi | The PingAccess objects the object's settings name (what PingAccess refuses it without) |
| [`paHeaderContract`](#a-paheadercontract) |  | `dn` | multi | The header contracts of the headers an identity mapping sets |

<a id="c-paresource"></a>
### paResource

A resource of an application: its paths and methods, how they are authenticated, their policy

OID `1.3.6.1.4.1.32473.3.5.2.2` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`paConfig`](#a-paconfig) |  | `json` | single | The object's settings as the Admin API writes them: secrets withheld, the objects it names as ${pingaccess-id:<collection>/<name>} |
| [`paWithheld`](#a-pawithheld) |  | `string` | multi | Settings withheld at import because they are or may be secret (JSON Pointer): their presence only |
| [`paCredentialRole`](#a-pacredentialrole) |  | `string` | single | The secret role whose binding references the object's withheld values in each environment |
| [`paSourceVersion`](#a-pasourceversion) |  | `string` | single | The PingAccess version the settings were read from |
| [`paUses`](#a-pauses) |  | `dn` | multi | The PingAccess objects the object's settings name (what PingAccess refuses it without) |

<a id="c-parule"></a>
### paRule

An access control or processing rule, or a rule set

OID `1.3.6.1.4.1.32473.3.5.2.7` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`paRuleKind`](#a-parulekind) | yes | `enum` | single | A rule, or a rule set of rules or rule sets |
| [`paConfig`](#a-paconfig) |  | `json` | single | The object's settings as the Admin API writes them: secrets withheld, the objects it names as ${pingaccess-id:<collection>/<name>} |
| [`paWithheld`](#a-pawithheld) |  | `string` | multi | Settings withheld at import because they are or may be secret (JSON Pointer): their presence only |
| [`paCredentialRole`](#a-pacredentialrole) |  | `string` | single | The secret role whose binding references the object's withheld values in each environment |
| [`paSourceVersion`](#a-pasourceversion) |  | `string` | single | The PingAccess version the settings were read from |
| [`paUses`](#a-pauses) |  | `dn` | multi | The PingAccess objects the object's settings name (what PingAccess refuses it without) |

<a id="c-pasite"></a>
### paSite

Where PingAccess sends an application's requests

OID `1.3.6.1.4.1.32473.3.5.2.3` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`paConfig`](#a-paconfig) |  | `json` | single | The object's settings as the Admin API writes them: secrets withheld, the objects it names as ${pingaccess-id:<collection>/<name>} |
| [`paWithheld`](#a-pawithheld) |  | `string` | multi | Settings withheld at import because they are or may be secret (JSON Pointer): their presence only |
| [`paCredentialRole`](#a-pacredentialrole) |  | `string` | single | The secret role whose binding references the object's withheld values in each environment |
| [`paSourceVersion`](#a-pasourceversion) |  | `string` | single | The PingAccess version the settings were read from |
| [`paUses`](#a-pauses) |  | `dn` | multi | The PingAccess objects the object's settings name (what PingAccess refuses it without) |
| [`paBackendRole`](#a-pabackendrole) |  | `string` | single | The binding role of the application a site sends requests to: each environment renders its hosts |
| [`paPort`](#a-paport) |  | `port` | single | The port the application behind a site listens on |

<a id="c-pavirtualhost"></a>
### paVirtualHost

A host name and port PingAccess answers on

OID `1.3.6.1.4.1.32473.3.5.2.4` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`paConfig`](#a-paconfig) |  | `json` | single | The object's settings as the Admin API writes them: secrets withheld, the objects it names as ${pingaccess-id:<collection>/<name>} |
| [`paWithheld`](#a-pawithheld) |  | `string` | multi | Settings withheld at import because they are or may be secret (JSON Pointer): their presence only |
| [`paCredentialRole`](#a-pacredentialrole) |  | `string` | single | The secret role whose binding references the object's withheld values in each environment |
| [`paSourceVersion`](#a-pasourceversion) |  | `string` | single | The PingAccess version the settings were read from |
| [`paUses`](#a-pauses) |  | `dn` | multi | The PingAccess objects the object's settings name (what PingAccess refuses it without) |
| [`paServiceRole`](#a-paservicerole) |  | `string` | single | The service name role a virtual host answers as: each environment renders its host name |

<a id="c-pawebsession"></a>
### paWebSession

How PingAccess signs users in, as an OpenID Connect relying party, and keeps their session

OID `1.3.6.1.4.1.32473.3.5.2.5` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`paConfig`](#a-paconfig) |  | `json` | single | The object's settings as the Admin API writes them: secrets withheld, the objects it names as ${pingaccess-id:<collection>/<name>} |
| [`paWithheld`](#a-pawithheld) |  | `string` | multi | Settings withheld at import because they are or may be secret (JSON Pointer): their presence only |
| [`paCredentialRole`](#a-pacredentialrole) |  | `string` | single | The secret role whose binding references the object's withheld values in each environment |
| [`paSourceVersion`](#a-pasourceversion) |  | `string` | single | The PingAccess version the settings were read from |
| [`paUses`](#a-pauses) |  | `dn` | multi | The PingAccess objects the object's settings name (what PingAccess refuses it without) |
| [`paIntegration`](#a-paintegration) |  | `dn` | single | The OpenID Connect client integration a web session signs users in as |
| [`paIssuer`](#a-paissuer) |  | `url` | single | The OpenID provider a web session signs users in with (its issuer) |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-pabackendrole"></a>`paBackendRole` | `1.3.6.1.4.1.32473.3.5.1.10` | `string` | intent | single |  | The binding role of the application a site sends requests to: each environment renders its hosts |
| <a id="a-paconfig"></a>`paConfig` | `1.3.6.1.4.1.32473.3.5.1.1` | `json` | intent | single |  | The object's settings as the Admin API writes them: secrets withheld, the objects it names as ${pingaccess-id:<collection>/<name>} |
| <a id="a-pacontextroot"></a>`paContextRoot` | `1.3.6.1.4.1.32473.3.5.1.7` | `string` | contract | single |  | The path an application is reached at on its virtual hosts |
| <a id="a-pacredentialrole"></a>`paCredentialRole` | `1.3.6.1.4.1.32473.3.5.1.3` | `string` | intent | single |  | The secret role whose binding references the object's withheld values in each environment |
| <a id="a-paenvironmentbound"></a>`paEnvironmentBound` | `1.3.6.1.4.1.32473.3.5.1.14` | `bool` | intent | single |  | Whether an object held as is differs per environment (keys, trust, listeners, nodes, agents): created in each environment, never rendered |
| <a id="a-paheadercontract"></a>`paHeaderContract` | `1.3.6.1.4.1.32473.3.5.1.13` | `dn` | intent | multi |  | The header contracts of the headers an identity mapping sets |
| <a id="a-paintegration"></a>`paIntegration` | `1.3.6.1.4.1.32473.3.5.1.11` | `dn` | intent | single |  | The OpenID Connect client integration a web session signs users in as |
| <a id="a-paissuer"></a>`paIssuer` | `1.3.6.1.4.1.32473.3.5.1.12` | `url` | contract | single |  | The OpenID provider a web session signs users in with (its issuer) |
| <a id="a-paobjecttype"></a>`paObjectType` | `1.3.6.1.4.1.32473.3.5.1.5` | `string` | intent | single |  | An object held as is: its Admin API collection (keyPairs, availabilityProfiles, ...) |
| <a id="a-paport"></a>`paPort` | `1.3.6.1.4.1.32473.3.5.1.9` | `port` | intent | single |  | The port the application behind a site listens on |
| <a id="a-parulekind"></a>`paRuleKind` | `1.3.6.1.4.1.32473.3.5.1.15` | enum: `rule`, `rule-set` | intent | single |  | A rule, or a rule set of rules or rule sets |
| <a id="a-paservicerole"></a>`paServiceRole` | `1.3.6.1.4.1.32473.3.5.1.8` | `string` | intent | single |  | The service name role a virtual host answers as: each environment renders its host name |
| <a id="a-pasourceversion"></a>`paSourceVersion` | `1.3.6.1.4.1.32473.3.5.1.4` | `string` | meta | single |  | The PingAccess version the settings were read from |
| <a id="a-pauses"></a>`paUses` | `1.3.6.1.4.1.32473.3.5.1.6` | `dn` | intent | multi |  | The PingAccess objects the object's settings name (what PingAccess refuses it without) |
| <a id="a-pawithheld"></a>`paWithheld` | `1.3.6.1.4.1.32473.3.5.1.2` | `string` | meta | multi |  | Settings withheld at import because they are or may be secret (JSON Pointer): their presence only |

# Custom

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 3 object classes · 24 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

custom domain schema fragment: how operators define fields and record types of their own (OIDs pinned by number). The definitions are entries (governed, historied, exported like everything else); the metadata says what a field is, what values it takes, which records carry it, where its value lives (settings of captured config files, or other systems), and how it behaves in a migration.

**Branches:** `ou=custom-schema,dc=ciam-ops`

## Object classes

<a id="c-ciamcustomdefinition"></a>
### ciamCustomDefinition

A field or record type an operator defines

OID `1.3.6.1.4.1.32473.1.2.36` · abstract · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamDefinitionNumber`](#a-ciamdefinitionnumber) | yes | `int` | single | Pinned OID number of a custom definition (under the custom arc) |
| [`ciamPurpose`](directory.md#a-ciampurpose) |  | `string` | single | Why the attribute is stored |
| [`ciamPiiClass`](directory.md#a-ciampiiclass) |  | `enum` | single | Privacy classification |
| [`ciamDefinitionStatus`](#a-ciamdefinitionstatus) |  | `enum` | single | Lifecycle of a custom definition |
| [`ciamDocumentation`](#a-ciamdocumentation) |  | `url` | multi | Documentation about it |
| [`ciamRunbookRef`](#a-ciamrunbookref) |  | `dn` | multi | Runbooks about it |
| [`ciamValueSource`](#a-ciamvaluesource) |  | `string` | multi | Where the value lives in a system the record does not hold, as "system: locator" (a console, a register, an API path); for a config file held in the record use ciamSettingRef |
| [`ciamSettingRef`](#a-ciamsettingref) |  | `dn` | multi | Settings of captured config files (ou=config-files) where the value lives |
| [`ciamUsedBy`](#a-ciamusedby) |  | `string` | multi | Adapters, parsers or renderers that read or write it |

<a id="c-ciamfielddefinition"></a>
### ciamFieldDefinition

Definition of a custom field

OID `1.3.6.1.4.1.32473.1.2.37` · structural · inherits [`ciamCustomDefinition`](#c-ciamcustomdefinition)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamValueType`](#a-ciamvaluetype) | yes | `string` | single | Value type of a custom field: string, int, bool, time, dn, extdn, cidr, ip, fqdn, url, port, ref-uri, json or enum:a\|b\|c |
| [`ciamPortability`](#a-ciamportability) | yes | `enum` | single | What happens to the value in a migration (SPEC 3.1) |
| [`ciamMultiValued`](#a-ciammultivalued) |  | `bool` | single | The field may hold several values (default: one) |
| [`ciamCarriedBy`](#a-ciamcarriedby) |  | `string` | multi | Record types (object classes) that may carry the field |
| [`ciamUnit`](#a-ciamunit) |  | `string` | single | Unit of the value (days, seconds, MB, ...) |
| [`ciamExample`](#a-ciamexample) |  | `string` | multi | Example value |
| [`ciamDefaultValue`](#a-ciamdefaultvalue) |  | `string` | single | Value assumed when a record does not carry the field |
| [`ciamMinValue`](#a-ciamminvalue) |  | `int` | single | Smallest allowed value (int and port fields) |
| [`ciamMaxValue`](#a-ciammaxvalue) |  | `int` | single | Largest allowed value (int and port fields) |
| [`ciamPattern`](#a-ciampattern) |  | `string` | single | Regular expression every value must match |
| [`ciamMaxLength`](#a-ciammaxlength) |  | `int` | single | Longest allowed value, in characters |
| [`ciamOverridable`](#a-ciamoverridable) |  | `bool` | single | An environment may override the value (environment overlays) |
| [`ciamCensusTerm`](#a-ciamcensusterm) |  | `bool` | single | The census looks for the field's values in files, whatever their type: a term operators want found wherever it is copied (an old brand or domain, an account ID, a bucket name) |

<a id="c-ciamrecordtypedefinition"></a>
### ciamRecordTypeDefinition

Definition of a custom record type

OID `1.3.6.1.4.1.32473.1.2.38` · structural · inherits [`ciamCustomDefinition`](#c-ciamcustomdefinition)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamRecordKind`](#a-ciamrecordkind) |  | `enum` | single | Structural (a kind of record) or auxiliary (a set of fields any record may add) |
| [`ciamParentType`](#a-ciamparenttype) |  | `string` | single | Record type a custom record type extends (default: ciamObject; auxiliary: top) |
| [`ciamRequiredField`](#a-ciamrequiredfield) |  | `string` | multi | Fields a record of this type must carry (besides cn) |
| [`ciamOptionalField`](#a-ciamoptionalfield) |  | `string` | multi | Fields a record of this type may carry |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamcarriedby"></a>`ciamCarriedBy` | `1.3.6.1.4.1.32473.1.1.154` | `string` | meta | multi |  | Record types (object classes) that may carry the field |
| <a id="a-ciamcensusterm"></a>`ciamCensusTerm` | `1.3.6.1.4.1.32473.1.1.265` | `bool` | meta | single |  | The census looks for the field's values in files, whatever their type: a term operators want found wherever it is copied (an old brand or domain, an account ID, a bucket name) |
| <a id="a-ciamdefaultvalue"></a>`ciamDefaultValue` | `1.3.6.1.4.1.32473.1.1.157` | `string` | meta | single |  | Value assumed when a record does not carry the field |
| <a id="a-ciamdefinitionnumber"></a>`ciamDefinitionNumber` | `1.3.6.1.4.1.32473.1.1.150` | `int` | meta | single |  | Pinned OID number of a custom definition (under the custom arc) |
| <a id="a-ciamdefinitionstatus"></a>`ciamDefinitionStatus` | `1.3.6.1.4.1.32473.1.1.165` | enum: `proposed`, `active`, `deprecated` | meta | single |  | Lifecycle of a custom definition |
| <a id="a-ciamdocumentation"></a>`ciamDocumentation` | `1.3.6.1.4.1.32473.1.1.166` | `url` | meta | multi |  | Documentation about it |
| <a id="a-ciamexample"></a>`ciamExample` | `1.3.6.1.4.1.32473.1.1.156` | `string` | meta | multi |  | Example value |
| <a id="a-ciammaxlength"></a>`ciamMaxLength` | `1.3.6.1.4.1.32473.1.1.161` | `int` | meta | single |  | Longest allowed value, in characters |
| <a id="a-ciammaxvalue"></a>`ciamMaxValue` | `1.3.6.1.4.1.32473.1.1.159` | `int` | meta | single |  | Largest allowed value (int and port fields) |
| <a id="a-ciamminvalue"></a>`ciamMinValue` | `1.3.6.1.4.1.32473.1.1.158` | `int` | meta | single |  | Smallest allowed value (int and port fields) |
| <a id="a-ciammultivalued"></a>`ciamMultiValued` | `1.3.6.1.4.1.32473.1.1.153` | `bool` | meta | single |  | The field may hold several values (default: one) |
| <a id="a-ciamoptionalfield"></a>`ciamOptionalField` | `1.3.6.1.4.1.32473.1.1.171` | `string` | meta | multi |  | Fields a record of this type may carry |
| <a id="a-ciamoverridable"></a>`ciamOverridable` | `1.3.6.1.4.1.32473.1.1.162` | `bool` | meta | single |  | An environment may override the value (environment overlays) |
| <a id="a-ciamparenttype"></a>`ciamParentType` | `1.3.6.1.4.1.32473.1.1.169` | `string` | meta | single |  | Record type a custom record type extends (default: ciamObject; auxiliary: top) |
| <a id="a-ciampattern"></a>`ciamPattern` | `1.3.6.1.4.1.32473.1.1.160` | `string` | meta | single |  | Regular expression every value must match |
| <a id="a-ciamportability"></a>`ciamPortability` | `1.3.6.1.4.1.32473.1.1.152` | enum: `intent`, `contract`, `binding`, `secret-ref`, `observed`, `meta` | meta | single |  | What happens to the value in a migration (SPEC 3.1) |
| <a id="a-ciamrecordkind"></a>`ciamRecordKind` | `1.3.6.1.4.1.32473.1.1.168` | enum: `structural`, `auxiliary` | meta | single |  | Structural (a kind of record) or auxiliary (a set of fields any record may add) |
| <a id="a-ciamrequiredfield"></a>`ciamRequiredField` | `1.3.6.1.4.1.32473.1.1.170` | `string` | meta | multi |  | Fields a record of this type must carry (besides cn) |
| <a id="a-ciamrunbookref"></a>`ciamRunbookRef` | `1.3.6.1.4.1.32473.1.1.167` | `dn` | meta | multi |  | Runbooks about it |
| <a id="a-ciamsettingref"></a>`ciamSettingRef` | `1.3.6.1.4.1.32473.1.1.186` | `dn` | meta | multi |  | Settings of captured config files (ou=config-files) where the value lives |
| <a id="a-ciamunit"></a>`ciamUnit` | `1.3.6.1.4.1.32473.1.1.155` | `string` | meta | single |  | Unit of the value (days, seconds, MB, ...) |
| <a id="a-ciamusedby"></a>`ciamUsedBy` | `1.3.6.1.4.1.32473.1.1.164` | `string` | meta | multi |  | Adapters, parsers or renderers that read or write it |
| <a id="a-ciamvaluesource"></a>`ciamValueSource` | `1.3.6.1.4.1.32473.1.1.163` | `string` | meta | multi |  | Where the value lives in a system the record does not hold, as "system: locator" (a console, a register, an API path); for a config file held in the record use ciamSettingRef |
| <a id="a-ciamvaluetype"></a>`ciamValueType` | `1.3.6.1.4.1.32473.1.1.151` | `string` | meta | single |  | Value type of a custom field: string, int, bool, time, dn, extdn, cidr, ip, fqdn, url, port, ref-uri, json or enum:a\|b\|c |

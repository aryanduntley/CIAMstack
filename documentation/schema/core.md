# Core

*Core · OID arc `1.3.6.1.4.1.32473.1` · 2 object classes · 8 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

The definitions every entry builds on.

**Branches:** `ou=settings,dc=ciam-ops`

## Object classes

<a id="c-ciamestatesetting"></a>
### ciamEstateSetting

An estate-wide setting the platform's managers give a value (under ou=settings, named as a domain declares it): where the record holds none, or one that isn't valid, the domain's default applies

OID `1.3.6.1.4.1.32473.1.2.96` · structural · inherits [`ciamObject`](#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamEstateValue`](#a-ciamestatevalue) | yes | `string` | single | An estate setting's value, as text the declaring domain's setting reads (a whole number, TRUE or FALSE, or a string) |

<a id="c-ciamobject"></a>
### ciamObject

Base of every operations-directory entry

OID `1.3.6.1.4.1.32473.1.2.1` · abstract

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`description`](../SCHEMA.md#standard-description) |  | `string` |  | Free text |
| [`ciamOwner`](#a-ciamowner) |  | `dn` | multi | Owning party (team, partner, vendor) |
| [`ciamLastChanged`](#a-ciamlastchanged) |  | `time` | single | Last change before this directory tracked history |
| [`ciamChangeRef`](#a-ciamchangeref) |  | `dn` | multi | Change record(s) that justify this entry |
| [`ciamVerifyPending`](#a-ciamverifypending) |  | `string` | multi | An attribute whose value the record holds ahead of the live system, awaiting an import to confirm it: "<attribute> <adapter>" (the adapter whose import confirms it; "<attribute>" alone: any) |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamchangeref"></a>`ciamChangeRef` | `1.3.6.1.4.1.32473.1.1.6` | `dn` | meta | multi |  | Change record(s) that justify this entry |
| <a id="a-ciamcriticality"></a>`ciamCriticality` | `1.3.6.1.4.1.32473.1.1.77` | enum: `critical`, `high`, `medium`, `low` | meta | single |  | Business criticality |
| <a id="a-ciamestatevalue"></a>`ciamEstateValue` | `1.3.6.1.4.1.32473.1.1.456` | `string` | meta | single |  | An estate setting's value, as text the declaring domain's setting reads (a whole number, TRUE or FALSE, or a string) |
| <a id="a-ciamformat"></a>`ciamFormat` | `1.3.6.1.4.1.32473.1.1.172` | vocab: `arm-json` (format arm-json), `bicep` (format bicep), `c` (format c), `cloudformation-json` (format cloudformation-json), `cloudformation-yaml` (format cloudformation-yaml), `csv` (format csv), `dockerfile` (format dockerfile), `dsconfig-batch` (format dsconfig-batch), `groovy` (format groovy), `haproxy-cfg` (format haproxy-cfg), `hcl` (format hcl), `html` (format html), `ini` (format ini), `java-properties` (format java-properties), `javascript` (format javascript), `json` (format json), `ldif` (format ldif), `markdown` (format markdown), `ndjson` (format ndjson), `oscal-json` (format oscal-json), `pem` (format pem), `powershell` (format powershell), `python` (format python), `shell` (format shell), `sql` (format sql), `text` (format text), `toml` (format toml), `xml` (format xml), `yaml` (format yaml) | meta | single |  | File format or language of something recorded (one of the registered formats) |
| <a id="a-ciamlastchanged"></a>`ciamLastChanged` | `1.3.6.1.4.1.32473.1.1.5` | `time` | meta | single |  | Last change before this directory tracked history |
| <a id="a-ciamowner"></a>`ciamOwner` | `1.3.6.1.4.1.32473.1.1.4` | `dn` | meta | multi |  | Owning party (team, partner, vendor) |
| <a id="a-ciampopulation"></a>`ciamPopulation` | `1.3.6.1.4.1.32473.1.1.93` | enum: `customers`, `suppliers`, `partners`, `individuals` | intent | multi |  | Identity populations served |
| <a id="a-ciamverifypending"></a>`ciamVerifyPending` | `1.3.6.1.4.1.32473.1.1.425` | `string` | meta | multi |  | An attribute whose value the record holds ahead of the live system, awaiting an import to confirm it: "<attribute> <adapter>" (the adapter whose import confirms it; "<attribute>" alone: any) |

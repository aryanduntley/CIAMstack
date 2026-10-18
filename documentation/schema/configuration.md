# Configuration

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 5 object classes · 18 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

configuration domain schema fragment: config files held in the record (OIDs pinned by number). The census records where the record's values are copied into files: each scanned file, and under it each value found (the entry it belongs to, the attribute, the lines), never the values themselves. A bundle (code, scripts, templates, a package) is recorded by where it lives in version control and its SHA-256; its content is not held in the record. A captured file is one entry (its format, where it lives in version control, the servers it is deployed to, its layout) and one child entry per setting (its locator in the file, its value or a link to a value in the record).

**Branches:** `ou=bundles,dc=ciam-ops`, `ou=census,dc=ciam-ops`, `ou=config-files,dc=ciam-ops`

## Object classes

<a id="c-ciambundle"></a>
### ciamBundle

Code, scripts, templates or a package, deployed as a unit: recorded where it lives, not held in the record

OID `1.3.6.1.4.1.32473.1.2.41` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamRepoPath`](#a-ciamrepopath) | yes | `string` | single | Where the file lives in version control (the same for every environment) |
| [`ciamBundleKind`](#a-ciambundlekind) | yes | `enum` | single | What a bundle is |
| [`ciamSha256`](#a-ciamsha256) | yes | `string` | single | SHA-256 of the file as captured |
| [`ciamFormat`](core.md#a-ciamformat) |  | `vocab` | single | File format or language of something recorded (one of the registered formats) |
| [`ciamBundleVersion`](#a-ciambundleversion) |  | `string` | single | The version of a bundle (a release, a tag, a package version) |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) |  | `vocab` | single | Server role a service or rule targets |
| [`ciamDeployPath`](#a-ciamdeploypath) |  | `string` | single | Where the file is written on the servers it is deployed to |

<a id="c-ciamconfigfile"></a>
### ciamConfigFile

A config file held in the record

OID `1.3.6.1.4.1.32473.1.2.39` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamFormat`](core.md#a-ciamformat) | yes | `vocab` | single | File format or language of something recorded (one of the registered formats) |
| [`ciamRepoPath`](#a-ciamrepopath) | yes | `string` | single | Where the file lives in version control (the same for every environment) |
| [`ciamCaptureLevel`](#a-ciamcapturelevel) | yes | `enum` | single | How the record holds the file: its settings one by one, its whole text, or only a reference to it |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) |  | `vocab` | single | Server role a service or rule targets |
| [`ciamDeployPath`](#a-ciamdeploypath) |  | `string` | single | Where the file is written on the servers it is deployed to |
| [`ciamSkeleton`](#a-ciamskeleton) |  | `string` | single | The file's text with each setting's place marked (settings), or its whole text (whole-file) |
| [`ciamSha256`](#a-ciamsha256) |  | `string` | single | SHA-256 of the file as captured |
| [`ciamCaptureProblem`](#a-ciamcaptureproblem) |  | `string` | multi | Why the file is not held as settings, or why a value was withheld |

<a id="c-ciamconfigsetting"></a>
### ciamConfigSetting

One setting of a captured config file

OID `1.3.6.1.4.1.32473.1.2.40` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamLocator`](#a-ciamlocator) | yes | `string` | single | Where a setting is in its file (key, section.key, JSON pointer, XPath, dn\|attribute) |
| [`ciamSettingValue`](#a-ciamsettingvalue) |  | `string` | single | The value of a setting |
| [`ciamSettingRaw`](#a-ciamsettingraw) |  | `string` | single | The setting's text exactly as the file wrote it when captured (its quoting and type are kept) |
| [`ciamValueFrom`](#a-ciamvaluefrom) |  | `string` | single | Where the value comes from instead of a literal: role#attribute, a binding of the environment the file is rendered for (a secret reference renders as ${secret:<ref-uri>}), or role#kind:name, a value derived from that binding (proxy:host, proxy:port, proxy:bypass, ...) |
| [`ciamSecretRequired`](#a-ciamsecretrequired) |  | `bool` | single | The value was withheld at capture: it must come from a secret reference (ciamValueFrom) |
| [`ciamCaptureProblem`](#a-ciamcaptureproblem) |  | `string` | multi | Why the file is not held as settings, or why a value was withheld |

<a id="c-ciamoccurrence"></a>
### ciamOccurrence

A value of the record found in a scanned file: whose, which attribute, on which lines

OID `1.3.6.1.4.1.32473.1.2.47` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamOccurrenceOf`](#a-ciamoccurrenceof) | yes | `dn` | single | The entry whose value occurs in the file |
| [`ciamOccurringAttr`](#a-ciamoccurringattr) | yes | `string` | single | Which attribute of that entry holds the value |
| [`ciamLineNumber`](#a-ciamlinenumber) | yes | `int` | multi | Lines of the file the value occurs on |

<a id="c-ciamscannedfile"></a>
### ciamScannedFile

A file the census scanned for values of the record

OID `1.3.6.1.4.1.32473.1.2.46` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamRepoPath`](#a-ciamrepopath) | yes | `string` | single | Where the file lives in version control (the same for every environment) |
| [`ciamSha256`](#a-ciamsha256) | yes | `string` | single | SHA-256 of the file as captured |
| [`ciamOnServer`](#a-ciamonserver) |  | `dn` | single | The server a scanned file was taken from |
| [`ciamConcern`](#a-ciamconcern) |  | `string` | multi | What in the file may be secret material, by line (never the value) |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciambundlekind"></a>`ciamBundleKind` | `1.3.6.1.4.1.32473.1.1.184` | enum: `code`, `script`, `template`, `package`, `dashboard`, `other` | meta | single |  | What a bundle is |
| <a id="a-ciambundleversion"></a>`ciamBundleVersion` | `1.3.6.1.4.1.32473.1.1.185` | `string` | meta | single |  | The version of a bundle (a release, a tag, a package version) |
| <a id="a-ciamcapturelevel"></a>`ciamCaptureLevel` | `1.3.6.1.4.1.32473.1.1.175` | enum: `settings`, `whole-file`, `reference` | meta | single |  | How the record holds the file: its settings one by one, its whole text, or only a reference to it |
| <a id="a-ciamcaptureproblem"></a>`ciamCaptureProblem` | `1.3.6.1.4.1.32473.1.1.178` | `string` | meta | multi |  | Why the file is not held as settings, or why a value was withheld |
| <a id="a-ciamconcern"></a>`ciamConcern` | `1.3.6.1.4.1.32473.1.1.218` | `string` | observed | multi |  | What in the file may be secret material, by line (never the value) |
| <a id="a-ciamdeploypath"></a>`ciamDeployPath` | `1.3.6.1.4.1.32473.1.1.174` | `string` | intent | single |  | Where the file is written on the servers it is deployed to |
| <a id="a-ciamlinenumber"></a>`ciamLineNumber` | `1.3.6.1.4.1.32473.1.1.217` | `int` | observed | multi |  | Lines of the file the value occurs on |
| <a id="a-ciamlocator"></a>`ciamLocator` | `1.3.6.1.4.1.32473.1.1.179` | `string` | intent | single |  | Where a setting is in its file (key, section.key, JSON pointer, XPath, dn\|attribute) |
| <a id="a-ciamoccurrenceof"></a>`ciamOccurrenceOf` | `1.3.6.1.4.1.32473.1.1.215` | `dn` | observed | single |  | The entry whose value occurs in the file |
| <a id="a-ciamoccurringattr"></a>`ciamOccurringAttr` | `1.3.6.1.4.1.32473.1.1.216` | `string` | observed | single |  | Which attribute of that entry holds the value |
| <a id="a-ciamonserver"></a>`ciamOnServer` | `1.3.6.1.4.1.32473.1.1.214` | `dn` | observed | single |  | The server a scanned file was taken from |
| <a id="a-ciamrepopath"></a>`ciamRepoPath` | `1.3.6.1.4.1.32473.1.1.173` | `string` | meta | single |  | Where the file lives in version control (the same for every environment) |
| <a id="a-ciamsecretrequired"></a>`ciamSecretRequired` | `1.3.6.1.4.1.32473.1.1.183` | `bool` | meta | single |  | The value was withheld at capture: it must come from a secret reference (ciamValueFrom) |
| <a id="a-ciamsettingraw"></a>`ciamSettingRaw` | `1.3.6.1.4.1.32473.1.1.181` | `string` | intent | single |  | The setting's text exactly as the file wrote it when captured (its quoting and type are kept) |
| <a id="a-ciamsettingvalue"></a>`ciamSettingValue` | `1.3.6.1.4.1.32473.1.1.180` | `string` | intent | single |  | The value of a setting |
| <a id="a-ciamsha256"></a>`ciamSha256` | `1.3.6.1.4.1.32473.1.1.177` | `string` | observed | single | X-PATTERN `^[0-9a-f]{64}$` | SHA-256 of the file as captured |
| <a id="a-ciamskeleton"></a>`ciamSkeleton` | `1.3.6.1.4.1.32473.1.1.176` | `string` | intent | single |  | The file's text with each setting's place marked (settings), or its whole text (whole-file) |
| <a id="a-ciamvaluefrom"></a>`ciamValueFrom` | `1.3.6.1.4.1.32473.1.1.182` | `string` | intent | single | X-PATTERN `^[A-Za-z0-9._-]+#[A-Za-z][A-Za-z0-9-]*(:[a-z][a-z0-9-]*)?$` | Where the value comes from instead of a literal: role#attribute, a binding of the environment the file is rendered for (a secret reference renders as ${secret:<ref-uri>}), or role#kind:name, a value derived from that binding (proxy:host, proxy:port, proxy:bypass, ...) |

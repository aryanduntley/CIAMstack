# azure (opsdir-adapter-azure)

*Package · OID arc `1.3.6.1.4.1.32473.3.7` · 1 object classes · 7 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Azure schema fragment, under this package's own OID arc: choices only Microsoft Sentinel has, which the core's vendor-neutral detections don't name (milestone 129, decision 3538). A SIEM detection on a Sentinel workspace (an alarm binding naming it in ciamLogDestinationRole) may add the auxiliary class azSentinelRule: how its analytics rule runs (scheduled, or near-real-time), its alerts' details taken from its results (alert details override) and how long Sentinel stops running it after an alert (suppression). Without the class, the rule is scheduled, with Sentinel's own alert details and no suppression. Pure data.

## Object classes

<a id="c-azsentinelrule"></a>
### azSentinelRule

Microsoft Sentinel's choices for a SIEM detection (on its alarm binding): how its analytics rule runs, its alerts' details and its suppression

OID `1.3.6.1.4.1.32473.3.7.2.1` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`azSentinelRuleKind`](#a-azsentinelrulekind) |  | `enum` | single | How Sentinel runs a detection's analytics rule: scheduled (the default: every evaluation period, over it) or nrt (near-real-time: every minute, over what arrived since its last run; a rows detection only) |
| [`azSentinelAlertName`](#a-azsentinelalertname) |  | `string` | single | The name of a detection's alerts, its results' columns as {{Column}} (alert details override; none: the analytics rule's name) |
| [`azSentinelAlertDescription`](#a-azsentinelalertdescription) |  | `string` | single | The description of a detection's alerts, its results' columns as {{Column}} (alert details override; none: the analytics rule's description) |
| [`azSentinelSeverityColumn`](#a-azsentinelseveritycolumn) |  | `string` | single | The result column whose value is an alert's severity (none: the alert rule's severity) |
| [`azSentinelTacticsColumn`](#a-azsentineltacticscolumn) |  | `string` | single | The result column whose value is an alert's ATT&CK tactics (none: the alert rule's tactics) |
| [`azSentinelAlertProperty`](#a-azsentinelalertproperty) |  | `string` | multi | An alert property a result column sets: '<property>=<column>', property one of AlertLink, ConfidenceLevel, ConfidenceScore, ExtendedLinks, ProductComponentName, ProductName, ProviderName, RemediationSteps, SubTechniques, Techniques |
| [`azSentinelSuppression`](#a-azsentinelsuppression) |  | `string` | single | How long Sentinel stops running a detection's analytics rule after it raises an alert (5m to 24h, whole minutes; none: never) |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-azsentinelalertdescription"></a>`azSentinelAlertDescription` | `1.3.6.1.4.1.32473.3.7.1.3` | `string` | binding | single |  | The description of a detection's alerts, its results' columns as {{Column}} (alert details override; none: the analytics rule's description) |
| <a id="a-azsentinelalertname"></a>`azSentinelAlertName` | `1.3.6.1.4.1.32473.3.7.1.2` | `string` | binding | single |  | The name of a detection's alerts, its results' columns as {{Column}} (alert details override; none: the analytics rule's name) |
| <a id="a-azsentinelalertproperty"></a>`azSentinelAlertProperty` | `1.3.6.1.4.1.32473.3.7.1.6` | `string` | binding | multi | X-PATTERN `^(AlertLink\|ConfidenceLevel\|ConfidenceScore\|ExtendedLinks\|ProductComponentName\|ProductName\|ProviderName\|RemediationSteps\|SubTechniques\|Techniques)=[A-Za-z_][A-Za-z0-9_]*$` | An alert property a result column sets: '<property>=<column>', property one of AlertLink, ConfidenceLevel, ConfidenceScore, ExtendedLinks, ProductComponentName, ProductName, ProviderName, RemediationSteps, SubTechniques, Techniques |
| <a id="a-azsentinelrulekind"></a>`azSentinelRuleKind` | `1.3.6.1.4.1.32473.3.7.1.1` | enum: `scheduled`, `nrt` | binding | single |  | How Sentinel runs a detection's analytics rule: scheduled (the default: every evaluation period, over it) or nrt (near-real-time: every minute, over what arrived since its last run; a rows detection only) |
| <a id="a-azsentinelseveritycolumn"></a>`azSentinelSeverityColumn` | `1.3.6.1.4.1.32473.3.7.1.4` | `string` | binding | single | X-PATTERN `^[A-Za-z_][A-Za-z0-9_]*$` | The result column whose value is an alert's severity (none: the alert rule's severity) |
| <a id="a-azsentinelsuppression"></a>`azSentinelSuppression` | `1.3.6.1.4.1.32473.3.7.1.7` | `string` | binding | single | X-PATTERN `^[0-9]+(s\|m\|h\|d)$` | How long Sentinel stops running a detection's analytics rule after it raises an alert (5m to 24h, whole minutes; none: never) |
| <a id="a-azsentineltacticscolumn"></a>`azSentinelTacticsColumn` | `1.3.6.1.4.1.32473.3.7.1.5` | `string` | binding | single | X-PATTERN `^[A-Za-z_][A-Za-z0-9_]*$` | The result column whose value is an alert's ATT&CK tactics (none: the alert rule's tactics) |

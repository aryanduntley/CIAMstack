# PingAM (opsdir-adapter-pingam)

*Package · OID arc `1.3.6.1.4.1.32473.3.1` · 5 object classes · 14 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

PingAM schema fragment, under this package's own OID arc: what the standard layers don't describe. A realm is one of the platform's identity services (auxiliary class pingamRealm: its realm path); authentication journeys (trees of nodes) and policy sets (of policies) are AM's own, held under ou=pingam. Node, tree and policy settings are kept as AM writes them (JSON), with values that may be secret withheld.

## Object classes

<a id="c-pingamjourney"></a>
### pingamJourney

An authentication journey (tree): its nodes are its children

OID `1.3.6.1.4.1.32473.3.1.2.2` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingamRealm`](#c-pingamrealm) | yes | `dn` | single | The realm (identity service) a journey or policy set belongs to |
| [`pingamEntryNode`](#a-pingamentrynode) | yes | `string` | single | The node a journey starts at |
| [`pingamEnabled`](#a-pingamenabled) |  | `bool` | single | Whether the journey can be used |
| [`pingamTreeConfig`](#a-pingamtreeconfig) |  | `json` | single | The journey's other settings, as AM writes them |

<a id="c-pingamnode"></a>
### pingamNode

One node of a journey (cn: its node id)

OID `1.3.6.1.4.1.32473.3.1.2.3` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingamNodeType`](#a-pingamnodetype) | yes | `string` | single | The AM node type (UsernameCollectorNode, DataStoreDecisionNode, PageNode, ...) |
| [`pingamDisplayName`](#a-pingamdisplayname) |  | `string` | single | The node's name in the journey |
| [`pingamNodeConfig`](#a-pingamnodeconfig) |  | `json` | single | The node's settings, as AM writes them (values that may be secret withheld) |
| [`pingamOutcome`](#a-pingamoutcome) |  | `string` | multi | Where an outcome of the node leads: outcome=node id (the success and failure nodes end the journey) |
| [`pingamWithheld`](#a-pingamwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer): the environment supplies them |
| [`pingamNodeVersion`](#a-pingamnodeversion) |  | `string` | single | The node's version, as PingAM 8.1 and later write it (the tree's node map and the node's _type); absent for earlier versions, whose nodes have none |

<a id="c-pingampolicy"></a>
### pingamPolicy

One authorization policy of a policy set

OID `1.3.6.1.4.1.32473.3.1.2.5` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingamPolicyConfig`](#a-pingampolicyconfig) |  | `json` | single | The policy: resources, actions, subject and conditions, as AM writes them |
| [`pingamWithheld`](#a-pingamwithheld) |  | `string` | multi | Settings withheld at import because they may be secret (JSON Pointer): the environment supplies them |

<a id="c-pingampolicyset"></a>
### pingamPolicySet

A policy set (AM application): its policies are its children

OID `1.3.6.1.4.1.32473.3.1.2.4` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`pingamRealm`](#c-pingamrealm) | yes | `dn` | single | The realm (identity service) a journey or policy set belongs to |
| [`pingamApplicationType`](#a-pingamapplicationtype) |  | `string` | single | A policy set's application type |
| [`pingamSetConfig`](#a-pingamsetconfig) |  | `json` | single | The policy set's other settings, as AM writes them |

<a id="c-pingamrealm"></a>
### pingamRealm

An identity service that is an AM realm

OID `1.3.6.1.4.1.32473.3.1.2.1` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`pingamRealmPath`](#a-pingamrealmpath) | yes | `string` | single | The AM realm an identity service is ('/', '/customers'): part of its endpoint URLs |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-pingamapplicationtype"></a>`pingamApplicationType` | `1.3.6.1.4.1.32473.3.1.1.11` | `string` | intent | single |  | A policy set's application type |
| <a id="a-pingamdisplayname"></a>`pingamDisplayName` | `1.3.6.1.4.1.32473.3.1.1.7` | `string` | intent | single |  | The node's name in the journey |
| <a id="a-pingamenabled"></a>`pingamEnabled` | `1.3.6.1.4.1.32473.3.1.1.4` | `bool` | intent | single |  | Whether the journey can be used |
| <a id="a-pingamentrynode"></a>`pingamEntryNode` | `1.3.6.1.4.1.32473.3.1.1.3` | `string` | intent | single |  | The node a journey starts at |
| <a id="a-pingamnodeconfig"></a>`pingamNodeConfig` | `1.3.6.1.4.1.32473.3.1.1.8` | `json` | intent | single |  | The node's settings, as AM writes them (values that may be secret withheld) |
| <a id="a-pingamnodetype"></a>`pingamNodeType` | `1.3.6.1.4.1.32473.3.1.1.6` | `string` | intent | single |  | The AM node type (UsernameCollectorNode, DataStoreDecisionNode, PageNode, ...) |
| <a id="a-pingamnodeversion"></a>`pingamNodeVersion` | `1.3.6.1.4.1.32473.3.1.1.14` | `string` | intent | single |  | The node's version, as PingAM 8.1 and later write it (the tree's node map and the node's _type); absent for earlier versions, whose nodes have none |
| <a id="a-pingamoutcome"></a>`pingamOutcome` | `1.3.6.1.4.1.32473.3.1.1.9` | `string` | intent | multi | X-PATTERN `^[^=]+=.+$` | Where an outcome of the node leads: outcome=node id (the success and failure nodes end the journey) |
| <a id="a-pingampolicyconfig"></a>`pingamPolicyConfig` | `1.3.6.1.4.1.32473.3.1.1.13` | `json` | intent | single |  | The policy: resources, actions, subject and conditions, as AM writes them |
| <a id="a-pingamrealm"></a>`pingamRealm` | `1.3.6.1.4.1.32473.3.1.1.2` | `dn` | intent | single |  | The realm (identity service) a journey or policy set belongs to |
| <a id="a-pingamrealmpath"></a>`pingamRealmPath` | `1.3.6.1.4.1.32473.3.1.1.1` | `string` | contract | single | X-PATTERN `^/([A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*)?$` | The AM realm an identity service is ('/', '/customers'): part of its endpoint URLs |
| <a id="a-pingamsetconfig"></a>`pingamSetConfig` | `1.3.6.1.4.1.32473.3.1.1.12` | `json` | intent | single |  | The policy set's other settings, as AM writes them |
| <a id="a-pingamtreeconfig"></a>`pingamTreeConfig` | `1.3.6.1.4.1.32473.3.1.1.5` | `json` | intent | single |  | The journey's other settings, as AM writes them |
| <a id="a-pingamwithheld"></a>`pingamWithheld` | `1.3.6.1.4.1.32473.3.1.1.10` | `string` | meta | multi |  | Settings withheld at import because they may be secret (JSON Pointer): the environment supplies them |

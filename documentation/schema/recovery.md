# Recovery

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 3 object classes · 11 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Recovery domain schema: what disaster recovery promises and what shows it holds. A recovery objective (under ou=recovery) is the estate's promise for the roles it names: how long what they serve may be down after a disaster (RTO) and how much of what they hold may be lost (RPO), and the runbook that recovers them; every environment running those roles is held to it. A standby environment says so on its own entry (the auxiliary class ciamStandby): the environment it takes over from, how ready it is kept and the runbook that fails over to it; its region is its cloud's. A failover drill (under ou=failover-drills) is the record of one failover someone did: from where to where, how it went, how long until service was back and how much was lost.

**Branches:** `ou=failover-drills,dc=ciam-ops`, `ou=recovery,dc=ciam-ops`

## Object classes

<a id="c-ciamfailoverdrill"></a>
### ciamFailoverDrill

One failover drill (under ou=failover-drills): when, from which environment to which, the roles it verified (all when none is named), how it went, how long until service was back and how much was lost

OID `1.3.6.1.4.1.32473.1.2.102` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamDrilledOn`](#a-ciamdrilledon) | yes | `time` | single | When a failover drill was done |
| [`ciamDrillFrom`](#a-ciamdrillfrom) | yes | `dn` | single | The environment a failover drill failed over from |
| [`ciamDrillTo`](#a-ciamdrillto) | yes | `dn` | single | The environment a failover drill failed over to |
| [`ciamDrillResult`](#a-ciamdrillresult) | yes | `enum` | single | How a failover drill went: passed (service back and verified), partial (back, but something was missing or wrong), failed |
| [`ciamServiceMinutes`](#a-ciamserviceminutes) |  | `int` | single | How long a failover drill took, in minutes, until service was back from the environment failed over to (the recovery time it measured) |
| [`ciamDataLossMinutes`](#a-ciamdatalossminutes) |  | `int` | single | How many minutes of changes a failover drill lost (the recovery point it measured; 0: none) |
| [`ciamRecoversRole`](#a-ciamrecoversrole) |  | `string` | multi | A role a recovery objective or failover drill is about: a volume, a database, an object store, the servers of a role |
| [`ciamRunbookRef`](custom.md#a-ciamrunbookref) |  | `dn` | multi | Runbooks about it |

<a id="c-ciamrecoveryobjective"></a>
### ciamRecoveryObjective

A recovery objective (under ou=recovery): for the roles it names, how long what they serve may be down after a disaster (RTO), how much of what they hold may be lost (RPO) and the runbook that recovers them; every environment running them is held to it

OID `1.3.6.1.4.1.32473.1.2.100` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamRecoversRole`](#a-ciamrecoversrole) | yes | `string` | multi | A role a recovery objective or failover drill is about: a volume, a database, an object store, the servers of a role |
| [`ciamRtoMinutes`](#a-ciamrtominutes) |  | `int` | single | Recovery time objective: how long what a role serves may be unavailable after a disaster, in minutes |
| [`ciamRpoMinutes`](#a-ciamrpominutes) |  | `int` | single | Recovery point objective: how much of what a role holds may be lost in a disaster, in minutes of changes (0: nothing) |
| [`ciamRunbookRef`](custom.md#a-ciamrunbookref) |  | `dn` | multi | Runbooks about it |

<a id="c-ciamstandby"></a>
### ciamStandby

Added to an environment that stands by for another: the environment it takes over from, how ready it is kept and the runbook that fails over to it

OID `1.3.6.1.4.1.32473.1.2.101` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamStandbyOf`](#a-ciamstandbyof) | yes | `dn` | single | The environment a standby environment takes over from in a disaster (its primary) |
| [`ciamStandbyMode`](#a-ciamstandbymode) |  | `enum` | single | How ready a standby is kept: serving already (hot), running with less capacity (warm), its data kept current but its servers mostly stopped (pilot-light), built only when needed (cold) |
| [`ciamRunbookRef`](custom.md#a-ciamrunbookref) |  | `dn` | multi | Runbooks about it |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamdatalossminutes"></a>`ciamDataLossMinutes` | `1.3.6.1.4.1.32473.1.1.481` | `int` | meta | single | X-MIN `0` | How many minutes of changes a failover drill lost (the recovery point it measured; 0: none) |
| <a id="a-ciamdrilledon"></a>`ciamDrilledOn` | `1.3.6.1.4.1.32473.1.1.476` | `time` | meta | single |  | When a failover drill was done |
| <a id="a-ciamdrillfrom"></a>`ciamDrillFrom` | `1.3.6.1.4.1.32473.1.1.477` | `dn` | meta | single |  | The environment a failover drill failed over from |
| <a id="a-ciamdrillresult"></a>`ciamDrillResult` | `1.3.6.1.4.1.32473.1.1.479` | enum: `passed`, `partial`, `failed` | meta | single |  | How a failover drill went: passed (service back and verified), partial (back, but something was missing or wrong), failed |
| <a id="a-ciamdrillto"></a>`ciamDrillTo` | `1.3.6.1.4.1.32473.1.1.478` | `dn` | meta | single |  | The environment a failover drill failed over to |
| <a id="a-ciamrecoversrole"></a>`ciamRecoversRole` | `1.3.6.1.4.1.32473.1.1.471` | `string` | meta | multi |  | A role a recovery objective or failover drill is about: a volume, a database, an object store, the servers of a role |
| <a id="a-ciamrpominutes"></a>`ciamRpoMinutes` | `1.3.6.1.4.1.32473.1.1.473` | `int` | meta | single | X-MIN `0` | Recovery point objective: how much of what a role holds may be lost in a disaster, in minutes of changes (0: nothing) |
| <a id="a-ciamrtominutes"></a>`ciamRtoMinutes` | `1.3.6.1.4.1.32473.1.1.472` | `int` | meta | single | X-MIN `1` | Recovery time objective: how long what a role serves may be unavailable after a disaster, in minutes |
| <a id="a-ciamserviceminutes"></a>`ciamServiceMinutes` | `1.3.6.1.4.1.32473.1.1.480` | `int` | meta | single | X-MIN `0` | How long a failover drill took, in minutes, until service was back from the environment failed over to (the recovery time it measured) |
| <a id="a-ciamstandbymode"></a>`ciamStandbyMode` | `1.3.6.1.4.1.32473.1.1.475` | enum: `hot`, `warm`, `pilot-light`, `cold` | intent | single |  | How ready a standby is kept: serving already (hot), running with less capacity (warm), its data kept current but its servers mostly stopped (pilot-light), built only when needed (cold) |
| <a id="a-ciamstandbyof"></a>`ciamStandbyOf` | `1.3.6.1.4.1.32473.1.1.474` | `dn` | intent | single |  | The environment a standby environment takes over from in a disaster (its primary) |

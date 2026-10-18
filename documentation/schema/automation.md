# Automation

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 2 object classes · 15 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Automation domain schema: the platform's hidden automation as entries. A job is intent (what runs, when, on what, with which secrets, from which code), the same in every environment; where an environment runs a function or a pipeline is a binding (ciamJobBinding), like any other per-environment resource.

**Branches:** `ou=jobs,dc=ciam-ops`

## Object classes

<a id="c-ciamjob"></a>
### ciamJob

A piece of the platform's automation: what runs, when, on what, with which secrets, from which code

OID `1.3.6.1.4.1.32473.1.2.48` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamJobKind`](#a-ciamjobkind) | yes | `enum` | single | What a job is: a cron entry, a systemd timer, a scheduled task, a serverless function, a pipeline |
| [`ciamSchedule`](#a-ciamschedule) |  | `string` | multi | When a job runs, as its system writes it (a cron expression, rate(1 hour), OnCalendar=daily, ...) |
| [`ciamTrigger`](#a-ciamtrigger) |  | `string` | multi | What else starts a job: manual, push, pull-request, http, queue, event, boot, ... |
| [`ciamCommand`](#a-ciamcommand) |  | `string` | single | What a job runs (a command line, a handler, an entry point); never stored when it holds a secret |
| [`ciamRunsAs`](#a-ciamrunsas) |  | `string` | single | The account a job runs as (an OS user, a service account, a runner) |
| [`ciamRuntime`](#a-ciamruntime) |  | `string` | single | What a job runs in: a language runtime (python3.12), a runner image (ubuntu-24.04), ... |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) |  | `vocab` | single | Server role a service or rule targets |
| [`ciamJobRole`](#a-ciamjobrole) |  | `string` | single | The binding role that realizes the job in each environment (its function, its pipeline) |
| [`ciamUsesRole`](#a-ciamusesrole) |  | `string` | multi | A binding role the job uses (a secret, a service name, a storage location): each environment binds it |
| [`ciamSecretName`](#a-ciamsecretname) |  | `string` | multi | A secret the job expects by name in its own system (a CI secret, an environment variable from a secret store): the name, never the value |
| [`ciamCodeBundle`](#a-ciamcodebundle) |  | `dn` | single | The bundle holding the code the job runs |
| [`ciamRepoPath`](configuration.md#a-ciamrepopath) |  | `string` | single | Where the file lives in version control (the same for every environment) |
| [`ciamRepoUrl`](#a-ciamrepourl) |  | `url` | single | The repository a job is defined in |
| [`ciamDeploysTo`](#a-ciamdeploysto) |  | `string` | multi | An environment a pipeline deploys to, as its CI system names it |
| [`ciamFoundOn`](#a-ciamfoundon) |  | `dn` | multi | A server a job was found on |
| [`ciamCriticality`](core.md#a-ciamcriticality) |  | `enum` | single | Business criticality |
| [`ciamInEnvironment`](infrastructure.md#a-ciaminenvironment) |  | `dn` | multi | An environment a shared entry (a host baseline, a job) applies in; an overlay of it too. With neither this nor ciamOnProvider, the entry applies in every environment |
| [`ciamOnProvider`](infrastructure.md#a-ciamonprovider) |  | `vocab` | multi | A provider (a ciamCloudProvider value) in whose environments a shared entry (a host baseline, a job) applies |
| [`ciamJobName`](#a-ciamjobname) |  | `string` | single | A job's name as its own system shows it (a workflow's name:, a CI project's name), apart from the entry's name |
| [`ciamCiSystem`](#a-ciamcisystem) |  | `string` | single | The CI system a pipeline was imported from (the importing package's system: github-actions, gitlab-ci, ...): a re-import from it removes the pipelines its repositories no longer define |

<a id="c-ciamjobbinding"></a>
### ciamJobBinding

Where an environment runs a job (a function, a pipeline): the provider's reference for it

OID `1.3.6.1.4.1.32473.1.2.49` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) | yes | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamSchedule`](#a-ciamschedule) |  | `string` | multi | When a job runs, as its system writes it (a cron expression, rate(1 hour), OnCalendar=daily, ...) |
| [`ciamRuntime`](#a-ciamruntime) |  | `string` | single | What a job runs in: a language runtime (python3.12), a runner image (ubuntu-24.04), ... |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamcisystem"></a>`ciamCiSystem` | `1.3.6.1.4.1.32473.1.1.660` | `string` | meta | single |  | The CI system a pipeline was imported from (the importing package's system: github-actions, gitlab-ci, ...): a re-import from it removes the pipelines its repositories no longer define |
| <a id="a-ciamcodebundle"></a>`ciamCodeBundle` | `1.3.6.1.4.1.32473.1.1.228` | `dn` | intent | single |  | The bundle holding the code the job runs |
| <a id="a-ciamcommand"></a>`ciamCommand` | `1.3.6.1.4.1.32473.1.1.222` | `string` | intent | single |  | What a job runs (a command line, a handler, an entry point); never stored when it holds a secret |
| <a id="a-ciamdeploysto"></a>`ciamDeploysTo` | `1.3.6.1.4.1.32473.1.1.230` | `string` | intent | multi |  | An environment a pipeline deploys to, as its CI system names it |
| <a id="a-ciamfoundon"></a>`ciamFoundOn` | `1.3.6.1.4.1.32473.1.1.231` | `dn` | observed | multi |  | A server a job was found on |
| <a id="a-ciamjobkind"></a>`ciamJobKind` | `1.3.6.1.4.1.32473.1.1.219` | enum: `cron`, `timer`, `scheduled-task`, `function`, `pipeline`, `other` | intent | single |  | What a job is: a cron entry, a systemd timer, a scheduled task, a serverless function, a pipeline |
| <a id="a-ciamjobname"></a>`ciamJobName` | `1.3.6.1.4.1.32473.1.1.659` | `string` | meta | single |  | A job's name as its own system shows it (a workflow's name:, a CI project's name), apart from the entry's name |
| <a id="a-ciamjobrole"></a>`ciamJobRole` | `1.3.6.1.4.1.32473.1.1.225` | `string` | intent | single |  | The binding role that realizes the job in each environment (its function, its pipeline) |
| <a id="a-ciamrepourl"></a>`ciamRepoUrl` | `1.3.6.1.4.1.32473.1.1.229` | `url` | meta | single |  | The repository a job is defined in |
| <a id="a-ciamrunsas"></a>`ciamRunsAs` | `1.3.6.1.4.1.32473.1.1.223` | `string` | intent | single |  | The account a job runs as (an OS user, a service account, a runner) |
| <a id="a-ciamruntime"></a>`ciamRuntime` | `1.3.6.1.4.1.32473.1.1.224` | `string` | intent | single |  | What a job runs in: a language runtime (python3.12), a runner image (ubuntu-24.04), ... |
| <a id="a-ciamschedule"></a>`ciamSchedule` | `1.3.6.1.4.1.32473.1.1.220` | `string` | intent | multi |  | When a job runs, as its system writes it (a cron expression, rate(1 hour), OnCalendar=daily, ...) |
| <a id="a-ciamsecretname"></a>`ciamSecretName` | `1.3.6.1.4.1.32473.1.1.227` | `string` | meta | multi |  | A secret the job expects by name in its own system (a CI secret, an environment variable from a secret store): the name, never the value |
| <a id="a-ciamtrigger"></a>`ciamTrigger` | `1.3.6.1.4.1.32473.1.1.221` | `string` | intent | multi |  | What else starts a job: manual, push, pull-request, http, queue, event, boot, ... |
| <a id="a-ciamusesrole"></a>`ciamUsesRole` | `1.3.6.1.4.1.32473.1.1.226` | `string` | intent | multi |  | A binding role the job uses (a secret, a service name, a storage location): each environment binds it |

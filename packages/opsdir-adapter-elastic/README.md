# opsdir-adapter-elastic

opsdir SIEM add-on for Elastic Security (task 552, milestone 109; Serverless and Fleet shipping task 555; decisions on the milestone). It renders the Elastic data streams an environment keeps logs in, with how long Elasticsearch keeps them searchable (an index lifecycle policy, or on Elastic Cloud Serverless the data stream lifecycle) and in all (a snapshot archive). It renders the detections its alert rules are realized by there, as ES|QL detection rules, and the Fleet policies Elastic Agent ships the products' logs there with (log files on servers, container output on Kubernetes). All of it comes as Elasticsearch and Kibana API documents and as Terraform for Elastic's `elastic/elasticstack` provider. It reads the retention and the rules back from the Elasticsearch and Kibana APIs (read-only) and from its own documents (the round trip).

**Applies to** environments whose stack declares it (`ciamStackRole: siem`, `ciamAdapter: elastic`). It keeps the log destinations of kind `siem-index` whose `ciamProviderRef` is a logs data stream named as Elastic names them: `logs-<dataset>-<namespace>`, where dataset and namespace are lowercase letters, digits, `.` and `_`, don't start with `.` or `_`, and are at most 100 characters (`Adapter.siem_indexes`). The provider adapters (AWS, Azure, Google Cloud) leave those destinations to it (`Services.siem_keeper`).

**Depends on** `opsdir` (the observability domain's log routes, sources, alarms and SIEM helpers, estate settings, render notes, inventory placement, collection sources) and `opsdir-format-terraform` (HCL). At run time it needs Elasticsearch and Kibana 8.x or 9.x: self-managed, ECE, ECK or Elastic Cloud Hosted (the `stateful` offering, its default), or Elastic Cloud Serverless (`serverless`). Its pinned defaults are the current releases: Elastic Stack 9.5.5, elasticstack provider `~> 0.16.6` (Fleet policies' `inputs` map since 0.14), and the Fleet integration packages `filestream` 2.5.1 (Kibana 9.4 or later) and `kubernetes` 1.85.5 (Kibana 9.5 or later); on Kibana 8.19 set the version settings below to 1.2.0 and 1.83.1, the latest there.

## The record

| What | Entry |
|---|---|
| The offering of Elastic | the stack component's `ciamOffering` (core attribute; this adapter's vocabulary): `stateful` (not recorded: self-managed, ECE, ECK, Elastic Cloud Hosted) or `serverless` (Elastic Cloud Serverless) |
| An Elastic data stream | `ciamLogDestination` (`ciamDestinationKind: siem-index`, `ciamProviderRef: logs-<dataset>-<namespace>`), with `ciamRetentionDays` (days searchable; `0` kept indefinitely), `ciamTotalRetentionDays` (days kept in all, archive included) and `ciamArchiveRef` (the snapshot repository keeping the archive, e.g. Elastic Cloud's `found-snapshots`) |
| What goes there | a `ciamLogRoute` whose `ciamLogDestinationRole` the environment binds to that stream; the core holds the stream's total days to the route's obligation (`check_logs`) |
| What ships there | the route's `ciamPublishedBy` server roles and the logs their products declare (log files under each server's `ciamInstallRoot`, container output on Kubernetes), as for every log route |
| A detection | a `ciamAlarmBinding` with `ciamProviderRef` its rule's `rule_id`, `ciamRealizes` the alert rule, `ciamLogDestinationRole` the stream it searches, `ciamMetric` the ES|QL search returning the matching events (`FROM <stream> \| WHERE ...`), and `ciamSearchLanguage` when the search isn't ES|QL (`kuery`, `lucene`, `eql`: the vocabulary this adapter declares; not recorded means ES|QL) |
| A rows detection and what it names | the detection's `ciamDetectionMode: rows` (its search returns one row per finding, its own threshold included) and `ciamEntityMapping` (`<entity> <identifier>=<result column>`, core attributes, milestone 109) |
| What it detects in ATT&CK | the alert rule's `ciamAttackTactic` (short names, `credential-access`) and `ciamAttackTechnique` (IDs, `T1110.003`) |

## What it renders

Per environment, nothing environment-neutral, in the render targets chosen (both by default):

| File | Target | Content |
|---|---|---|
| `elastic/api/ilm-policies.json` | `api` | Per data stream recording a retention, the ILM policy `opsdir-<stream>` as `GET _ilm/policy` answers it (`PUT _ilm/policy/<name>` takes `{"policy": ...}`): hot phase rollover at `max_age 1d` or `max_primary_shard_size 50gb`; delete phase `min_age` = days searchable (Elasticsearch counts it from rollover, so logs are deleted within a day after that), with `wait_for_snapshot` on the stream's snapshot policy when it is archived; no delete phase when kept indefinitely; `_meta` naming the stream |
| `elastic/api/component-templates.json` | `api` | The component template `<type>-<dataset>@custom` setting `index.lifecycle.name` to that policy. This is the hook Elastic documents for one dataset's own lifecycle, composed by the dataset's integration template (Fleet's) for every namespace |
| `elastic/api/slm-policies.json` | `api` | When the stream keeps logs longer in all than searchable and records `ciamArchiveRef`: the SLM policy `opsdir-<stream>` as `GET _slm/policy` answers it. It runs every day at 01:30, snapshots the stream (`include_global_state: false`) into that repository, and expires each snapshot after the total minus the searchable days (none when kept indefinitely). The last snapshot holding a backing index is taken as ILM deletes it, so logs are kept that much longer in all |
| `elastic/api/data-stream-lifecycles.json` | `api` | On Serverless, instead of the three files above: per data stream recording a retention, its data stream lifecycle as `GET _data_stream/<stream>/_lifecycle` answers it (`PUT` takes its `lifecycle`): `enabled`, `data_retention` the days searchable (none when kept indefinitely) |
| `elastic/api/detection-rules.ndjson` | `api` | The detections as ES\|QL rules, one per line, as `POST /api/detection_engine/rules/_import` takes them |
| `elastic/api/fleet-agent-policies.json` | `api` | The Fleet agent policies shipping the logs (`items`), each as `POST /api/fleet/agent_policies` takes it (below) |
| `elastic/api/fleet-package-policies.json` | `api` | Their integration policies (`items`), each as `POST /api/fleet/package_policies?format=simplified` takes it. Install the integration package first (`POST /api/fleet/epm/packages/<name>/<version>`) |
| `elastic/terraform/versions.tf` | `terraform` | `elastic/elasticstack` `~> 0.16.6`, with empty `elasticsearch` and `kibana` connection blocks. The endpoints and API keys come from the provider's environment variables (`ELASTICSEARCH_ENDPOINTS`, `ELASTICSEARCH_API_KEY`, `KIBANA_ENDPOINT`, `KIBANA_API_KEY`) and never appear in the files |
| `elastic/terraform/main.tf` | `terraform` | The render notes as `# NOTE` comments, then the same documents as `elasticstack_elasticsearch_index_lifecycle`, `elasticstack_elasticsearch_component_template`, `elasticstack_elasticsearch_snapshot_lifecycle` (on Serverless `elasticstack_elasticsearch_data_stream_lifecycle` instead), `elasticstack_kibana_security_detection_rule` (with `space_id` when the setting below isn't `default`), and `elasticstack_fleet_integration` (installing the packages), `elasticstack_fleet_agent_policy` and `elasticstack_fleet_integration_policy` (each stream's `vars` as `jsonencode`). Checked with `terraform fmt -check`, `init` and `validate` against provider 0.16.6 (the package test marked `terraform`) |

A detection rule is the detection's search counted per window, every window of the alert rule's evaluation period breaching (`alarms.detection_condition`, as the Splunk and Sentinel renders count it): `<search> | STATS events = COUNT(*) BY slot = BUCKET(@timestamp, <window> seconds) | WHERE events > <n> | STATS breaching = COUNT(*) | WHERE breaching >= <windows>` (`>=` for `ge`). It is `type`/`language` `esql`, `interval` the period, `from` `now-<period>`, `to` `now`. The detection engine limits the search to that range on `@timestamp`, and each row it returns is an alert. Its `rule_id` is the detection's `ciamProviderRef` and its `name` the alert rule. Its `description` is `opsdir: realizes alert rule <rule>` (read back). `severity`/`risk_score` come from the rule's `ciamSeverity`: `sev0` critical 99, `sev1` high 73, `sev2` medium 47, `sev3` and `sev4` low 21, medium 47 when none. It is tagged `opsdir` and enabled. A threshold rule can't require every window, so ES|QL is the one language rendered.

**ATT&CK and entities (milestone 109, task 587).** A **rows** detection (`ciamDetectionMode: rows`) runs its search as written, no count wrapper: each row is an alert, run every evaluation period of its alert rule (`ciamEvaluationPeriod`, `5m` when none) over that period. The rule's MITRE ATT&CK tactics and techniques become the rule's `threat` array as the Kibana detection engine API documents it: an entry per recorded tactic (`framework` `MITRE ATT&CK`, `tactic` `{id, name, reference}`, e.g. `TA0006`, `Credential Access`, `https://attack.mitre.org/tactics/TA0006/`), holding the recorded techniques that serve that tactic in ATT&CK (`{id, name, reference}`, `https://attack.mitre.org/techniques/T1110/`), each recorded sub-technique under its parent's `subtechnique` (`https://attack.mitre.org/techniques/T1110/003/`). The record holds only IDs and short names, and the API requires every name, so the names and the tactics each technique serves come from the core's ATT&CK table (ATT&CK Enterprise v20, `opsdir.domains.observability.attack`, generated from MITRE's STIX bundle by `opsdir/scripts/gen-attack.py`); `attack.py` here shapes only the `threat` array. A rows detection's entity mappings name the result columns an alert is about: they become the rule's `investigation_fields` (`{"field_names": [...]}`; the provider's list), the alert's highlighted fields. An ES|QL rule's alert holds the row's columns. Elastic has no entity mapping of its own: its entity risk scoring groups alerts by `user.name` and `host.name`. `severity_mapping` and `risk_score_mapping` aren't rendered: the record holds no per-finding severity. The Terraform validates against provider 0.16.6.

On **Elastic Cloud Serverless** there is no index lifecycle and no snapshots: a stream keeps logs as its data stream lifecycle says, set on the stream itself, so streams sharing a dataset don't share it. A stream the record keeps longer in all than searchable can't be archived there (a blocker below).

**Shipping (Fleet).** Elastic Agent ships the logs, enrolled in Fleet policies the render writes (they replace task 552's action note):
- **Log files on servers.** Per server role, the agent policy `opsdir-<cloud>-<env>-<role>` (its ID and name; namespace the first stream's; the agents' logs and metrics monitored). Per role and log file, a Custom Logs (Filestream) integration policy `opsdir-<cloud>-<env>-<role>-<file>` (package `filestream`, input `filestream-filestream`, stream `filestream.filestream`): `paths` the file's glob under every install root the role's servers record (a root a server lacks matches nothing on it), `data_stream.dataset` and namespace the stream's. JSON lines are decoded into the event (`parsers`: `ndjson`, `target ""`, `overwrite_keys`, `add_error_key`; a mixed file `ignore_decoding_error`), records spanning lines are joined from the log's first-line pattern (`multiline`, `negate`, `match after`), and when the routes take only some of a file's lines, the others are dropped (`processors`: a `drop_event` unless one of the clauses keeping the routes' kinds holds: a rule's field starting with its prefix as `regexp ^prefix`, a field being there as `has_fields`). A file goes to one stream: the first route's.
- **Container output on Kubernetes.** The agent policy `opsdir-<cloud>-<env>-kubernetes`, and per role and log a Kubernetes integration policy `opsdir-<cloud>-<env>-<role>-<container or "containers">` (package `kubernetes`) with only its container logs stream (`container-logs-filestream` / `kubernetes.container_logs`) enabled, every other input off. Its `condition` picks the role's pods by the label the deployment kits set, the namespaces the role runs in, and the log's container: `${kubernetes.labels.opsdir.io/role} == '<role>' and (${kubernetes.namespace} == '<ns>' ...) and ${kubernetes.container.name} == '<sidecar>'` (or `!=` the role's other logs' containers for its main output). Its `data_stream.dataset` and namespace are the stream's. Config templating leaves the label dotted, as written. The condition was checked with Elastic Agent 9.5.5 (standalone, a local kind cluster): only the labelled pod's chosen container was collected, and the dedotted form `opsdir_io/role` matched nothing. Container lines aren't decoded: a route taking only some lines ships the container whole (a note).
- The `parsers` and `processors` were checked with Filebeat 9.5.5 (Elastic Agent's filestream engine) on JSON, mixed and multi-line files: the kinds kept and dropped as the routes say.

A rule Terraform or the import creates runs as the API key that created it (Kibana keeps the key with the rule): create them with the Elastic team's rule-managing key, never the collector's read-only one.

Estate settings:
- `elastic-kibana-space` (default `default`): the Kibana space the rules are rendered into and read from.
- `elastic-filestream-version` (default `2.5.1`, needs Kibana 9.4 or later; 1.2.0 on Kibana 8.19): the Custom Logs (Filestream) package version the file policies use.
- `elastic-kubernetes-version` (default `1.85.5`, needs Kibana 9.5 or later; 1.83.1 on Kibana 8.19): the Kubernetes package version the container policies use.

## What it leaves to a person (render notes)

| Note | Severity |
|---|---|
| Who a detection notifies (its rule actions and connectors): set in Kibana | action |
| A stream's policy takes effect for backing indices created from the next rollover, and only where the stream's index template composes `<type>-<dataset>@custom` (Fleet integration templates do; the built-in `logs` template doesn't). The note gives the switch for existing backing indices (`PUT <stream>/_settings` `index.lifecycle.name`), and says opsdir writes the whole component template | action |
| A stream keeping logs longer in all than searchable that records no `ciamArchiveRef`: no snapshot policy, so logs are deleted at the searchable days | action |
| Streams sharing a dataset: its component template attaches one policy to every namespace. A note when they keep logs as long, a blocker when they don't | note / blocker |
| A stream recording no retention: no policy rendered | note |
| A detection whose condition a rule can't count (a threshold that isn't a rate or a count; a comparison other than `gt`/`ge`), whose search isn't ES\|QL, or whose search doesn't start `FROM` the stream it searches | blocker |
| A detection that records no search | note |
| An alert rule's ATT&CK techniques its threat array leaves out: serving none of its recorded tactics, or not in ATT&CK v20; its tactics ATT&CK v20 retired (`defense-evasion`) | note |
| A rows detection mapping an account name or a host name to a column other than `user.name` / `host.name`: its alerts add to no entity's risk score (rename the column in the search) | note |
| Per server role, enrolling its servers (named) in its agent policy: `elastic-agent install --url <Fleet Server URL> --enrollment-token <its token>` (never rendered), and the package to install first when applying the API documents | action |
| Running Elastic Agent on the clusters as Fleet's DaemonSet enrolled in the Kubernetes agent policy (`FLEET_ENROLL`, `FLEET_URL`, `FLEET_ENROLLMENT_TOKEN` from a Secret); a catch-all Kubernetes policy also collecting the same output into `logs-kubernetes.container_logs-*` | action |
| A route taking only some of a container's lines: shipped whole | note |
| A log file or container output two routes ship to different streams: the first route's stream takes it | blocker |
| Serverless: each stream's lifecycle applies once the stream exists (Fleet creates it at its first event) | action |
| Serverless: the project's maximum retention must allow the longest days rendered (a Security project's `search_lake` `max_retention_days`, 396 unless changed) | action |
| Serverless: a stream kept indefinitely takes the project's default retention | note |
| Serverless: a stream kept longer in all than searchable (no archive to restore: they are deleted after the searchable days); a `ciamArchiveRef` with no days past them is an action | blocker |

## What it reads

| Importer | Reads | Into |
|---|---|---|
| `elastic/elasticsearch` | `<cloud>/<env>/data-streams.json` (`GET /_data_stream`), `ilm-policies.json` (`GET /_ilm/policy`), `slm-policies.json` (`GET /_slm/policy`), `cluster.json` (`GET /`), `component-templates.json` and `data-stream-lifecycles.json` (the render's) | the environment's Elastic data streams (`logs`) |
| `elastic/kibana` | `<cloud>/<env>/detection-rules.json` (`GET /api/detection_engine/rules/_find`; further pages `detection-rules.<n>.json`) or `detection-rules.ndjson` (an export, or the render's file) | its detections (`alarm`) |

How a stream's days are read:
- **Searchable days.** When the data stream lifecycle manages the stream (`next_generation_managed_by`, or only its lifecycle is given), its `effective_retention` (what a global or project default or maximum leaves it), else its `data_retention` (neither: indefinitely). Otherwise its ILM policy's delete-phase `min_age` (no delete phase: indefinitely; days that aren't whole are named). The policy is the one the stream reports (`ilm_policy`), else the one its dataset's component template attaches, else the one whose `_meta` names it.
- **Days in all.** When a snapshot policy covers the stream (`config.indices`, wildcards included), the searchable days plus the policy's `retention.expire_after` (the longest such policy; none: indefinitely). Its repository is the archive.

A setting the answers don't give is left as the record has it, never read as zero. Streams of other types and system streams are left out. When `cluster.json`'s `version.build_flavor` (`serverless` on Elastic Cloud Serverless) disagrees with the offering the stack declares (`ciamOffering`), a notice says so. The Fleet policies aren't read back: nothing in the record holds them, they derive from the routes.

How a rule is read:
- It realizes the rule its description names (role `alarm-<rule>`).
- It searches the stream its ES|QL `FROM` names first, or the first of its `index` list.
- Its search loses the condition the render wrapped around it.
- Its language is recorded when it isn't ES|QL.
- A rule of another type (threshold, query, EQL) is named: only its search is read, not its condition.

The Kibana importer also reports each stream a rule searches, with its kind only, which links the rule to the record's stream. Notices about the environment's other log destinations and alarms (a cloud's, another SIEM's) are left out.

`opsdir collect` runs read-only collectors against the environment's collection sources for each importer (`ciamCollectionSource`: the Elasticsearch endpoint for `elastic/elasticsearch`, the Kibana endpoint for `elastic/kibana`):
- `elastic/elasticsearch` makes the four GETs.
- `elastic/kibana` pages `_find` 1000 rules at a time, under `/s/<space>` for a non-default space.
- The credential the source's `ciamCredentialRole` references is sent as `Authorization: ApiKey <encoded key>` (`ciamCredentialScheme: api-key`: an Elasticsearch API key's `encoded` value), as Bearer or as Basic. Its `ciamCaRole` is the trust anchor.

The reader needs no write privilege:
- Elasticsearch: cluster `read_ilm`, `read_slm` and `monitor` (`GET /`), and `view_index_metadata` on the `logs-*` streams.
- Kibana: Security, Rules and Exceptions, Rules: Read, carried by the API key's role descriptor for the `kibana-.kibana` application. Check the exact privilege name with `GET _security/privilege` on the target version.

Elastic's own pages disagree on two of these: the SLM read privilege (`read_slm` in the privilege reference, `manage_slm` on the GET-policy page) and the template read privilege (`monitor` in 8.19, `manage_index_templates` in the current API page).

## Known limits

- **Not validated live.** Not validated against a live cluster (7.2). The ES|QL wrap follows Elastic's documented `STATS ... BY BUCKET` and the engine's own time filter, but hasn't run.
- **Days are a floor plus at most a day.** A phase's age counts from rollover. Deletion is asynchronous. Snapshot expiry also depends on when snapshots run, and `min_count`/`max_count` on a policy the Elastic team keeps can hold or drop snapshots. The total read back is searchable plus `expire_after`, not a guarantee.
- **Serverless.** Retention is the data stream lifecycle only, and there is no archive to restore (no user snapshots: "anticipated in a future release"). Elastic's pages disagree on a Serverless stream's default retention (indefinite in the overview, 30 days for logs in the template defaults, 396 days for a Security project's `search_lake` default and maximum); the render names the project settings instead of assuming one. A component template's `template.lifecycle` (for streams not created yet) isn't rendered: provider 0.16.6's component template has no such block, and both targets say the same thing.
- **One policy per dataset.** A dataset's `@custom` component template attaches one policy to all its namespaces. A per-namespace policy needs Elastic's cloned-template procedure, by hand.
- **Detections.** Detections are the searches each environment records. Nothing translates another SIEM's search into ES|QL, and the products don't declare detections yet. Exceptions, suppression and rule actions aren't rendered. ATT&CK names follow v20 (2026-10-13), the version the core follows: v19 split Defense Evasion into Stealth (`TA0005`) and Defense Impairment (`TA0112`), so a rule still recording `defense-evasion` has that tactic left out of its `threat` array (a note) until its owner applies the planner's fix choosing the successor. The importer doesn't read a rule's `threat` or `investigation_fields` back (the alert rule's ATT&CK is its intent, and the fields don't say which entity they name).
- **Shipping.** The Fleet policies are rendered, not applied or enrolled, and not read back. Not validated against a live Fleet: the policy bodies follow the packages' manifests (filestream 2.5.1, kubernetes 1.85.5) and Fleet's simplified format, the Terraform validates against provider 0.16.6, and the agent-side `condition`, `parsers` and `processors` ran locally (above). The variables of older package versions (the settings' 8.19 values) aren't checked. ECS normalization is the integrations' job: the record holds no field mapping.
- **Government clouds.** Elastic Cloud runs on AWS GovCloud (US) `us-gov-east-1`; a hosted Fleet Server there isn't explicitly documented (Serverless Security and Observability projects include one). Elastic's trust FAQ and FedRAMP documentation say Moderate and High; its cloud security page and subscription matrix say Moderate. No DoD impact level, and no managed offering in Azure Government, was found. Establishing that is the operator's authorization package; this add-on says nothing about it.

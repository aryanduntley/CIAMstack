# opsdir-adapter-elastic

opsdir SIEM add-on for Elastic Security (task 552, milestone 109; decision on the task). It renders the Elastic data streams an environment keeps logs in, with how long Elasticsearch keeps them searchable (an index lifecycle policy) and in all (a snapshot archive). It also renders the detections its alert rules are realized by there, as ES|QL detection rules. Both come as Elasticsearch and Kibana API documents and as Terraform for Elastic's `elastic/elasticstack` provider. It reads them back from the Elasticsearch and Kibana APIs (read-only) and from its own documents (the round trip).

**Applies to** environments whose stack declares it (`ciamStackRole: siem`, `ciamAdapter: elastic`). It keeps the log destinations of kind `siem-index` whose `ciamProviderRef` is a logs data stream named as Elastic names them: `logs-<dataset>-<namespace>`, where dataset and namespace are lowercase letters, digits, `.` and `_`, don't start with `.` or `_`, and are at most 100 characters (`Adapter.siem_indexes`). The provider adapters (AWS, Azure, Google Cloud) leave those destinations to it (`Services.siem_keeper`).

**Depends on** `opsdir` (the observability domain's log routes, sources, alarms and SIEM helpers, estate settings, render notes, inventory placement, collection sources) and `opsdir-format-terraform` (HCL). At run time it needs Elasticsearch and Kibana 8.x or 9.x: self-managed, ECE, ECK or Elastic Cloud Hosted. Serverless is not covered (see Known limits). Its pinned default is the current release line: Elastic Stack 9.5.5 and elasticstack provider `~> 0.16.6`.

## The record

| What | Entry |
|---|---|
| An Elastic data stream | `ciamLogDestination` (`ciamDestinationKind: siem-index`, `ciamProviderRef: logs-<dataset>-<namespace>`), with `ciamRetentionDays` (days searchable; `0` kept indefinitely), `ciamTotalRetentionDays` (days kept in all, archive included) and `ciamArchiveRef` (the snapshot repository keeping the archive, e.g. Elastic Cloud's `found-snapshots`) |
| What goes there | a `ciamLogRoute` whose `ciamLogDestinationRole` the environment binds to that stream; the core holds the stream's total days to the route's obligation (`check_logs`) |
| A detection | a `ciamAlarmBinding` with `ciamProviderRef` its rule's `rule_id`, `ciamRealizes` the alert rule, `ciamLogDestinationRole` the stream it searches, `ciamMetric` the ES|QL search returning the matching events (`FROM <stream> \| WHERE ...`), and `ciamSearchLanguage` when the search isn't ES|QL (`kuery`, `lucene`, `eql`: the vocabulary this adapter declares; not recorded means ES|QL) |

## What it renders

Per environment, nothing environment-neutral, in the render targets chosen (both by default):

| File | Target | Content |
|---|---|---|
| `elastic/api/ilm-policies.json` | `api` | Per data stream recording a retention, the ILM policy `opsdir-<stream>` as `GET _ilm/policy` answers it (`PUT _ilm/policy/<name>` takes `{"policy": ...}`): hot phase rollover at `max_age 1d` or `max_primary_shard_size 50gb`; delete phase `min_age` = days searchable (Elasticsearch counts it from rollover, so logs are deleted within a day after that), with `wait_for_snapshot` on the stream's snapshot policy when it is archived; no delete phase when kept indefinitely; `_meta` naming the stream |
| `elastic/api/component-templates.json` | `api` | The component template `<type>-<dataset>@custom` setting `index.lifecycle.name` to that policy. This is the hook Elastic documents for one dataset's own lifecycle, composed by the dataset's integration template (Fleet's) for every namespace |
| `elastic/api/slm-policies.json` | `api` | When the stream keeps logs longer in all than searchable and records `ciamArchiveRef`: the SLM policy `opsdir-<stream>` as `GET _slm/policy` answers it. It runs every day at 01:30, snapshots the stream (`include_global_state: false`) into that repository, and expires each snapshot after the total minus the searchable days (none when kept indefinitely). The last snapshot holding a backing index is taken as ILM deletes it, so logs are kept that much longer in all |
| `elastic/api/detection-rules.ndjson` | `api` | The detections as ES\|QL rules, one per line, as `POST /api/detection_engine/rules/_import` takes them |
| `elastic/terraform/versions.tf` | `terraform` | `elastic/elasticstack` `~> 0.16.6`, with empty `elasticsearch` and `kibana` connection blocks. The endpoints and API keys come from the provider's environment variables (`ELASTICSEARCH_ENDPOINTS`, `ELASTICSEARCH_API_KEY`, `KIBANA_ENDPOINT`, `KIBANA_API_KEY`) and never appear in the files |
| `elastic/terraform/main.tf` | `terraform` | The render notes as `# NOTE` comments, then the same documents as `elasticstack_elasticsearch_index_lifecycle`, `elasticstack_elasticsearch_component_template`, `elasticstack_elasticsearch_snapshot_lifecycle` and `elasticstack_kibana_security_detection_rule` (with `space_id` when the setting below isn't `default`). Checked with `terraform fmt -check` and `terraform validate` against provider 0.16.6 |

A detection rule is the detection's search counted per window, every window of the alert rule's evaluation period breaching (`alarms.detection_condition`, as the Splunk and Sentinel renders count it): `<search> | STATS events = COUNT(*) BY slot = BUCKET(@timestamp, <window> seconds) | WHERE events > <n> | STATS breaching = COUNT(*) | WHERE breaching >= <windows>` (`>=` for `ge`). It is `type`/`language` `esql`, `interval` the period, `from` `now-<period>`, `to` `now`. The detection engine limits the search to that range on `@timestamp`, and each row it returns is an alert. Its `rule_id` is the detection's `ciamProviderRef` and its `name` the alert rule. Its `description` is `opsdir: realizes alert rule <rule>` (read back). `severity`/`risk_score` come from the rule's `ciamSeverity`: `sev0` critical 99, `sev1` high 73, `sev2` medium 47, `sev3` and `sev4` low 21, medium 47 when none. It is tagged `opsdir` and enabled. A threshold rule can't require every window, so ES|QL is the one language rendered.

A rule Terraform or the import creates runs as the API key that created it (Kibana keeps the key with the rule): create them with the Elastic team's rule-managing key, never the collector's read-only one.

The estate setting `elastic-kibana-space` (default `default`) names the Kibana space the rules are rendered into and read from.

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
| What Elastic Agent must collect from the servers into each stream (role, hosts, file, stream): a Fleet policy, the Elastic team's | action |
| Container output to an Elastic stream: not shipped by anything rendered | blocker |

## What it reads

| Importer | Reads | Into |
|---|---|---|
| `elastic/elasticsearch` | `<cloud>/<env>/data-streams.json` (`GET /_data_stream`), `ilm-policies.json` (`GET /_ilm/policy`), `slm-policies.json` (`GET /_slm/policy`), `component-templates.json` (the render's) | the environment's Elastic data streams (`logs`) |
| `elastic/kibana` | `<cloud>/<env>/detection-rules.json` (`GET /api/detection_engine/rules/_find`; further pages `detection-rules.<n>.json`) or `detection-rules.ndjson` (an export, or the render's file) | its detections (`alarm`) |

How a stream's days are read:
- **Searchable days.** When the data stream lifecycle manages the stream (`next_generation_managed_by`), its `data_retention` (none: indefinitely). Otherwise its ILM policy's delete-phase `min_age` (no delete phase: indefinitely; days that aren't whole are named). The policy is the one the stream reports (`ilm_policy`), else the one its dataset's component template attaches, else the one whose `_meta` names it.
- **Days in all.** When a snapshot policy covers the stream (`config.indices`, wildcards included), the searchable days plus the policy's `retention.expire_after` (the longest such policy; none: indefinitely). Its repository is the archive.

A setting the answers don't give is left as the record has it, never read as zero. Streams of other types and system streams are left out.

How a rule is read:
- It realizes the rule its description names (role `alarm-<rule>`).
- It searches the stream its ES|QL `FROM` names first, or the first of its `index` list.
- Its search loses the condition the render wrapped around it.
- Its language is recorded when it isn't ES|QL.
- A rule of another type (threshold, query, EQL) is named: only its search is read, not its condition.

The Kibana importer also reports each stream a rule searches, with its kind only, which links the rule to the record's stream. Notices about the environment's other log destinations and alarms (a cloud's, another SIEM's) are left out.

`opsdir collect` runs read-only collectors against the environment's collection sources for each importer (`ciamCollectionSource`: the Elasticsearch endpoint for `elastic/elasticsearch`, the Kibana endpoint for `elastic/kibana`):
- `elastic/elasticsearch` makes the three GETs.
- `elastic/kibana` pages `_find` 1000 rules at a time, under `/s/<space>` for a non-default space.
- The credential the source's `ciamCredentialRole` references is sent as `Authorization: ApiKey <encoded key>` (`ciamCredentialScheme: api-key`: an Elasticsearch API key's `encoded` value), as Bearer or as Basic. Its `ciamCaRole` is the trust anchor.

The reader needs no write privilege:
- Elasticsearch: cluster `read_ilm` and `read_slm`, and `view_index_metadata` on the `logs-*` streams.
- Kibana: Security, Rules and Exceptions, Rules: Read, carried by the API key's role descriptor for the `kibana-.kibana` application. Check the exact privilege name with `GET _security/privilege` on the target version.

Elastic's own pages disagree on two of these: the SLM read privilege (`read_slm` in the privilege reference, `manage_slm` on the GET-policy page) and the template read privilege (`monitor` in 8.19, `manage_index_templates` in the current API page).

## Known limits

- **Not validated live.** Not validated against a live cluster (7.2). The ES|QL wrap follows Elastic's documented `STATS ... BY BUCKET` and the engine's own time filter, but hasn't run.
- **Days are a floor plus at most a day.** A phase's age counts from rollover. Deletion is asynchronous. Snapshot expiry also depends on when snapshots run, and `min_count`/`max_count` on a policy the Elastic team keeps can hold or drop snapshots. The total read back is searchable plus `expire_after`, not a guarantee.
- **Serverless isn't rendered.** It has no ILM and no user snapshots, so a Serverless stream would need the data stream lifecycle (`data_retention`) instead. The reader already reads the data stream lifecycle.
- **One policy per dataset.** A dataset's `@custom` component template attaches one policy to all its namespaces. A per-namespace policy needs Elastic's cloned-template procedure, by hand.
- **Detections.** Detections are the searches each environment records. Nothing translates another SIEM's search into ES|QL, and the products don't declare detections yet. MITRE mappings, exceptions, suppression and rule actions aren't rendered.
- **Shipping isn't rendered.** Elastic Agent and Fleet integration policies are the Elastic team's, named as an action. Container output is a blocker. ECS normalization is the integrations' job: the record holds no field mapping.
- **Government clouds.** Elastic Cloud runs on AWS GovCloud (US) `us-gov-east-1`. Elastic's trust FAQ and FedRAMP documentation say Moderate and High; its cloud security page and subscription matrix say Moderate. No DoD impact level, and no managed offering in Azure Government, was found. Establishing that is the operator's authorization package; this add-on says nothing about it.

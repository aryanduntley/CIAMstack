# opsdir-adapter-splunk

opsdir SIEM add-on (milestone 6.2e, decision 3046): the Splunk indexes an environment keeps logs in, with their retention, the detections its alert rules are realized by there as scheduled saved searches, and the Universal Forwarder inputs that ship the products' log files to them. It reads them back from its own `.conf` files (the round trip) and from Splunk's management API (read-only).

**Applies to** environments whose stack declares it (`ciamStackRole: siem`, `ciamAdapter: splunk`). It keeps the log destinations of kind `siem-index` whose `ciamProviderRef` is a Splunk index name (lowercase letters, digits, `_` and `-`, not starting with `_` or `-`): `Adapter.siem_indexes`. The provider adapters (AWS, Azure, Google Cloud) leave those destinations to it (`Services.siem_keeper`), so a route to a Splunk index is not one of their blockers. On servers it works beside `opsdir-adapter-ansible`, which places its forwarder inputs (`HostFile`s).

**Depends on** `opsdir` only: the observability domain's log routes, sources, alarms and SIEM helpers (`opsdir.domains.observability`), estate settings, render notes, the inventory placement (`core.inventory.layout_import`). At run time, Splunk Enterprise or Splunk Cloud Platform and a Universal Forwarder on each server that ships logs. No HTTP Event Collector token is used or rendered.

## The record

| What | Entry |
|---|---|
| A Splunk index | `ciamLogDestination` (`ciamDestinationKind: siem-index`, `ciamProviderRef: <index>`), with `ciamRetentionDays` (days searchable; `0` kept indefinitely) and, when it archives them, `ciamTotalRetentionDays` (days kept in all, archive included) |
| What goes there | a `ciamLogRoute` whose `ciamLogDestinationRole` the environment binds to that index; the core holds the index's total days to the route's obligation (`check_logs`) |
| A detection | a `ciamAlarmBinding` with `ciamProviderRef` its saved search's name, `ciamRealizes` the alert rule, `ciamLogDestinationRole` the index it searches, and `ciamMetric` the search returning the matching events (SPL, `index=<index> ...`) |

## What it renders

Per environment, nothing environment-neutral:

| File | When | Content |
|---|---|---|
| `splunk/apps/opsdir_ciam/default/indexes.conf` | the environment keeps logs in a Splunk index, or runs a detection on one | A header, the `# NOTE` comment of every render note, then a stanza per index: `homePath`, `coldPath`, `thawedPath` under `$SPLUNK_DB/<index>/`, `frozenTimePeriodInSecs` (days searchable × 86400) and, when the total is longer, `archiver.enableDataArchive = true` and `archiver.coldStorageRetentionPeriod` (total days, archive included) |
| `splunk/apps/opsdir_ciam/default/savedsearches.conf` | same | A stanza per detection on a Splunk index here: `description = opsdir: realizes alert rule <rule>`, `search`, `is_scheduled = 1`, `cron_schedule`, `dispatch.earliest_time = -<period>s`, `dispatch.latest_time = now`, `alert_type = number of events`, `alert_comparator = greater than`, `alert_threshold = 0`, `disabled = 0` |
| `<forwarder home>/etc/apps/opsdir_ciam/local/inputs.conf` on the servers (a `HostFile`, placed by Ansible; the forwarder restarted when it changes) | servers of a role ship a file to a Splunk index | Per server role and install root, a `[monitor://<file>]` per log file a route ships to a Splunk index, with `index`, `sourcetype` (`_json` for JSON lines, else `ciam:<role>:<file>`) and `disabled = false` |

The forwarder home is the estate setting `splunk-forwarder-home` (default `/opt/splunkforwarder`).

A detection's condition comes from its alert rule as the core reads it for a SIEM (`alarms.detection_condition`): a rate threshold (`50 /min`) is a count of matching events per window (60 s at least), compared greater than (`gt`) or greater or equal (`ge`), and every window of the rule's evaluation period must breach. The search is the detection's own, then `| bin _time span=<window>s | stats count by _time | where count > <n> | stats count AS breaching | where breaching >= <windows>`; it runs every period (`*/5 * * * *` for 5 minutes) over the period.

## What it leaves to a person (render notes)

| Note | Severity |
|---|---|
| Install the `opsdir_ciam` app where indexes and searches run (Enterprise: deployment server or cluster manager; Cloud: its index management and app installation take these values) | action |
| Where the forwarders send (`outputs.conf`, or Splunk Cloud's forwarder credentials package): the Splunk team's | action |
| Who a detection notifies (its alert actions): set in Splunk | action |
| An index kept indefinitely (searchable or in all): Splunk freezes by age, so the setting isn't rendered and Splunk's default applies | action |
| A detection whose condition a saved search can't count (a threshold that isn't a rate or a count; a comparison other than `gt`/`ge`; a period cron can't run evenly) | blocker |
| A detection that records no search | note |
| A log file the route takes only some lines of: shipped whole (the forwarder doesn't filter by field) | note |
| Records spanning lines: joined where Splunk parses the data (`props.conf`), the Splunk team's | note |
| Container output to a Splunk index: not shipped by this add-on | blocker |
| A file two routes send to different indexes: monitored once, for the first route | blocker |

## What it reads

| Importer | Reads | Into |
|---|---|---|
| `splunk/conf` | `<cloud>/<env>/indexes.conf`, `savedsearches.conf` (its render read back: reading it back changes nothing; or an app's own files) | the environment's Splunk indexes (`logs`) and detections (`alarm`) |
| `splunk/rest` | `<cloud>/<env>/indexes.json` (`GET /services/data/indexes?output_mode=json&count=0`) and `saved-searches.json` (`GET /servicesNS/-/-/saved/searches?output_mode=json&count=0`) | the same |

An index reads as days searchable from `frozenTimePeriodInSecs` (whole days; a remainder is named) and days in all from `archiver.coldStorageRetentionPeriod` when `archiver.enableDataArchive` is on; a setting the source doesn't give is left as the record has it, never read as zero. Splunk's own indexes (a leading `_`) are left out; others the record doesn't have are counted, unless the environment's `roles.json` names their role. A saved search realizes the rule its description names (role `alarm-<rule>`), searches the index its search names first (`index=<name>`), and holds its search without the condition the render wrapped around it. Notices about the environment's other log destinations and alarms (a cloud's) are left out.

`opsdir collect` runs the two GETs (collector `rest`) against the environment's collection source for `splunk/rest` (`ciamCollectionSource`: the management endpoint, `https://<host>:8089`), with the credential its `ciamCredentialRole` references sent as `Authorization: Bearer` (`ciamCredentialScheme: bearer`, a Splunk authentication token) or HTTP Basic, and its `ciamCaRole` as the trust anchor. The reader needs no write capability: a role that lists indexes (`indexes_list_all` where listing is restricted) and can read the saved searches' apps.

## Known limits

- Retention days are a ceiling, not a guarantee: a bucket freezes only when all its events are older, and a size limit (`maxTotalDataSizeMB`, set on every index by default) can freeze it sooner. The `splunk/rest` importer names the size limit of each index the record holds; the record doesn't model it.
- Splunk Cloud Platform: `archiver.*` (Dynamic Data Active Archive) is read where the management API exposes it, which isn't verified on every stack; a self-storage archive (DDSS) keeps data in the customer's bucket, whose retention the record holds on that bucket, not here. The Admin Config Service is not used (listing indexes there needs `indexes_edit`).
- Detections are rendered from the search each environment records; nothing translates one SIEM's search into another's, and the products don't declare detections yet (a follow-up). Enterprise Security correlation searches (`action.correlationsearch.*`, notables, risk) are not rendered.
- **Containers on Kubernetes** (milestone 109, task 575, `kubernetes.py`): per cluster running a role whose containers a route ships to a Splunk index, `kubernetes/splunk-otel-collector/<cluster>-values.yaml` for the Splunk OpenTelemetry Collector chart 0.162.1:
  - the cluster's name and distribution (EKS, AKS or GKE, from the cloud's provider);
  - the index's HEC (`ciamIntakeUrl` + `/services/collector/event`) and the index;
  - logs only;
  - container logs filtered to the routed roles' namespaces (a `filter` operator on `resource["k8s.namespace.name"]`, which the chart's container parser sets from each log file's path);
  - `secret.create: false` with Secret `splunk-otel-collector-hec`, so the token is never in the values.

  Installing the chart and filling the Secret (key `splunk_platform_hec_token`) from the reference the index's `ciamCredentialRole` names are actions. A cluster whose routes ship to more than one index, or an index without an intake URL or credential, is a blocker. Every container in those namespaces is shipped, sidecars included (a note). Checked with `helm template` against the chart's values schema.
- Forwarding from the clouds' log services is the provider adapters' (milestone 109): a log destination's `ciamForwardsToRole` naming a Splunk index makes the AWS adapter render CloudWatch -> Firehose -> HEC (`ciamIntakeUrl`, the token from the secret `ciamCredentialRole` references: `{"hec_token": ...}`, never in the render or state). Pub/Sub (Google Cloud) isn't rendered.
- Normalization (CIM) is the Splunk team's (add-ons, `props.conf`); the record holds no field mapping.
- Splunk's availability in a government cloud (FedRAMP, IL5) is the operator's authorization package to establish; this add-on says nothing about it.

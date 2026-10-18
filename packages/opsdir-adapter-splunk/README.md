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
| A rows detection and what it names | the detection's `ciamDetectionMode: rows` (its search returns one row per finding, its own threshold included) and `ciamEntityMapping` (`<entity> <identifier>=<result column>`, core attributes, milestone 109) |
| What it detects in ATT&CK | the alert rule's `ciamAttackTactic` (short names) and `ciamAttackTechnique` (IDs, `T1110.003`) |
| Whether Splunk Enterprise Security runs there | the stack component's `ciamOffering` (core attribute; this adapter's vocabulary): `platform` (not recorded: Splunk Enterprise or Splunk Cloud Platform on its own) or `enterprise-security` (either, running Splunk ES: detections become correlation searches) |

## What it renders

Per environment, nothing environment-neutral:

| File | When | Content |
|---|---|---|
| `splunk/apps/opsdir_ciam/default/indexes.conf` | the environment keeps logs in a Splunk index, or runs a detection on one | A header, the `# NOTE` comment of every render note, then a stanza per index: `homePath`, `coldPath`, `thawedPath` under `$SPLUNK_DB/<index>/`, `frozenTimePeriodInSecs` (days searchable × 86400) and, when the total is longer, `archiver.enableDataArchive = true` and `archiver.coldStorageRetentionPeriod` (total days, archive included) |
| `splunk/apps/opsdir_ciam/default/savedsearches.conf` | same | A stanza per detection on a Splunk index here: `description = opsdir: realizes alert rule <rule>`, `search`, `is_scheduled = 1`, `cron_schedule`, `dispatch.earliest_time = -<period>s`, `dispatch.latest_time = now`, `alert_type = number of events`, `alert_comparator = greater than`, `alert_threshold = 0`, `disabled = 0`; a rows detection adds `alert.digest_mode = 0`; on Splunk ES, the correlation search settings below |
| `<forwarder home>/etc/apps/opsdir_ciam/local/inputs.conf` on the servers (a `HostFile`, placed by Ansible; the forwarder restarted when it changes) | servers of a role ship a file to a Splunk index | Per server role and install root, a `[monitor://<file>]` per log file a route ships to a Splunk index, with `index`, `sourcetype` (`_json` for JSON lines, else `ciam:<role>:<file>`) and `disabled = false` |

The forwarder home is the estate setting `splunk-forwarder-home` (default `/opt/splunkforwarder`).

A detection's condition comes from its alert rule as the core reads it for a SIEM (`alarms.detection_condition`): a rate threshold (`50 /min`) is a count of matching events per window (60 s at least), compared greater than (`gt`) or greater or equal (`ge`), and every window of the rule's evaluation period must breach. The search is the detection's own, then `| bin _time span=<window>s | stats count by _time | where count > <n> | stats count AS breaching | where breaching >= <windows>`; it runs every period (`*/5 * * * *` for 5 minutes) over the period.

A **rows** detection (`ciamDetectionMode: rows`, milestone 109, task 587) runs its search as written, no count wrapper, every evaluation period of its alert rule (`ciamEvaluationPeriod`, 5 minutes when none) over that period, its alert actions applied to each result (`alert.digest_mode = 0`: one alert per row, as Sentinel's `AlertPerResult`).

**Splunk Enterprise Security** (`ciamOffering: enterprise-security`, task 587). Each detection's saved search is a correlation search, with the settings ES documents for `savedsearches.conf` (research on milestone 109, section 1):
- `action.correlationsearch.enabled = 1` and `action.correlationsearch.label = <alert rule>`.
- `action.correlationsearch.annotations = {"mitre_attack":["T1110.003",...]}`: the alert rule's ATT&CK techniques as recorded (sub-techniques included), those the core's ATT&CK version (ATT&CK v20, `opsdir.domains.observability.attack`) holds: a technique it retired or never held is left out (a note; the planner asks for its replacement). ES enriches the tactics from the techniques, so tactics recorded without a technique aren't annotated (a note).
- The notable (ES 8: a finding): `action.notable = 1`, `action.notable.param.rule_title = <alert rule>`, `action.notable.param.rule_description = opsdir: realizes alert rule <rule>`.
- For a rows detection with entity mappings, the risk action: `action.risk = 1` and `action.risk.param._risk`, a JSON list with a risk object per account name (`{"risk_object_field": <column>, "risk_object_type": "user", "risk_score": <n>}`) and host name (`"system"`), and a threat object per IP address (`{"threat_object_field": <column>, "threat_object_type": "ip_address"}`). The risk score comes from the rule's `ciamSeverity` on Elastic's scale (`sev0` 99, `sev1` 73, `sev2` 47, `sev3`/`sev4` 21, 47 when none), so both SIEMs score a rule alike.

On the plain platform, a saved search has no place for ATT&CK or entities: a detection recording them is a note.

## What it leaves to a person (render notes)

| Note | Severity |
|---|---|
| Install the `opsdir_ciam` app where indexes and searches run (Enterprise: deployment server or cluster manager; Cloud: its index management and app installation take these values) | action |
| Where the forwarders send (`outputs.conf`, or Splunk Cloud's forwarder credentials package): the Splunk team's | action |
| Who a detection notifies (its alert actions): set in Splunk | action |
| An index kept indefinitely (searchable or in all): Splunk freezes by age, so the setting isn't rendered and Splunk's default applies | action |
| A detection whose condition a saved search can't count (a threshold that isn't a rate or a count; a comparison other than `gt`/`ge`; a period cron can't run evenly) | blocker |
| A detection that records no search | note |
| Splunk ES: each finding's severity and security domain (`action.notable.param.severity`, `.security_domain`) are set in ES (the values ES stores aren't established); compare one detection saved in ES 8 with the rendered settings before installing (ES 8's own serialization of findings and intermediate findings isn't established) | action |
| Splunk ES: entity mappings with no documented risk or threat object type (an account's other identifiers, a host's DNS domain, a URL, an application); ATT&CK tactics recorded without techniques; ATT&CK techniques not in ATT&CK v20 | note |
| Plain platform: a detection's ATT&CK and entity mappings, which a saved search can't hold | note |
| A log file the route takes only some lines of: shipped whole (the forwarder doesn't filter by field) | note |
| Records spanning lines: joined where Splunk parses the data (`props.conf`), the Splunk team's | note |
| Container output to a Splunk index: not shipped by this add-on | blocker |
| A file two routes send to different indexes: monitored once, for the first route | blocker |

## What it reads

| Importer | Reads | Into |
|---|---|---|
| `splunk/conf` | `<cloud>/<env>/indexes.conf`, `savedsearches.conf` (its render read back: reading it back changes nothing; or an app's own files) | the environment's Splunk indexes (`logs`) and detections (`alarm`) |
| `splunk/rest` | `<cloud>/<env>/indexes.json` (`GET /services/data/indexes?output_mode=json&count=0`) and `saved-searches.json` (`GET /servicesNS/-/-/saved/searches?output_mode=json&count=0`) | the same |

An index reads as days searchable from `frozenTimePeriodInSecs` (whole days; a remainder is named) and days in all from `archiver.coldStorageRetentionPeriod` when `archiver.enableDataArchive` is on; a setting the source doesn't give is left as the record has it, never read as zero. Splunk's own indexes (a leading `_`) are left out; others the record doesn't have are counted, unless the environment's `roles.json` names their role. A saved search realizes the rule its description names (role `alarm-<rule>`), searches the index its search names first (`index=<name>`), and holds its search without the condition the render wrapped around it. A search as written whose alert actions apply to each result (`alert.digest_mode` off) or whose risk action names objects reads as a rows detection, its risk and threat objects as the entity mappings they were rendered from; the ES annotations are the alert rule's intent and aren't read. Notices about the environment's other log destinations and alarms (a cloud's) are left out.

`opsdir collect` runs the two GETs (collector `rest`) against the environment's collection source for `splunk/rest` (`ciamCollectionSource`: the management endpoint, `https://<host>:8089`), with the credential its `ciamCredentialRole` references sent as `Authorization: Bearer` (`ciamCredentialScheme: bearer`, a Splunk authentication token) or HTTP Basic, and its `ciamCaRole` as the trust anchor. The reader needs no write capability: a role that lists indexes (`indexes_list_all` where listing is restricted) and can read the saved searches' apps.

## Known limits

- Retention days are a ceiling, not a guarantee: a bucket freezes only when all its events are older, and a size limit (`maxTotalDataSizeMB`, set on every index by default) can freeze it sooner. The `splunk/rest` importer names the size limit of each index the record holds; the record doesn't model it.
- Splunk Cloud Platform: `archiver.*` (Dynamic Data Active Archive) is read where the management API exposes it, which isn't verified on every stack; a self-storage archive (DDSS) keeps data in the customer's bucket, whose retention the record holds on that bucket, not here. The Admin Config Service is not used (listing indexes there needs `indexes_edit`).
- Detections are rendered from the search each environment records; nothing translates one SIEM's search into another's, and the products don't declare detections yet (a follow-up). Splunk ES correlation searches are rendered with the settings ES documents (ES 7 and 8 documentation, Splunk's security content); the serialization ES 8.7 writes when a detection is saved (findings, intermediate findings, risk modifiers) isn't documented, and the rendered settings haven't run on a live ES (the action note). The Terraform provider `splunk/splunk` 1.5.4 has no ES arguments, so the app's `.conf` files remain the form rendered.
- **Containers on Kubernetes** (milestone 109, task 575, `kubernetes.py`): per cluster running a role whose containers a route ships to a Splunk index, `kubernetes/splunk-otel-collector/<cluster>-values.yaml` for the Splunk OpenTelemetry Collector chart 0.162.1:
  - the cluster's name and distribution (EKS, AKS or GKE, from the cloud's provider);
  - the index's HEC (`ciamIntakeUrl` + `/services/collector/event`) and the index;
  - logs only;
  - container logs filtered to the routed roles' namespaces (a `filter` operator on `resource["k8s.namespace.name"]`, which the chart's container parser sets from each log file's path);
  - `secret.create: false` with Secret `splunk-otel-collector-hec`, so the token is never in the values.

  The Secret (key `splunk_platform_hec_token`) is filled from the reference the index's `ciamCredentialRole` names (task 593). When an installed adapter delivers that reference's scheme to Kubernetes, and the record gives its store all it needs, `kubernetes/splunk-otel-collector/<cluster>-externalsecrets.yaml` is rendered for the External Secrets Operator:
  - namespace `splunk-otel-collector`, where the chart is installed;
  - service account `splunk-otel-collector-hec-reader`, which the store is read as;
  - a `SecretStore` with the scheme owner's provider (AWS Secrets Manager, Azure Key Vault, Google Secret Manager, Vault);
  - an `ExternalSecret` writing the token to the chart's Secret.

  An `aws-sm://` secret holds `{"hec_token": ...}`, the form Firehose reads, so one secret serves both; the `ExternalSecret` takes that property. Other schemes hold the token as the secret's value. No value enters the render.

  The action asks the team to do three things: give the reader account an identity that can read the reference (the record names none for the collector), apply the file, and install the chart. Without a delivering adapter, or with the store's values unbound (a Vault server with no `ciamSecretStore`), the action asks for the Secret to be filled by hand instead. A cluster whose routes ship to more than one index, or an index without an intake URL or credential, is a blocker. Every container in those namespaces is shipped, sidecars included (a note). Checked with `helm template` against the chart's values schema, and with kubeconform (External Secrets CRD schemas).
- Forwarding from the clouds' log services is the provider adapters' (milestone 109): a log destination's `ciamForwardsToRole` naming a Splunk index makes the AWS adapter render CloudWatch -> Firehose -> HEC. The token comes from the secret `ciamCredentialRole` references (`{"hec_token": ...}`) and is never in the render or the state. For Splunk Cloud Platform on AWS, Firehose sends to the stack's Firehose endpoint (`https://http-inputs-firehose-<stack>.splunkcloud.com:443`), derived from the HEC host in `ciamIntakeUrl` (`http-inputs-<stack>.splunkcloud.com`). Splunk documents no Firehose endpoint for its other stacks (Google Cloud, Azure, FedRAMP on AWS GovCloud, trials), so forwarding to those is a blocker. Splunk Enterprise is sent to at the intake URL without its path, and an action lists the load balancer Firehose needs in front of the HEC. Pub/Sub (Google Cloud) isn't rendered.
- Normalization (CIM) is the Splunk team's (add-ons, `props.conf`); the record holds no field mapping.
- Splunk's availability in a government cloud (FedRAMP, IL5) is the operator's authorization package to establish; this add-on says nothing about it.

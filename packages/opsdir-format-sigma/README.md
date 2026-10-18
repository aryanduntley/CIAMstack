# opsdir-format-sigma

Sigma for opsdir: the alert rules that adopted a product's declared detection (`ciamDeclaredDetection`, see the core README's *Detections products declare*) written as [Sigma](https://github.com/SigmaHQ/sigma-specification) rules, specification **2.1.0** (`SPEC`). Sigma is an export: the declaration and the record are the source, and opsdir's own SIEM adapters render natively from the same rules.

**Applies to** no environment by itself. It registers:

| What | Name | Entry point |
|---|---|---|
| Adapter | `sigma`, kind `platform`, declaration-only: it renders only where a stack declares it (stack role `detections`) | `opsdir.adapters` |

Its files are in the core's `yaml` format. It defines no schema of its own and depends on nothing beyond opsdir (no pySigma).

## What it writes

`sigma/<alert rule>.yml` per alert rule adopting a detection that an adapter rendering the environment declares (`Services.detections`), headed by the do-not-edit comment:

| Document | From the record and the declaration |
|---|---|
| Base rule (`name` `<alert rule>-events`) | `title`, `description` (naming the alert rule and the declaration), `references` (its evidence), `author` `opsdir`; `logsource`: `product` and `service` the declaration's product and log names (lower case, spaces as underscores), `definition` the product version range and its prerequisites; `detection.selection`: the rule's canonical selector (`ciamDetectionSelector`) in the product's field names and values, from the declaration's mapping for the version the environment runs (its servers' and workloads' `ciamProductVersion`; the newest release when none is recorded); `condition: selection`; `fields`: the grouping and distinct fields; `level`, `status`, `tags` |
| Correlation rule (`name` `<alert rule>`), when the rule counts | `correlation`: `type` `event_count`, or `value_count` when it counts a distinct field (`condition.field`); `rules` the base rule's name; `group-by` its `ciamGroupBy` fields; `timespan` its `ciamEvaluationPeriod`; `condition` `gte` its threshold (`ciamComparison gt N` is `gte N+1`). `generate` is left out (false): the base rule doesn't alert on its own |

What Sigma needs that the record doesn't say is fixed, the same every render:

| Field | Value |
|---|---|
| `id` | UUID version 5 of the rule's name (`urn:opsdir:sigma:<name>`): the specification asks for random version 4 ids; these stay put across renders |
| `status` | the declaration's validation: `documented` → `experimental`, `lab-verified` → `test`, `live-verified` → `stable` |
| `level` | the rule's `ciamSeverity`: `sev1` → `critical`, `sev2` → `high`, `sev3` → `medium`, `sev4` → `low` |
| `tags` | `attack.<tactic short name>` (`attack.credential-access`), `attack.<technique ID, lower case>` (`attack.t1110.003`), from the rule's ATT&CK |
| `logsource` names | custom: SigmaHQ's taxonomy names none of these products, so a converter needs a pipeline mapping them to the index or table holding the logs |

## What it leaves out (render notes)

| Note | When |
|---|---|
| action: not exported, fixed windows | the rule counts in fixed (clock-aligned) windows (`ciamWindowKind fixed`): a Sigma correlation's timespan isn't bound to clock boundaries, so it can't say that. Render it natively, or make the window sliding if that is meant |
| action: not exported, no mapping | the declaration maps no product version the environment records for its role |
| action: not exported, not a count | the rule's condition isn't a count reached (`ciamComparison` other than `ge`/`gt`, a threshold with a unit or not whole) or it counts without a window |
| action: not exported, field not mapped | a canonical field the rule selects, groups or counts on that the product's mapping doesn't name |
| note: status experimental | the declaration is documented only: replay the product's events against it once converted, before relying on it |
| note: Sigma rules | wherever one is exported: whoever converts them (the SIEM team) gives the converter a pipeline for the custom product and service names, and the SIEM must parse the logs into the product's fields (conversion doesn't parse) |

A rule adopting a detection no adapter rendering the environment declares (its product isn't there) is neither written nor noted.

The shape is checked against the attributes the specification documents (tests: `tests/test_sigma.py`); converting them with a pinned pySigma and its backends is a check left to whoever converts.

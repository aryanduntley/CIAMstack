# Changes, deployment, failure and concurrency

*What CIAMstack does with a change from the moment it is proposed to the moment the live system is confirmed to match, what it deliberately leaves to the company's own deployment tooling, what happens when a multi-system change fails halfway, and how parallel work by several teams is kept from colliding.*

---

## 1. CIAMstack does not deploy

CIAMstack generates configuration and reads systems back. It never applies anything to a live system:

- `opsdir render` writes files: Terraform, ARM/Bicep, CloudFormation, Kubernetes values, product configuration, Ansible, setup scripts, request drafts.
- `opsdir collect` and `opsdir import` read live systems and exports, read-only.
- No CIAMstack command runs `terraform apply`, calls a product's admin API to change it, or pushes to a cluster. Applying PingFederate's rendered Admin API requests, for example, is the operator's pipeline's job.

Deploying is done by the company's own pipelines or operators, with their own credentials, under their own change process. That keeps the security profiles apart: CIAMstack has the authority to describe and generate production configuration, but not to change production.

```
the record (approved change applied)
   │
   ▼  opsdir render: files + MANIFEST (each file's SHA-256, scope, who requested it)
review: the rendered diff, in the company's repository or pipeline
   │
   ▼  CI/CD or an operator, with their own credentials
Terraform / Ansible / the product's API / native tooling
   │
   ▼
production
   │
   ▼  opsdir collect (read-only) or opsdir import --dry-run
the record compared with the live system: drift, conflicts, verification
```

## 2. The states of a change

The record keeps what is intended apart from what is observed. These states are not the same, and CIAMstack doesn't treat them as the same:

| State | Where it lives | What it means |
|---|---|---|
| **Proposed** | A change record with status `proposed`, holding the exact records it will apply | Someone wants it. Nothing in the record has changed yet. |
| **Approved** | The change's status `approved`, with its approvers recorded | The required people agreed. Still nothing changed. |
| **Desired** (applied to the record) | The record's entries; the change's status `applied`; history | The record now says this is how the platform should be. **`applied` means applied to the record, not deployed.** |
| **Rendered** | The render's files and MANIFEST, wherever they were written | The working files generated from the desired state. The record doesn't track render runs; the manifest names who requested each. |
| **Deployed** | Outside CIAMstack: the pipeline's run, the ITSM work ticket | Someone applied the files. CIAMstack reads ITSM tickets as evidence, never as approval. |
| **Observed** | Import runs and collection attempts under `ou=imports`; observed attributes; drift | What the live system was read back as, and when. |
| **Verified** | No conflict or drift for the entry since a newer import; `ciamVerifyPending` cleared | The live system was read back and matches the record. |

Two mechanisms connect desired and observed:

- **Drift and conflicts.** An import or collection compares the live system with the record. Each disagreement is a conflict a person decides: take the live value, or keep the record's. `opsdir report drift` shows what differs from the intended configuration.
- **Awaiting verification.** A fix that changes the record ahead of the live system marks the value as awaiting verification (`ciamVerifyPending`, naming the adapter whose import confirms it). The check that offered the fix keeps reporting it until that adapter's import covers the entry: a match clears the mark, a difference becomes a conflict.

## 3. When a multi-system change fails halfway

Suppose a move needs DNS, cloud networking, the directory, federation, certificates, partner metadata and firewall rules, and the fourth step fails.

**What CIAMstack considers committed.** Only the record. A change (or a workspace cutover) is applied to the record in one database transaction: all of its records or none. The live systems are committed by whatever deployed them, step by step.

**What it does automatically.** Nothing to the live systems. It doesn't roll anything back and it doesn't retry. It doesn't run the deployment, so it has nothing to roll back.

**How the state is recovered:**

1. **Read the live systems back.** `opsdir collect` (or an import dry run) for each system involved. The systems already updated agree with the record; the ones not yet updated, or half updated, show up as conflicts and drift, entry by entry.
2. **Decide, per difference, which way to go:**
   - **Forward:** keep the record's value and deploy again once the cause is fixed. The record still holds the desired state, so the same render applies.
   - **Back:** record the previous values under a new approved change (history holds every entry's before values), render, and deploy that. Taking the live value at an import does the same for what was never changed.
3. **Re-plan.** `opsdir plan` (and `opsdir migrate` for a move) lists what still blocks, with owners.

**Rollback of the deployment itself** is the pipeline's: keep each render in the company's repository, so the previous one can be redeployed. CIAMstack renders the record as it is now, not as it was at an earlier point.

**For a migration,** the source environment stays in the record, and operated from it, until it is retired. Contracts (service names, entity IDs, issuers) stay the same, and a fix lowers the DNS TTL of a changing name ahead of the move. Falling back during a cutover is therefore switching traffic back to an environment the record still describes, not rebuilding it.

**Ordering.** Where one rendered Terraform root reads what another writes, the reading root takes it as an input and says which root it comes from, applied first. The plan's actions carry do-by dates from their lead times. The order of the cutover itself is the company's runbook, rehearsed in stage.

## 4. Concurrency: several teams at once

**In the live record.** Every write is a database transaction under its approved change, checked against the rules at commit. Changes to different entries don't interfere. A proposed change holds the exact records it will apply, and its approvals start over if those records change before it is applied. The store also notes what each entry the records touch looked like when they were proposed (`ciamChangeBase`). If another change writes one of those entries before the proposal is applied, applying it is refused and names the entry and the other change: the approvers saw the entry as it was, so the records are proposed again, and approved again, against what it is now.

**Long-running work happens in a workspace.** A migration team copies the live record into a workspace, which remembers the live snapshot it was copied from. Meanwhile, the platform keeps being operated from the live record, and the directory team, for example, keeps changing production there. At cutover:

| Entry changed in | Result |
|---|---|
| The workspace only | Applied to the live record |
| The live record only | Kept as the live record has it |
| Both | **The cutover is refused** and names each entry. A person resolves it in the workspace (or recreates the workspace) before cutting over. |

The workspace's changes are applied in one transaction, under the approved change, through every rule of the store. Before cutover:

- `opsdir workspace status` says what the workspace changed and whether the live record moved on since the copy;
- `opsdir workspace diff` shows the workspace's changes as LDIF change records;
- re-run `opsdir --workspace plan` and render, so the findings and renders reviewed are the workspace's as it is.

After a cutover, the workspace is rebuilt from the new live record.

So three weeks of migration work and three weeks of production changes meet in one explicit step: baseline (the snapshot), current (the live record), proposed (the workspace). Conflicts are found, never overwritten.

**Imports racing changes.** An import that would change something the record holds is a conflict, decided by a person, not a silent overwrite. Fixes that must not act on a stale picture of the live system (pinning firewall priorities, for example) refuse until an import taken after the entries' last change covers them.

**Upgrades** run one at a time, in one transaction.

# opsdir-adapter-servicenow

opsdir ITSM add-on (adapter kind `itsm`) for ServiceNow change management. It reads the change tickets that the record's change records are tracked by and records them as **evidence**, read-only (milestone 6.2f, f1). The governance domain then compares each ticket with the record: `opsdir report tickets` and the planner's `Change tickets` check (`opsdir/README.md`, *ITSM tickets*).

A ticket **never approves anything in opsdir**. The importer writes nothing under `ou=changes`. A ticket's approval never becomes a change's `ciamChangeStatus`, and its approvers never become `ciamApprovedBy`. The store's rule still holds: every write needs an approved change record. Mirroring approvals and publishing CMDB configuration items are later work (6.2f f2).

It also **drafts work tickets** that hand a team its findings, as files a person posts (task 612, decisions 3409 and 3415), and reads the filed ones back as evidence: *Work tickets* below.

**Applies to** no environment and renders nothing (`applies=None`, like `opsdir-adapter-fedramp`). Collecting opts in through a collection source (below).

**Depends on** `opsdir` (the governance domain's ticket model: `domains/governance/tickets.py`).

## The link, in the record

A change record names its ticket in `ciamTicketRef`, as `servicenow:<number>` (for example `servicenow:CHG0030101`). The link is the operator's, set under an approved change. Only linked tickets are read.

State codes differ between change models, so the operator says which model uses which codes, in estate settings (`opsdir setting`):

| Setting | Default | What it says |
|---|---|---|
| `servicenow-standard-state-models` | none | The models (sys_ids or names, comma-separated, as `GET /api/sn_chg_rest/change/model` lists them; `(none)` for changes without a model) on ServiceNow's documented **standard state model**: -5 new, -4 assess, -3 authorize, -2 scheduled, -1 implement, 0 review, 3 closed, 4 cancelled |
| `servicenow-legacy-state-models` | none | The models whose changes still hold the **legacy (pre-Geneva) codes**: -5 Pending, 1 Open, 2 Work in Progress, 3 Closed Complete, 4 Closed Incomplete, 7 Closed Skipped |
| `servicenow-legacy-states` | `-5=new, 1=assess, 2=implement, 3=closed, 4=closed, 7=cancelled` | The legacy codes in neutral terms (`<code>=<state>, ...`). Closed Skipped is cancelled: the work wasn't done. A code not mapped keeps its native state |
| `servicenow-approval-values` | `not requested=not-requested, requested=requested, approved=approved, rejected=rejected` | `change_request.approval`'s raw values in neutral terms (`<raw value>=<approval>, ...`) |

A ticket whose model is named in neither model setting keeps only its native state, and its neutral state is unknown, so it is never taken as closed or cancelled. A model named in **both** is refused the same way, with a notice. A setting's malformed part, or a state or approval outside the neutral ones, is named in a notice. Confirm your instance's models and values before you name them.

## Reading tickets (importer `servicenow/change-requests`)

`opsdir import --change CHG-… --at <when the export was taken> servicenow/change-requests <folder>`. The folder holds the answers of two tables, `change_request` and `sysapproval_approver`, in either form:

| Form | Files |
|---|---|
| As `opsdir collect` saves them | `<instance host>/change_request/<chunk>-<offset>.json`, `<instance host>/sysapproval_approver/<chunk>-<offset>.json` (Table API answers, `{"result": [...]}`) |
| An export you made | `change_request*.json` and `sysapproval_approver*.json` (a saved Table API answer, or a list export in JSON, `{"records": [...]}`), optionally under a folder named for the instance's host |

The instance's host folder gives each ticket its address, `ciamDocUrl` = `https://<host>/api/now/table/change_request/<sys_id>`. Without that folder no address is recorded, and a notice says so. An export holding two instances is refused, and so is an export from another instance than the one the record's tickets were read from (one instance per record: Known limits).

**Raw values only.** Raw date/times are UTC, while display values are in the reading user's time zone. A field may be raw (`"-2"`) or raw and display together (`{"value": "-2", "display_value": "Scheduled"}`, from `sysparm_display_value=all`). A record whose state or window times come as display text only is left out with a notice: export with `sysparm_display_value=false` or `all`.

| ServiceNow (`change_request`) | Record (`ciamTicket`, `cn=<number>,ou=servicenow,ou=tickets`) |
|---|---|
| `number`, `sys_id`, `short_description` | `cn`, `ciamProviderRef`, `ciamTitle` |
| `state` (with `chg_model`) | `ciamTicketState` from the standard codes or the legacy map, by the model setting naming the model; `ciamTicketNativeState` always: the raw code and its label |
| `type` | `ciamTicketChangeType` (`normal`, `standard`, `emergency`; any other value only as the fact below) |
| `approval` | `ciamTicketApproval` through `servicenow-approval-values`: **the** approval evidence. A raw value the setting doesn't map leaves the approval unknown, is kept as the fact `approval <raw value>` and is named in a notice |
| `start_date`, `end_date` | `ciamTicketPlannedStart`, `ciamTicketPlannedEnd` |
| `work_start`, `work_end` | `ciamTicketWorkStart`, `ciamTicketWorkEnd` |
| `type`, `chg_model`, `close_code`, `assignment_group`, `cmdb_ci`, `requested_by`, `correlation_id`, `correlation_display`, `sys_updated_on` | `ciamTicketFact` `<field> <raw value>` (reference fields keep their sys_ids) |
| `sysapproval_approver` rows of the change (`sysapproval` = its sys_id) | `ciamTicketApprover` `<state> <approver sys_id> updated <sys_updated_on>`: detail only. They are never used to judge approval (one approved approver doesn't approve a change, and no rows doesn't mean none was needed), and `sys_updated_on` isn't when anything was approved |

What the import does with what it finds:
- Each ticket read is its own import group, so an import replaces only the tickets it read.
- A linked ticket missing from the export is never removed. The record keeps what it last read, and the planner reports the ticket as not imported.
- Tickets the record doesn't link are named in a notice and left out.
- A requested field the answers never carry is named in a notice. The API silently ignores fields it doesn't know, and fields the reader can't see are also missing.
- An error answer (`{"error": ...}`) is named in a notice.

## Work tickets: drafts and read-back

`opsdir tickets <from> <to> -o DIR [--mine]` writes, for each team the plan's findings name as owner, `tickets/servicenow/<team>.json`: the Table API create body of a record in **your site-approved table derived from `task`**, and `tickets/README.md` saying how to post it. opsdir posts nothing and holds no ServiceNow credential. The team, or an admin, posts the draft with their own credentials and links the number it answers on the change that does the work (`ciamTicketRef servicenow:<number>`, next to the change ticket). The next import then reads it back as a **work ticket**.

There is no portable default table. Base `task` and orphan `sc_task`, `change_task` or `problem_task` records aren't a supported fulfiller workflow; `incident` or `problem` fit only when the findings are one. Pick or build the table on the instance, confirm that the posting users' roles can create records in it (table and field ACLs: `itil` alone isn't a guarantee), and find its mandatory fields.

| Setting | Default | What it says |
|---|---|---|
| `servicenow-ticket-table` | none | The table work tickets are filed in (for example `u_ciam_remediation`; not `change_request`). Drafts are written for it, and the collector and importer read linked numbers from it |
| `servicenow-ticket-groups` | none | Each owning team's assignment group, `<team>=<group sys_id>, ...` (the team as its `ciamParty` under `ou=owners` is named, any case). A sys_id, never a name: the draft posts raw values |
| `servicenow-ticket-fields` | none | Fields every draft also sets, raw values, `<field>=<value>, ...`: for example `impact=3, urgency=3`, or what your table makes mandatory (company, category, CI). Never a drafted field: one named here is left out, with a note |
| `servicenow-ticket-states` | none | The table's state codes in neutral terms, `<code>=<state>, ...`. Base `task`'s are -5 Pending, 1 Open, 2 Work in Progress, 3 Closed Complete, 4 Closed Incomplete, 7 Closed Skipped (for example `-5=new, 1=new, 2=implement, 3=closed, 4=closed, 7=cancelled`); your table may have its own. A code not mapped keeps its native state only, with a notice |

**The draft** is for `POST /api/now/table/<table>?sysparm_input_display_value=false`:

| Field | Value |
|---|---|
| `short_description` | The ticket's title: the team, how many findings, the plan's source and target |
| `description` | Plain text: each finding with its area and do-by date, the earliest first. Not `work_notes` or `comments`, which are journal fields |
| `assignment_group` | The team's group sys_id, from `servicenow-ticket-groups` |
| `due_date` | The earliest do-by date, to the end of that **UTC** day (`YYYY-MM-DD 23:59:59`). Left out when no finding has one. Every finding's own date stays in the description |
| your defaults | `servicenow-ticket-fields` |

A team the draft can't be written for is named in `tickets/README.md` with the setting to give: the table isn't set (or isn't a usable table name), the team has no group, or its group isn't a sys_id. Setting problems (a malformed part, a team mapped twice) are listed too. The README's curl names placeholders only (`<access token>`, `<instance host>`, filled in from the record's tickets when they were read from one instance), run from the `tickets` folder.

**Read-back.** When `servicenow-ticket-table` is set, the collector reads the record's linked numbers from that table as well as from `change_request`: only the instance knows which a number is. The importer reads `<host>/<table>/<chunk>-<offset>.json` (or any `<table>*.json`). A linked number found there is a work ticket:

| ServiceNow (the work-ticket table) | Record (`ciamTicket`) |
|---|---|
| `number`, `sys_id`, `short_description` | `cn`, `ciamProviderRef`, `ciamTitle`; `ciamDocUrl` = `https://<host>/api/now/table/<table>/<sys_id>` |
| (the table) | `ciamTicketKind` `work`: no approval, no approval records |
| `state` | `ciamTicketState` through `servicenow-ticket-states`; `ciamTicketNativeState` always |
| `due_date` | `ciamTicketDue` |
| `work_start`, `work_end` | `ciamTicketWorkStart`, `ciamTicketWorkEnd` |
| `assignment_group`, `assigned_to`, `priority`, `impact`, `urgency`, `sys_class_name`, `closed_at`, `sys_updated_on` | `ciamTicketFact` `<field> <raw value>` |

The same rules as change tickets hold: raw values only (a state or time given only as display text is left out), only linked numbers, nothing removed, fields the answers never carry named. A number found in both tables is read as the change ticket, with a notice. While the table isn't set, a linked number not found in `change_request` is reported as not in the export, with a hint that the table isn't set. The planner compares a work ticket's state, windows and read time with the change; it has no approval to compare.

## Collecting (`opsdir collect`, read-only)

An environment's `ciamCollectionSource` with `ciamImporter: servicenow/change-requests` says where to read: `ciamSourceRef` is the instance's base URL (`https://<instance host>`). Collecting reads the tickets every environment's change records link, so declare one source.

The credential is the one its `ciamCredentialRole` binding references, resolved when collecting and never stored. `ciamCaRole` names the trust anchor, when the instance needs one. `ciamCredentialScheme` is one of:
- `basic`: a user's password, with `ciamLoginName`.
- `bearer`: an OAuth 2.0 access token minted outside opsdir, for example with inbound client credentials, which the instance must have enabled.
- `client-certificate`: mutual TLS. The binding references a PEM holding the client certificate, its chain and its private key. opsdir resolves it when collecting and loads it into the TLS connection through an anonymous in-memory file (Linux memfd): it is never written to disk or recorded, and no `Authorization` header is sent. Where the system has no memfd, the call fails and says why. The instance maps the certificate to the user the request runs as (ServiceNow's certificate-based authentication). Its prerequisites, from ServiceNow's documentation:
  - the instance on ADCv2 with ADC-to-application mTLS (`https://<instance>/adcv2/supports_tls` answers `true`; otherwise ServiceNow Support enables it);
  - the plugin `com.glide.auth.mutual` active and the property `glide.authenticate.mutual.enabled` true;
  - the client certificate's root and intermediate CA certificates registered on the instance, and the PEM certificate mapped to the reading user.

  It isn't supported on on-premises instances or instances with Edge Encryption. It is optional on the instance: other authentication keeps working for clients that present no certificate.

Calls (GETs only; nothing is ever written to the instance, not even a correlation field):

| Call | Saved as |
|---|---|
| `GET /api/now/table/change_request?sysparm_query=numberIN<up to 50 numbers>^ORDERBYsys_id&sysparm_fields=<the fields above>&sysparm_display_value=all&sysparm_exclude_reference_link=true&sysparm_limit=100&sysparm_offset=<n>` | `<host>/change_request/<chunk>-<offset>.json` |
| then `GET /api/now/table/sysapproval_approver?sysparm_query=sysapprovalIN<sys_ids found>^ORDERBYsys_id&sysparm_fields=sys_id,sysapproval,approver,state,sys_updated_on&…` | `<host>/sysapproval_approver/<chunk>-<offset>.json` |
| with `servicenow-ticket-table` set, also `GET /api/now/table/<table>?sysparm_query=numberIN<the same numbers>^ORDERBYsys_id&sysparm_fields=<the work-ticket fields above>&…` | `<host>/<table>/<chunk>-<offset>.json` |

Each chunk is read page after page until a page comes back **empty**. A short page doesn't end it, because the Table API applies its limit before the reader's access rules. A page holds more records than a chunk has tickets, so the second page of a chunk is normally the empty one. Only the requested fields of each record are kept.

**Least privilege.** Give the reader a role of your own that reads only `change_request` and `sysapproval_approver` (and the work-ticket table, when set), through table and field ACLs on the fields above, and review the roles it inherits. ServiceNow ships no such two-table role:
- `itil` is broader than this.
- `snc_read_only` restricts access a user already has; it grants none.
- `sysparm_fields` is not an access boundary.

The Change Management API's GET roles (`change_manager`, `itil`, `sn_change_read`, `admin`) don't establish access to approval records.

## Known limits

- **Change models.** Activating ServiceNow's state model doesn't migrate stored state values: records created before it keep their legacy codes but show the new labels (a -5 Pending reads New; 3 Closed Complete reads Closed; 4 Closed Incomplete reads Canceled). A model you name as standard may still hold such un-migrated records: their 1, 2 and 7 stay native (unknown), and their 4 reads cancelled. Name a model as legacy only when its changes hold the legacy codes. A model you haven't named keeps only its native state.
- **Approval values.** ServiceNow documents only `not requested` (the default) for `change_request.approval`; the full shipped list wasn't found. Workflow actions also report `cancelled`, `not_required` and `skipped`, and instances have been seen with others (`duplicate`, more information required on approver records). Map the values your instance uses in `servicenow-approval-values`; any other is kept as a fact, and the neutral approval stays unknown. Confirm them on your instance, as you do the complete set of `sysapproval_approver` states.
- **Display-only detection** relies on the raw state being an integer code and the raw times being `YYYY-MM-DD HH:MM:SS`. An export whose display values happen to look raw can't be told apart.
- **Comparisons.** The record's single `ciamPlannedAt` is compared by UTC day with the ticket's planned window: no tolerance beyond the day, and an end the ticket doesn't give is open. ITSM's own work times are compared with its planned window exactly, with no tolerance, and so are the record's own writes under the change (its history: applied-outside-window, `opsdir/README.md`). A ticket's work, approval and approver times later than when its export was read are named (after-read).
- **One instance.** One instance per record, enforced: the import refuses an export from another instance than the one the record's tickets were read from. The link names a number, not an instance, and numbers are only an instance's own: separate instances number independently, and ServiceNow doesn't even enforce unique numbers within an instance by default. A record spanning several instances (a commercial and a GCC one) would need the instance in the link; that isn't built.
- **Authentication.** Inbound OAuth client credentials depends on the instance's release and configuration (`glide.oauth.inbound.client.credential.grant_type.enabled`, an OAuth application user). A client certificate needs the prerequisites above; whether the instance can require a certificate and a password or token together wasn't confirmed, so opsdir sends one or the other.
- **Government instances.** ServiceNow's Government Community Cloud (GCC; FedRAMP High and DoD IL4, as ServiceNow describes it, with instances under `servicenowservices.com`) and National Security Cloud (NSC; DoD IL5, on Microsoft Azure Government) are separate offerings. Their API and authentication parity with the commercial cloud is unverified, and releases are qualified for them separately (ServiceNow lists a new family as being evaluated for GCC). Some features are documented as unavailable there. The collector reads any host, but confirm the contracted host name, installed release and plugins, network access and approved authentication with the customer.
- **List exports.** XML list exports need `admin`, and they aren't read; use JSON. The legacy JSONv2 processor (`change_request.do?JSONv2`) isn't read either; prefer the Table API.
- **Address.** The ticket's address is its Table API record URL, not the form URL a person opens.
- **Work-ticket drafts.** Unconfirmed per site, and not checkable by opsdir: whether the table accepts a record without a parent, which fields it makes mandatory, its choice values for `impact` and `urgency` (1 to 3 is the common ITSM set; `priority` is normally derived from them, so don't set it), its create ACLs, and its state codes. The do-by date is taken as the end of that UTC day; if your teams mean their local day, set `due_date` by hand before posting. ServiceNow limits `short_description` to the field's length on your table; the title is short, but a long team name could exceed it. No government-specific (GCC, NSC) create-body difference is documented, and parity isn't confirmed.

Sources (ServiceNow documentation, read by the 6.2f research on 2026-10-15): the Change Management API (Australia), the change state model mapping (updated 2026-03-12), the Table API (Zurich), query operators, client credentials, the read-only role, and list export (updated 2026-03-12). Task 558's research (2026-10-17): "Update change request states" (Brazil: the legacy codes, values not migrated), change model properties (Zurich), certificate-based authentication (Brazil) and its hardening guidance (Australia), enforcing unique numbering (Brazil), the GCC Teams bot page (Zurich, the GCC domain) and ServiceNow's compliance page (GCC, NSC). The latest generally available family is Australia; Brazil was in early availability (2026-09-24).

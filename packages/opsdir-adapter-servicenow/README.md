# opsdir-adapter-servicenow

opsdir ITSM add-on (adapter kind `itsm`) for ServiceNow change management. It reads the change tickets that the record's change records are tracked by and records them as **evidence**, read-only (milestone 6.2f, f1). The governance domain then compares each ticket with the record: `opsdir report tickets` and the planner's `Change tickets` check (`opsdir/README.md`, *ITSM tickets*).

A ticket **never approves anything in opsdir**. The importer writes nothing under `ou=changes`. A ticket's approval never becomes a change's `ciamChangeStatus`, and its approvers never become `ciamApprovedBy`. The store's rule still holds: every write needs an approved change record. Mirroring approvals and publishing CMDB configuration items are later work (6.2f f2).

**Applies to** no environment and renders nothing (`applies=None`, like `opsdir-adapter-fedramp`). Collecting opts in through a collection source (below).

**Depends on** `opsdir` (the governance domain's ticket model: `domains/governance/tickets.py`).

## The link, in the record

A change record names its ticket in `ciamTicketRef`, as `servicenow:<number>` (for example `servicenow:CHG0030101`). The link is the operator's, set under an approved change. Only linked tickets are read.

The instance's change models that use ServiceNow's documented **standard state model** are named by the estate setting `servicenow-standard-state-models`: a comma-separated list of the models' sys_ids or names, as `GET /api/sn_chg_rest/change/model` on the instance lists them. The setting has **no default**. A ticket whose model isn't named there keeps only its native state, and its neutral state is unknown, so it is never taken as closed or cancelled. Confirm your instance's models before you name them.

## Reading tickets (importer `servicenow/change-requests`)

`opsdir import --change CHG-… --at <when the export was taken> servicenow/change-requests <folder>`. The folder holds the answers of two tables, `change_request` and `sysapproval_approver`, in either form:

| Form | Files |
|---|---|
| As `opsdir collect` saves them | `<instance host>/change_request/<chunk>-<offset>.json`, `<instance host>/sysapproval_approver/<chunk>-<offset>.json` (Table API answers, `{"result": [...]}`) |
| An export you made | `change_request*.json` and `sysapproval_approver*.json` (a saved Table API answer, or a list export in JSON, `{"records": [...]}`), optionally under a folder named for the instance's host |

The instance's host folder gives each ticket its address, `ciamDocUrl` = `https://<host>/api/now/table/change_request/<sys_id>`. Without that folder no address is recorded, and a notice says so. An export holding two instances is refused.

**Raw values only.** Raw date/times are UTC, while display values are in the reading user's time zone. A field may be raw (`"-2"`) or raw and display together (`{"value": "-2", "display_value": "Scheduled"}`, from `sysparm_display_value=all`). A record whose state or window times come as display text only is left out with a notice: export with `sysparm_display_value=false` or `all`.

| ServiceNow (`change_request`) | Record (`ciamTicket`, `cn=<number>,ou=servicenow,ou=tickets`) |
|---|---|
| `number`, `sys_id`, `short_description` | `cn`, `ciamProviderRef`, `ciamTitle` |
| `state` (with `chg_model`) | `ciamTicketState` from `STATE_MODELS["standard"]` (-5 new, -4 assess, -3 authorize, -2 scheduled, -1 implement, 0 review, 3 closed, 4 cancelled) when the model is named in the setting; `ciamTicketNativeState` always: the raw code and its label |
| `approval` | `ciamTicketApproval` (`not requested`, `requested`, `approved`, `rejected` → not-requested, requested, approved, rejected): **the** approval evidence |
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

## Collecting (`opsdir collect`, read-only)

An environment's `ciamCollectionSource` with `ciamImporter: servicenow/change-requests` says where to read: `ciamSourceRef` is the instance's base URL (`https://<instance host>`). Collecting reads the tickets every environment's change records link, so declare one source.

The credential is the one its `ciamCredentialRole` binding references, resolved when collecting and never stored. `ciamCaRole` names the trust anchor, when the instance needs one. `ciamCredentialScheme` is one of:
- `basic`: a user's password, with `ciamLoginName`.
- `bearer`: an OAuth 2.0 access token minted outside opsdir, for example with inbound client credentials, which the instance must have enabled.

Calls (GETs only; nothing is ever written to the instance, not even a correlation field):

| Call | Saved as |
|---|---|
| `GET /api/now/table/change_request?sysparm_query=numberIN<up to 50 numbers>^ORDERBYsys_id&sysparm_fields=<the fields above>&sysparm_display_value=all&sysparm_exclude_reference_link=true&sysparm_limit=100&sysparm_offset=<n>` | `<host>/change_request/<chunk>-<offset>.json` |
| then `GET /api/now/table/sysapproval_approver?sysparm_query=sysapprovalIN<sys_ids found>^ORDERBYsys_id&sysparm_fields=sys_id,sysapproval,approver,state,sys_updated_on&…` | `<host>/sysapproval_approver/<chunk>-<offset>.json` |

Each chunk is read page after page until a page comes back **empty**. A short page doesn't end it, because the Table API applies its limit before the reader's access rules. A page holds more records than a chunk has tickets, so the second page of a chunk is normally the empty one. Only the requested fields of each record are kept.

**Least privilege.** Give the reader a role of your own that reads only `change_request` and `sysapproval_approver`, through table and field ACLs on the fields above, and review the roles it inherits. ServiceNow ships no such two-table role:
- `itil` is broader than this.
- `snc_read_only` restricts access a user already has; it grants none.
- `sysparm_fields` is not an access boundary.

The Change Management API's GET roles (`change_manager`, `itil`, `sn_change_read`, `admin`) don't establish access to approval records.

## Known limits

- **Change models.** The standard state model's codes are documented; legacy models use other codes (1 Open, 2 Work in Progress, 7 Closed Skipped, with -5, 3 and 4 labelled differently), and no full legacy map is documented, so none is shipped. A model you haven't named keeps only its native state.
- **Approval values.** The raw values of `change_request.approval` that are mapped (`not requested`, `requested`, `approved`, `rejected`) come from common Table API answers and were not confirmed by the 6.2f research. Any other value is kept as a fact, and the neutral approval stays unknown. Confirm them on your instance, as you do the complete set of `sysapproval_approver` states.
- **Display-only detection** relies on the raw state being an integer code and the raw times being `YYYY-MM-DD HH:MM:SS`. An export whose display values happen to look raw can't be told apart.
- **Comparisons.** The record's single `ciamPlannedAt` is compared by UTC day with the ticket's planned window: no tolerance beyond the day, and an end the ticket doesn't give is open. ITSM's own work times are compared with its planned window exactly, with no tolerance. When the record itself applied a change (its writes in the store's history) is not compared yet; that is a follow-up.
- **One instance.** One instance per record: the link names a number, not an instance.
- **Authentication.** Mutual TLS (certificate) authentication isn't supported by the collector. Inbound OAuth client credentials depends on the instance's release and configuration (`glide.oauth.inbound.client.credential.grant_type.enabled`, an OAuth application user).
- **Government instances.** API and authentication parity on ServiceNow's government offerings (GCC, NSC) is unverified. Confirm the contracted host name, installed release and plugins, network access and approved authentication with the customer.
- **List exports.** XML list exports need `admin`, and they aren't read; use JSON. The legacy JSONv2 processor (`change_request.do?JSONv2`) isn't read either; prefer the Table API.
- **Address.** The ticket's address is its Table API record URL, not the form URL a person opens.

Sources (ServiceNow documentation, read by the 6.2f research on 2026-10-15): the Change Management API (Australia), the change state model mapping (updated 2026-03-12), the Table API (Zurich), query operators, client credentials, the read-only role, and list export (updated 2026-03-12).

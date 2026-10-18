# opsdir-adapter-bmc-helix

opsdir ITSM add-on (adapter kind `itsm`) for BMC Helix ITSM change management: Helix SaaS and on-premises BMC Helix / Remedy ITSM alike, through the AR System REST API. It is the third ITSM add-on after `opsdir-adapter-servicenow` and `opsdir-adapter-jira-sm`, with the same contract. It reads the change tickets that the record's change records are tracked by and records them as **evidence**, read-only (milestone 6.2f follow-ups, task 556). The governance domain then compares each ticket with the record: `opsdir report tickets` and the planner's `Change tickets` check (`opsdir/README.md`, *ITSM tickets*).

It also drafts the **work orders** that hand the plan's findings to their owning teams, as files a person posts, and reads the linked work orders back as work tickets (task 612, below).

A ticket **never approves anything in opsdir**. The importer writes nothing under `ou=changes`. A ticket's approval never becomes a change's `ciamChangeStatus`, and its approvers never become `ciamApprovedBy`. The store's rule still holds: every write needs an approved change record.

**Applies to** no environment and renders nothing (`applies=None`). Collecting opts in through a collection source (below). Written against BMC Helix ITSM and BMC Helix Innovation Suite 26.3.01, the current release (SaaS 2026-09-22, on-premises 2026-09-23). The forms and fields it reads (`CHG:Infrastructure Change`, `AP:Detail-Signature`) are the long-standing Remedy ones, so earlier supported versions read alike.

**Depends on** `opsdir` (the governance domain's ticket model: `domains/governance/tickets.py`). No third-party libraries.

Install for development with `opsdir/scripts/dev-install.sh`. The package registers through the entry point `opsdir.adapters: bmc-helix`.

## The link, in the record

A change record names its ticket in `ciamTicketRef`, as `bmc-helix:<Infrastructure Change ID>` (for example `bmc-helix:CRQ000000001201`). The link is the operator's, set under an approved change. Only linked tickets are read.

## The status map, in the record

BMC's Change Request Status is a product list, and the REST API returns an enum as its string value (never its number or a label). This add-on declares the estate setting **`bmc-helix-status-states`**, whose **default** is BMC's documented list:

| Change Request Status | Neutral state |
|---|---|
| Draft | `new` |
| Request For Authorization | `authorize` |
| Request For Change, Planning In Progress, Scheduled For Review | `assess` |
| Scheduled For Approval | `authorize` |
| Scheduled | `scheduled` |
| Implementation In Progress | `implement` |
| Completed | `review` |
| Closed | `closed` |
| Cancelled | `cancelled` |
| Pending, Rejected | none: the native state is kept, with a notice |

Pending is on hold, from any phase, so it says nothing about where the change is. Rejected says the change's approval (below), not a lifecycle state.

A tenant that customised the list sets `bmc-helix-status-states` under an approved change, with comma-separated `<status>=<state>` pairs. The states are `new`, `assess`, `authorize`, `scheduled`, `implement`, `review`, `closed` and `cancelled`, the same syntax as `jira-sm-status-states`. The setting then replaces the default whole. A status that neither maps keeps only its native state: its neutral state is unknown, so the ticket is never taken as closed or cancelled, and a notice names it. Malformed parts, a status mapped twice (the first is used) and states outside the list are named in notices.

## What a ticket says

| BMC Helix (`CHG:Infrastructure Change`, `AP:Detail-Signature`) | Record (`ciamTicket`, `cn=<CRQ>,ou=bmc-helix,ou=tickets`) |
|---|---|
| `Infrastructure Change ID`, `Request ID`, `Description`, the entry's REST self link | `cn`, `ciamProviderRef` (the Request ID), `ciamTitle`, `ciamDocUrl` |
| `Change Request Status` | `ciamTicketState` by the status map; `ciamTicketNativeState` always, as BMC gives it |
| the signatures of each approval request (`Approval ID`: one per approval phase and level) | `ciamTicketApprovalStep` `<decision> <Approval ID> created <its first signature's Create-Date-Sig>` |
| the status and the steps | `ciamTicketApproval` (below) |
| each signature | `ciamTicketApprover` `<status> <Approver Signature, else Approvers> step <Approval ID> updated <Modified-Date-Sig>[ phase <Phase>]`: detail only, login ids, never names (spaces within a value become `_`) |
| `Change Timing` | `ciamTicketChangeType` when it is Emergency, Normal or Standard; Expedited, Latent and No Impact are kept as the fact `change-timing`, with a notice |
| `Scheduled Start Date`, `Scheduled End Date` | `ciamTicketPlannedStart`, `ciamTicketPlannedEnd` |
| `Actual Start Date`, `Actual End Date` | `ciamTicketWorkStart`, `ciamTicketWorkEnd` |
| `Change Type` (Project, Change, Release, ...), `Status Reason`, `Risk Level`, `Impact`, `Urgency`, `Priority`, `Last Modified Date` | `ciamTicketFact` `change-type …`, `status-reason …`, `risk-level …`, `impact …`, `urgency …`, `priority …`, `last-modified …` |

**Steps.** A step's decision comes from its signatures' statuses:
- `declined` when any signature is Rejected.
- Otherwise `pending` when any is Pending, Hold or More Information.
- Otherwise `approved` when any is Approved. Under One Must Sign, the other signatures are closed.
- An approval request whose signatures are only Cancelled, Error or Closed decides nothing. It isn't a step (a notice names it), but its signatures are kept as approver rows.

A step has no completed time: a signature's modified date isn't when it was decided.

**The overall approval.** BMC's change form holds no overall approval. The rule (the user's, tasks 551 and 556) is:
1. The status is Rejected: `rejected`.
2. Otherwise, any step declined: `rejected`.
3. Otherwise, any step pending: `requested`.
4. Otherwise, at least one step, all approved, **and** the neutral state is past authorization (`scheduled`, `implement`, `review` or `closed`): `approved`. A later approval phase may still come while the change waits in an approval status.
5. Otherwise: unknown. A change with no signatures is unknown, never `not-requested`: standard changes and auto-approval have none.

Rules 2-5 are shared with Jira Service Management (`tickets.derived_approval`). When the export holds no signature pages for a change, or they stop before a page that links no next one, the steps aren't read: the approval is unknown unless the status is Rejected, and a notice names the change.

**Which signatures are a change's.** A signature belongs to a change when its `Request` is the change's Request ID or its Infrastructure Change ID, and its `Application` is `CHG:Infrastructure Change` (or not given). BMC's approval join stores the application's request id, but which identifier ITSM stores there is unverified. Signatures of another application with a matching Request are named in a notice and left out. A signature seen on two pages is counted once (by `Detail-Sig-Id`).

**Times.** AR System's date-times carry their offsets (`2026-09-24T08:00:00.000+0000`) and are read as UTC. A date without a time is refused with a notice: its time zone is unknown.

## Reading tickets (importer `bmc-helix/change-requests`)

`opsdir import --change CHG-… --at <when the export was taken> bmc-helix/change-requests <folder>`. The folder holds JSON answers of `GET /api/arsys/v1/entry/<form>`:

| Form | Files |
|---|---|
| As `opsdir collect` saves them | `<server host>/change/<CRQ>.json` (`CHG:Infrastructure Change`), `<server host>/approval/<CRQ>/<offset>.json` (`AP:Detail-Signature`, page by page) |
| Answers you saved | any `*.json` that is a list answer (`{"entries": [...]}`) or a single entry (`{"values": {...}}`): a change when its values hold an `Infrastructure Change ID`, signatures when they hold an `Approval Status`. Signature pages go under `approval/<CRQ>/` or are named `approval-<CRQ>*.json`, so the import knows which change they complete |

What the import does with what it finds:
- Each ticket read is its own import group, so an import replaces only the tickets it read.
- A linked ticket missing from the export is never removed. The record keeps what it last read, and the planner reports the ticket as not imported.
- Tickets the record doesn't link are named in a notice and left out.
- Two entries for one change number (different Request IDs), an entry with no Request ID, or a number the record can't name: named and left out.
- AR System's error answers (`[{"messageType": "ERROR", "messageNumber": …, "messageText": …}]`) are named, as is a JSON file that isn't an entry answer.
- Changes from two servers (their self links) are refused: import one server at a time.

## Collecting (`opsdir collect`, read-only)

An environment's `ciamCollectionSource` with `ciamImporter: bmc-helix/change-requests` says where to read. `ciamSourceRef` is the REST server's base URL: Helix SaaS uses `https://<customer>-restapi.onbmc.com`, and an on-premises server is commonly `https://<host>:8008` (Jetty), or a `-restapi` host on containerised deployments. The URL is taken as given: Helix and on-premises servers are read the same way, and no URL tells them apart.

The credential is the one its `ciamCredentialRole` binding references, resolved when collecting and never stored. `ciamCaRole` names the trust anchor, when the server needs one. `ciamCredentialScheme` is one of:
- `token`: the reference holds the JWT that AR System's logon returns (`POST /api/jwt/login` with a user name and password). opsdir sends it as `Authorization: AR-JWT <jwt>`. A JWT is valid for one hour by default (the server's `Rest-Authentication-Token-Timeout`). The operator, or their pipeline, logs on, keeps the token where the reference points, collects, and releases it (`POST /api/jwt/logout`).
- `bearer`: a BMC Helix SSO OAuth access token, which BMC documents for on-premises servers.

opsdir never logs on itself: a logon is a POST, and collection makes only GETs. Any other scheme is refused, with why.

Calls (GETs only: nothing is ever written to BMC, and no approval is ever answered):

| Call | Saved as |
|---|---|
| per linked ticket, `GET /api/arsys/v1/entry/CHG%3AInfrastructure%20Change?q='Infrastructure Change ID' = "<CRQ>"&fields=values(<the fields above>)&limit=2&offset=0` | `<host>/change/<CRQ>.json` (no entry: the ticket isn't read; two: named by the import) |
| then, per ticket read, `GET /api/arsys/v1/entry/AP%3ADetail-Signature?q=('Request' = "<its Request ID>" OR 'Request' = "<CRQ>")&fields=values(Detail-Sig-Id, Approval ID, Request, Application, Approval Status, Approvers, Approver Signature, Phase, Create-Date-Sig, Modified-Date-Sig)&limit=100&offset=<n>`, the page after each page that links a next one | `<host>/approval/<CRQ>/<offset>.json` |

There is one qualified read per linked ticket. Only the requested values, each entry's self link and the answer's next link are kept: never a detailed description, never a person's name.

**Least privilege.** Use a dedicated, non-administrator reader:
- a Read or Restricted Read license. Neither modifies requests; a Fixed or Floating license isn't needed to read.
- `Infrastructure Change Viewer` (it can also add work information, so it is broader than a GET-only reader needs) and the company visibility of the changes it reads.
- read access to `AP:Detail-Signature` and its fields for other users' signatures. BMC documents no role for a cross-user approval reader; Approval Admin isn't needed by anything found, so don't grant it by default. Confirm with a non-admin user on the tenant.

Form, field and row permissions apply to REST as they do on screen: a field the reader can't see is simply not returned.

## Handing findings over: work-order drafts (`opsdir tickets`)

`opsdir tickets <from> <to> -o DIR [--mine]` writes one draft per owning team of the plan's findings (milestone 7.7, decision 3415). This add-on drafts a BMC Helix **work order**: `tickets/bmc-helix/<team>.json` is the body of `POST /api/arsys/v1/entry/WOI%3AWorkOrderInterface_Create`, and `tickets/README.md` says how to file it. opsdir **never posts it** and holds no BMC credential. The team, or an admin, posts the file with their own AR-JWT:

    curl --request POST 'https://<ar-rest-host>/api/arsys/v1/entry/WOI%3AWorkOrderInterface_Create' --header 'Authorization: AR-JWT <jwt>' --header 'Accept: application/json' --header 'Content-Type: application/json' --data-binary @<team>.json

A work order is BMC's standalone object for scheduled fulfilment work. An ordinary Work Order User can submit one, within their company and support-group permissions.

The body is `{"values": {...}}`, following BMC's documented REST create example, plus the assignment, priority and deadline fields of the work-order create mappings:

| Field | Value |
|---|---|
| `z1D_Action` | `CREATE` |
| `Summary` | the draft's title (`CIAM: <n> findings for <team> (<from> to <to>)`) |
| `Detailed Description` | the findings as plain text, earliest do-by first. The spelling is correct here: the incident interface's `Detailed Decription` misspelling isn't used |
| `Status` | `Assigned` |
| `Support Company`, `Support Organization`, `Support Group Name` | the team's support group, from `bmc-helix-ticket-groups` |
| `Priority` | `bmc-helix-ticket-fields`' `Priority` when it gives one (`Critical`, `High`, `Medium` or `Low`); otherwise `High` when the team's findings include a blocker, and `Medium` when they don't |
| `Scheduled End Date` | the end of the earliest do-by day, UTC (`2026-11-01T23:59:59.000+0000`); left out when no finding has a do-by date |
| everything else | from `bmc-helix-ticket-fields` |

**Settings** (no defaults: they are the tenant's own names). Set each under an approved change with `opsdir setting <name> '<value>' --change <id>`:
- **`bmc-helix-ticket-groups`**: `<team>=<Support Company>/<Support Organization>/<Support Group Name>, ...`, with names as the foundation data has them. A team is matched by name, in any case. A team without a group gets no draft: the README names it, with the command to run. A value split by `/` into fewer than three names is refused (a group name may itself hold `/`; a company or organization name can't). No name may hold a comma.
- **`bmc-helix-ticket-fields`**: `<field>=<value>, ...`, the other values of every draft. It must give `First Name`, `Last Name`, `Customer First Name`, `Customer Last Name`, `Company`, `Customer Company` and `Location Company` (who submits the work order and for whom, as the tenant's foundation data names them, as in BMC's create example). Without them, no draft is written. It can also give `Priority`, `Work Order Type`, a template, categorization or a manager group, when the tenant's workflow requires them. The fields opsdir sets itself (`z1D_Action`, `Summary`, `Detailed Description`, `Status`, the support group, `Scheduled End Date`) are left out, with a problem naming them.
- **`bmc-helix-field-limits`**: `<field>=<characters>, ...`, the installed create form's character limits, from the tenant's administrator. A draft with a longer value isn't written (the problem names the field, its length and the limit); nothing is cut. Empty by default: nothing is checked.

**Linking the work order back.** After posting, the work order's number is the `WorkOrder_ID` field of the interface entry that the answer's `Location` names (`GET <Location>?fields=values(WorkOrder_ID)`). Link it on the opsdir change that does the work, as `ciamTicketRef bmc-helix:<Work Order ID>`, next to the change's own ticket. BMC documents the `WorkOrder_ID` field; that this exact read sequence returns it on 26.x is unconfirmed.

## Work orders read back (work tickets)

A linked `bmc-helix:` number that starts with `WO` (BMC's Work Order ID prefix: `WO0000000000401`) is a work order. Any other number is a change. The same importer and collector read work orders alongside the changes, as **work tickets** (`ciamTicketKind: work`): evidence that the work handed over is happening. They carry no approval, and the comparison asks none of one (`domains/governance/tickets.py`).

Work orders are read from `WOI:WorkOrderInterface`, the query interface BMC documents for integrations, qualified by `Work Order ID`. One qualified read per linked work order, `limit=2`, saved as `<host>/workorder/<WO>.json`, with no approval read:

    GET /api/arsys/v1/entry/WOI%3AWorkOrderInterface?q='Work Order ID' = "<WO>"&fields=values(Work Order ID, Request ID, Description, Status, Scheduled Start Date, Scheduled End Date, Actual Start Date, Actual End Date, Status Reason, Priority, Work Order Type, Last Modified Date)&limit=2&offset=0

An answer you saved is read too: a list answer or single entry whose values hold a `Work Order ID`.

| BMC Helix (`WOI:WorkOrderInterface`) | Record (`ciamTicket`, `cn=<WO>,ou=bmc-helix,ou=tickets`) |
|---|---|
| `Work Order ID`, `Request ID`, `Description` (the work order's summary on the interface), the self link | `cn`, `ciamProviderRef`, `ciamTitle`, `ciamDocUrl` |
| (always) | `ciamTicketKind` `work` |
| `Status` | `ciamTicketState` by `bmc-helix-work-order-states`; `ciamTicketNativeState` always |
| `Scheduled Start Date`, `Scheduled End Date` | `ciamTicketPlannedStart`, `ciamTicketPlannedEnd` |
| `Scheduled End Date` | `ciamTicketDue`: when BMC expects the work done |
| `Actual Start Date`, `Actual End Date` | `ciamTicketWorkStart`, `ciamTicketWorkEnd` |
| `Status Reason`, `Priority`, `Work Order Type`, `Last Modified Date` | `ciamTicketFact` `status-reason …`, `priority …`, `work-order-type …`, `last-modified …` |

**`bmc-helix-work-order-states`** maps a work order's Status to a state. Its default is BMC's documented work-order list (26.1 status transitions):

| Status | Neutral state |
|---|---|
| Assigned (the initial status) | `new` |
| Planning (created, work not started) | `assess` |
| Waiting Approval (only where work-order approval is enabled; it isn't out of the box) | `authorize` |
| In Progress | `implement` |
| Completed (reached when the last task closes) | `review` |
| Closed | `closed` |
| Cancelled | `cancelled` |
| Pending (waiting for information), Rejected (an approver rejected it) | none: the native state is kept, with a notice |

It is overridden like `bmc-helix-status-states`. A cancelled work order on a change the record approves is an action for the change's owner: the work handed over was withdrawn.

Least privilege for the reader: `Work Order Viewer` is BMC's view-and-search permission (it can't modify work orders, though it can add work logs), and is enough for a GET-only reader. The AR System license it needs for REST reads is unconfirmed.

## Known limits

- **Not run against a live server.** The add-on follows BMC's documentation (Innovation Suite 26.3 REST, the TrueSight Orchestration Remedy change mappings, the Mobility approval field catalog). Confirm field names on the tenant: a customised form, an enum customised beyond `bmc-helix-status-states`, or a field name the form doesn't have can make the server refuse the read (the collection then fails with BMC's message).
- **Approval linkage.** Which identifier `AP:Detail-Signature`'s `Request` holds for ITSM changes is unverified, so both are asked for. `Phase` is read by the name the Mobility catalog gives it, and the catalog's field-ID columns disagree. The process-level `AP:Detail` statuses aren't read: their REST field names weren't confirmed.
- **Decision times.** No signature field is documented as the time of the decision: `Modified-Date-Sig` is only the last update. AP status history is off by default since 21.3.06.
- **Paging.** A page is followed while the answer links a next one. The server caps a query at `Max-Entries-Per-Query` (2,000 by default), and offset paging isn't a consistent snapshot of signatures changing while they're read.
- **Rate limits.** BMC publishes no rate limit for the Helix SaaS AR REST API; requests are made one at a time.
- **Exports.** Only saved REST JSON is read. AR System report exports (CSV, ARX, XML) aren't, because their enum and time-zone fidelity is unconfirmed. Web (BIRT) reports can't be exported from the Report Console since 25.4.00, and a report needn't include the approval records.
- **Authentication.** opsdir doesn't log on (above). Helix Portal access keys and IMS tokens aren't shown to authenticate `/api/arsys` and aren't taken. OAuth bearer tokens are documented for on-premises servers only.
- **Government.** BMC Helix is FedRAMP Moderate (marketplace package F1510057481, since 2016-05-05), and Helix ITSM is listed among its regulated-cloud services. REST and authentication parity there, and its host names, are unverified: confirm them with the customer.
- **Comparisons.** As for the other ITSM add-ons, the record's `ciamPlannedAt` is compared by UTC day with the planned window, and ITSM's own work times with its planned window exactly. When the record itself applied a change is not compared yet.
- **One server.** One server per record: the link names a change number, not a server.
- **Work-order drafts.**
  - Not posted to a live server.
  - Whether `WOI:WorkOrderInterface_Create` takes `Scheduled End Date` and passes it to the work order is **unconfirmed**: BMC documents the field on the work-order query and update mappings, not on the create mappings. After filing, check the work order's date. opsdir writes no second (update) request.
  - The create interface's field lengths weren't confirmed for every tenant. Ask the tenant's administrator for the form's limits and give them as `bmc-helix-field-limits` (`Summary=<n>, Detailed Description=<n>, ...`): a draft with a longer value isn't written, and the problem names the field, its length and the limit. Nothing is ever cut; with no limits given nothing is checked.
  - **Sources disagree on the assignee fields.** The work-order create mappings (TrueSight Orchestration 23.x) name `Support Company`, `Support Organization` and `Support Group Name` as the assignee, and the draft uses them. The older SRM 8.0 module mappings (BMC Atrium Orchestrator 2013) list those names as manager-side and `ASCPY`, `ASORG` and `ASGRP` as the assignee. Confirm on the tenant which group a filed work order is assigned to.
- **Work-order read-back.**
  - A work order is told from a change by its `WO` prefix. A tenant that changed the Work Order ID prefix links numbers that are read as changes.
  - The fields are those of `WOI:WorkOrderInterface`'s documented query mappings. Their names on the 26.x base form `WOI:WorkOrder` are unconfirmed, so the base form isn't read. The assignee-side support group isn't read either: its field names there are unconfirmed.
  - BMC documents `Pending` as reachable from most statuses, but not as a status from any phase (Completed can't go to Pending, for example). Either way it has no neutral state.
- **Versions.** Current release 26.3.01. The support catalog lists on-premises 25.4.01 to 2027-05-20 and 26.1.01 to 2027-09-06; 26.2 and 26.3 dates aren't published there yet.

Sources (BMC documentation, read by the task 556 research on 2026-10-16): AR System REST access and authentication (Innovation Suite 26.3), entry endpoints, pagination and sort, JSON data types; Change Management web services and form guidance; the TrueSight Orchestration Remedy change module mappings; approval forms (AP:Detail, AP:Signature, AP:Detail-Signature) and the Mobility approval field catalog; Change Management roles; license types; Max-Entries-Per-Query; report exports; the regulated-cloud service list; the ITSM and Innovation Suite 26.3 release pages and the support lifecycle catalog; and the FedRAMP Marketplace.

## Tests

`tests/test_bmc_helix.py` covers:
- registration through the entry point, and the default status map.
- a linked change read as evidence, with unlinked and missing changes named.
- signature statuses to steps, and Rejected to the approval.
- drift (in step, unapproved, rejected, outside the window).
- classes that aren't a change type, and date-only times.
- unmapped statuses and an overridden setting.
- which signatures are a change's (Request, Application, duplicates), and incomplete pages.
- saved answers, errors, duplicates and two servers.
- the collector: an AR-JWT token, a bearer token, refused schemes, paging and the kept projections.
- work-order drafts: the create body, priority (derived, given, refused), owned fields, a team without a group or the foundation fields missing (no draft, with the command to run), and the hand-off files.
- work orders read back as work tickets (state, windows, due date, facts), an unmapped or cancelled status, and the collector's one work-order read with no approvals.

Run them with `env -u PYTHONPATH opsdir/.venv/bin/python -m pytest -q packages/opsdir-adapter-bmc-helix`.

# opsdir-adapter-jira-sm

opsdir ITSM add-on (adapter kind `itsm`) for Jira Service Management change management, Cloud and Data Center. It is the second ITSM add-on after `opsdir-adapter-servicenow`, with the same contract. It reads the change tickets that the record's change records are tracked by and records them as **evidence**, read-only (milestone 6.2f follow-ups, task 551). The governance domain then compares each ticket with the record: `opsdir report tickets` and the planner's `Change tickets` check (`opsdir/README.md`, *ITSM tickets*).

It also drafts the **work tickets** that hand a team its findings (task 612, below): files a person posts, never a write opsdir makes. Once linked, a work ticket is read back like a change ticket, without an approval to compare.

A ticket **never approves anything in opsdir**. The importer writes nothing under `ou=changes`. A ticket's approval never becomes a change's `ciamChangeStatus`, and its approvers never become `ciamApprovedBy`. The store's rule still holds: every write needs an approved change record.

**Applies to** no environment and renders nothing (`applies=None`). Collecting opts in through a collection source (below).

**Depends on** `opsdir` (the governance domain's ticket model: `domains/governance/tickets.py`).

## The link, in the record

A change record names its ticket in `ciamTicketRef`, as `jira-sm:<issue key>` (for example `jira-sm:ITOPS-42`). The link is the operator's, set under an approved change. Only linked tickets are read.

## The mapping, in the record

Jira has no fixed answer to what a change ticket's status means, or where its change window is:
- A change workflow's statuses are the site's own. Their ids differ between sites, and a status category says only new, in progress or done.
- The change fields (Planned start, Planned end, Actual start, Actual end, Change type, Change risk, ...) are custom fields whose ids differ between sites. Their types are generic (a date-time, a select list), so neither a field's name nor its type says what it means.

So the operator maps both, in two estate settings this add-on declares. Neither has a default. Each holds comma-separated `<name>=<value>` pairs, and each is changed like any other entry, under an approved change.

| Setting | Holds | Example |
|---|---|---|
| `jira-sm-status-states` | `<status id or exact name>=<state>`, the state one of `new`, `assess`, `authorize`, `scheduled`, `implement`, `review`, `closed`, `cancelled` | `10010=assess, Awaiting CAB approval=authorize, 10012=scheduled, Implementing=implement, Completed=closed, Canceled=cancelled, Declined=closed` |
| `jira-sm-change-fields` | `<role>=<field id or exact name>`: the roles `planned-start`, `planned-end`, `work-start`, `work-end` (the actual window) and `change-type`; any other role (`risk`, `impact`, `urgency`, ...) is kept as a fact | `planned-start=customfield_10070, planned-end=customfield_10071, work-start=Actual start, work-end=Actual end, change-type=Change type, risk=Change risk` |

How the mapping is applied:
- A status's id is matched before its name. A status name holding a comma can only be mapped by id.
- A status that isn't mapped keeps only its native state. Its neutral state is unknown, so the ticket is never taken as closed or cancelled, and a notice names it.
- A field name is resolved through the site's field list (`GET /rest/api/3/field`, which the collector saves). A name two fields share is refused: map it by id.
- A window role that isn't mapped leaves that time empty. A notice names it, with the site's fields named like the documented window fields as candidates.
- Malformed parts, a status mapped twice (the first is used) and states outside the list are named in notices.

## What a ticket says

| Jira | Record (`ciamTicket`, `cn=<key>,ou=jira-sm,ou=tickets`) |
|---|---|
| `key`, `id`, `self`, `summary` | `cn`, `ciamProviderRef` (the id: a key changes when an issue moves), `ciamDocUrl` (the issue's REST URL as Jira gives it), `ciamTitle` |
| `status` | `ciamTicketState` by `jira-sm-status-states`; `ciamTicketNativeState` always: `<status id> <status name>` |
| each approval step (`GET /rest/servicedeskapi/request/<key>/approval`) | `ciamTicketApprovalStep` `<finalDecision> <step id> created <time>[ completed <time>]`: Jira's own decision of the step |
| the steps' decisions | `ciamTicketApproval`, derived (below) |
| each step's approvers | `ciamTicketApprover` `<approverDecision> <accountId, or key on Data Center> step <step id>`: detail only, identifiers, never names |
| the `change-type` field | `ciamTicketChangeType` when its value is `standard`, `normal` or `emergency` (any case); any other value is kept as a fact, with a notice |
| the `planned-start`, `planned-end`, `work-start`, `work-end` fields | `ciamTicketPlannedStart`, `ciamTicketPlannedEnd`, `ciamTicketWorkStart`, `ciamTicketWorkEnd` |
| `issuetype`, status category, `resolution`, `created`, `updated`, other mapped fields | `ciamTicketFact` `<name> <value>` (an option as its value, a person as their id) |

**Work tickets.** A linked issue of the type `jira-sm-ticket-issue-type` maps for its project (the key's prefix) is a work ticket: a team's findings handed over (below). It is read the same way, except:
- `ciamTicketKind` is `work`, and `ciamTicketDue` is its `duedate` (a day, kept as its 00:00 UTC). A `duedate` that isn't `YYYY-MM-DD` is left out, with a notice.
- It has no `ciamTicketApproval`, approval steps, approvers or change type, and the collector asks for no approval pages for it. The governance domain compares no approval for a work ticket.
- Its statuses are mapped in the same `jira-sm-status-states` (`To Do=new, In Progress=implement, Done=closed`, by id or name). A Task workflow's statuses are usually not the change workflow's, so map both.

**The overall approval is derived.** Jira Service Management has no request-wide approval. It approves by workflow steps, each with its own final decision (`approved`, `declined`, `pending`). The user's rule (task 551) is:
1. Any step declined: `rejected`.
2. Otherwise, any step pending: `requested`.
3. Otherwise, at least one step, all approved, **and** the ticket's neutral state is past authorization (`scheduled`, `implement`, `review` or `closed`): `approved`. The state matters because a later approval step may still come while the ticket waits in an approval status.
4. Otherwise: unknown. A ticket with no steps is unknown, never `not-requested`: no steps doesn't mean none was needed.

A single approver's decision never decides it. When the export holds no approval answer for a ticket, or its pages stop before one that says it is the last, the approval is unknown and a notice names the ticket.

**Times.** Jira's date-times carry their offsets (`2026-09-24T08:00:00.000+0200`) and are read as UTC. A date without a time (a Date Picker field) is refused with a notice: its time zone is unknown, so map a date-time field.

## Reading tickets (importer `jira-sm/change-requests`)

`opsdir import --change CHG-… --at <when the export was taken> jira-sm/change-requests <folder>`. The folder holds JSON answers:

| Form | Files |
|---|---|
| As `opsdir collect` saves them | `<site host>/field.json`, `<site host>/issue/<key>.json`, `<site host>/approval/<key>/<start>.json` |
| Answers you saved | any `*.json` that is an issue (`GET /rest/api/{3,2}/issue/<key>`), a search answer (`{"issues": [...]}` from Cloud's `/rest/api/3/search/jql` or Data Center's `/rest/api/2/search`) or the field list; approval pages under `approval/<key>/` or named `approval-<key>*.json` |

What the import does with what it finds:
- Each ticket read is its own import group, so an import replaces only the tickets it read.
- A linked ticket missing from the export is never removed. The record keeps what it last read, and the planner reports the ticket as not imported.
- Tickets the record doesn't link are named in a notice and left out.
- A mapped field the issues never carry is named in a notice: the reader can't see it, or it isn't on the change screens.
- An error answer (`{"errorMessages": ...}`, `{"errorMessage": ...}`) is named, as is a JSON file that isn't a Jira answer.
- Issues from two sites (their `self` URLs) are refused: import one site at a time.

## Collecting (`opsdir collect`, read-only)

An environment's `ciamCollectionSource` with `ciamImporter: jira-sm/change-requests` says where to read. `ciamSourceRef` is the site's base URL, which also says how the site is read:

| Base URL | Read as |
|---|---|
| `https://<site>.atlassian.net`, Government Cloud `https://<site>.atlassian-us-gov-mod.net` | Cloud, REST v3 |
| `https://api.atlassian.com/ex/jira/<cloudId>` (scoped API tokens, service accounts and OAuth 2.0 use the gateway; Government Cloud's is `https://api.atlassian-us-gov-mod.com/ex/jira/<cloudId>`) | Cloud, REST v3 |
| anything else | Data Center, REST v2 |

The credential is the one its `ciamCredentialRole` binding references, resolved when collecting and never stored. `ciamCaRole` names the trust anchor, when the site needs one. `ciamCredentialScheme` is one of:
- `basic`: on Cloud, the account's email as `ciamLoginName` and an API token; on Data Center, a user's password.
- `bearer`: on Data Center, a personal access token; on Cloud, an OAuth 2.0 (3LO) access token or a scoped token, minted outside opsdir, with the gateway URL. On Data Center, the approval resource refuses OAuth 2.0 apps, so use a personal access token there.

Calls (GETs only: nothing is ever written to the site, and no approval is ever answered):

| Call | Saved as |
|---|---|
| `GET /rest/api/{3,2}/field` | `<host>/field.json` (each field's id, name, custom, schema) |
| then, per linked ticket, `GET /rest/api/{3,2}/issue/<key>?fields=summary,status,resolution,issuetype,created,updated,duedate,<the mapped field ids>` | `<host>/issue/<key>.json` (a 404 is a ticket not read) |
| then, per ticket read that isn't a work ticket, `GET /rest/servicedeskapi/request/<key>/approval?start=<n>&limit=50`, page after page until one says `isLastPage` | `<host>/approval/<key>/<start>.json` (a 404, an issue that isn't a request, has none) |

There is one GET per linked ticket rather than a search. Searches on Cloud may lag ("recent updates might not be immediately visible"), and Data Center refuses a whole `key in (...)` query (400) when one key doesn't exist. Only what the importer reads is kept: people as their ids, never a display name or an email address.

**Least privilege.** Use a dedicated reader:
- **Browse Projects** on the change projects only, plus the issue security levels their change tickets use.
- Permission to view the requests, which the approval resource needs. No agent licence is documented as required for it.
- On Cloud, scopes `read:jira-work` and `read:servicedesk-request` (classic), or the granular `read:request.approval:jira-service-management` and `read:user:jira` plus the issue reads' own list (`read:issue-details:jira`, `read:field-configuration:jira`, ...).

Scopes don't grant project access: permissions still decide what the reader sees.

## Work-ticket drafts (`opsdir tickets`)

For each team a plan's findings name as owner, the core's hand-off (`opsdir tickets <from> <to> -o DIR [--mine]`) asks this add-on for a draft. It writes `tickets/jira-sm/<team>.json` and a section of `tickets/README.md` saying how to file it, or what kept it from being drafted. **opsdir files nothing and holds no Jira credential.** The team, or an admin, posts the draft with their own credentials, then links the issue it creates on the opsdir change that does the work (`ciamTicketRef jira-sm:<key>`). The next import reads its state back as a work ticket.

The draft is a plain issue of the project's **Task** type, not a customer request: no service desk or request type is involved. It is the body of:
- **Cloud**: `POST /rest/api/3/issue`, with the description in Atlassian Document Format: the line saying where the findings come from, a *Findings* heading, a bullet list (earliest do-by first, those without one last) and the link-back line.
- **Data Center**: `POST /rest/api/2/issue`, with the same description as a wiki-markup string (`h2. Findings`, `*` items). Wiki markup's special characters in the text (`[ ] { } | * _ + ^ ~ ! \`) are escaped, so they show as they are.

Which one is used depends on `jira-sm-ticket-site`, told apart the way the collector tells sites apart (above).

The body's fields:
- `project` `{key}` and the team's routing field.
- `issuetype` `{id}`.
- `summary`: the request's title, cut to 255 characters.
- `description`.
- `duedate`: the earliest do-by, `YYYY-MM-DD`. Left out when no finding has one.
- The operator's defaults.

All of these come from estate settings without defaults, because they are the site's own ids:

| Setting | Holds | Example |
|---|---|---|
| `jira-sm-ticket-site` | the base URL of the site the tickets are filed on | `https://example-aero.atlassian.net`, `https://jira.example-aero.test/jira` |
| `jira-sm-ticket-projects` | `<team>=<project key>[/<team field value>]` (a team by name, any case) | `Platform=CIAM/value:Identity, network=NET` |
| `jira-sm-ticket-team-field` | the field a team's value goes in, by id, for a site that routes by a team, component or select field | `customfield_10100`, `components` |
| `jira-sm-ticket-issue-type` | the work tickets' issue type id: one for every project, or `<project key>=<id>` where projects differ (a team-managed project has its own). From `GET /rest/api/3/issue/createmeta/<project key>/issuetypes` (`/rest/api/2/...` on Data Center) | `10002`, `CIAM=10105, NET=10002` |
| `jira-sm-ticket-fields` | `<field id>=<value>` every work ticket is created with | `priority=id:3, labels=list:ciam\|remediation` |

A field value is text as it is, or `<shape>:<value>`:
- `id:3`, `value:High`, `name:IAM`, `key:...` and `accountId:...` give an object with that key.
- `ids:`, `values:`, `names:` and `keys:a|b` give a list of such objects (`components=names:IAM|Directory`).
- `list:a|b` gives a list of text (labels), `number:5` a number, and `text:<value>` text that would otherwise read as a shape.

`project`, `issuetype`, `summary`, `description` and `duedate` are the draft's own: a default naming one is left out, with a problem.

What keeps a team's draft from being written is listed under the team in the README, with the setting to give (`opsdir setting <name> <value> --change <id>`):
- no site, or a site that isn't a base URL;
- no project for the team;
- no issue type for its project;
- a team value without `jira-sm-ticket-team-field`.

A malformed default is named too, and left out, but the draft is still written.

How to file, as the README says:
- **Cloud**: `curl --request POST 'https://<site>.atlassian.net/rest/api/3/issue' --user '<email>:<api-token>' --header 'Accept: application/json' --header 'Content-Type: application/json' --data-binary @jira-sm/<team>.json`. Through the gateway (`.../ex/jira/<cloudId>`), use `--header 'Authorization: Bearer <access-token>'` instead.
- **Data Center**: the same request to `/rest/api/2/issue` with `--header 'Authorization: Bearer <personal-access-token>'`.
- **Government Cloud**: OAuth 2.0 apps call the gateway `https://api.atlassian-us-gov-mod.com/ex/jira/<cloudId>` with a bearer token.

The poster needs **Browse Projects** and **Create Issues** in the project, plus **Schedule Issues** and `duedate` on the create screen for the due date.

## Known limits

- **CSV and XML exports aren't read** (deferred). A CSV export's times are in the exporting user's format and time zone, with no offset. Its column names for custom fields, the XML export's shape and whether either carries approval decisions weren't confirmed by the research. No export carries the approval steps, so save the REST answers (or collect).
- **Overall approval** is derived by the rule above, because no request-wide approval was found in Atlassian's documentation. Whether an approval step a ticket hasn't reached yet already has an approval object is unverified, so an all-approved ticket still waiting in an approval status stays unknown.
- **Status categories** are lifecycle only and kept as a fact. Atlassian's documentation lists `new`, `indeterminate`, `done`, while its workflow-status examples show others.
- **Field identity.** Field types are generic and no complete catalog of stable change-field identifiers is documented, so fields are mapped by id or exact name, never guessed.
- **Comparisons.** As for ServiceNow: the record's `ciamPlannedAt` is compared by UTC day with the planned window, and ITSM's own work times with its planned window exactly. When the record itself applied a change is not compared yet.
- **One site.** One site per record: the link names a key, not a site.
- **Government Cloud.** Jira Service Management is available on Atlassian Government Cloud (FedRAMP Moderate). Its OAuth 2.0 (3LO) endpoints are documented, but full REST parity (search, approvals) and scoped tokens there are unverified: confirm with the customer.
- **Work-ticket drafts.** Unconfirmed, so check them on the site before filing:
  - Whether every operation and body is the same on Government Cloud (the research found no documented difference, but no stated parity either), and whether an API token is taken on a Government Cloud site itself.
  - Whether a Data Center description field uses the wiki renderer (with the default text renderer, the escapes show).
  - Which value shape a site's team field takes: the Atlassian Team field, a select list's `{"value"}` or components' `{"name"}`.
  - What else a project's create screen requires: read its create metadata.

  A JSM customer request (`POST /rest/servicedeskapi/request`) isn't drafted. Assignment to a person isn't drafted either, and is left to the project's routing.
- **Data Center** 11.3 (the current LTS, supported to 2027-12-03) and 10.3 are documented alike. Atlassian ends Data Center on 2029-03-28.

Sources (Atlassian documentation, read by the task 551 research on 2026-10-16): Jira Cloud platform REST v3 issue search, issues and issue fields; Jira Service Management Cloud REST request approvals; Jira Data Center REST 11 search and Jira Service Management Data Center REST approval; default form fields for change requests; the change management workflow; export search results; API tokens, service accounts and Government Cloud 3LO; Data Center release notes and end-of-support policy.

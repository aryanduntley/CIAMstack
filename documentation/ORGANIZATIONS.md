# Organizations with several businesses

*How CIAMstack serves a group whose businesses run their own identity platforms: one standard across all of them, without one shared database or one shared stack. How a single record is set up is in [`RECORD-DATABASE.md`](RECORD-DATABASE.md); how a move works is in [`MIGRATIONS.md`](MIGRATIONS.md).*

---

## 1. The situation

Large groups are often made of businesses with their own histories, customers and security requirements, each with substantial operational autonomy. They may share enterprise security standards, cloud governance and some identity services. They rarely run identical identity infrastructure: one business may run PingDS and PingFederate, another a different identity provider, a third a more restricted environment with its own controls.

Two things make this hard to manage:

- **Different stacks.** Each business runs a different mix of directories, federation, access management, secret stores and tooling, so a tool built for one stack doesn't fit the others.
- **Different boundaries.** Each business has its own administrators, credentials, compliance obligations and, often, a system boundary an assessor treats as its own. Putting every business's configuration into one central system crosses those boundaries.

CIAMstack handles the first with adapters ([`MODULAR-STACKS.md`](MODULAR-STACKS.md)) and the second with one record per business.

## 2. One standard, separate records

**Each company keeps its own record.** A parent organization and each business run their own database, on their own server, under their own administrators and credentials, inside their own compliance boundary. The boundary is physical, a separate database, instead of depending on permission rules inside a shared one.

**The standard is the same everywhere.** Every record runs the same core: the same schema, the same database rules (every write approved, typed, schema-checked, kept in history, never holding a secret value), the same reports, dependency graph and planner checks. So governance is consistent across the group without its infrastructure being centralized:

| Shared by every business | Each business's own |
|---|---|
| The core: schema, rules R1–R10, reports, planner, workspaces | Its record's database, server and backups |
| How changes are approved and kept (author and approver recorded, approver never the author) | Its people, teams, grants and approvers |
| How keys and secrets are handled (references only, never values) | Its secret stores, keys and certificates |
| The adapters for products more than one business runs | The adapters for the products it runs, and only those |
| The vocabulary of findings, owners and evidence | Its environments, clouds, accounts and stacks |

A business installs only the adapters for what it runs. If two businesses run PingFederate, they install the same adapter and their PingFederate configuration is held and rendered the same way. If a third runs something else, it installs that product's adapter, or one is written for it, and nothing changes for the other two.

## 3. Each record knows whose it is

A record names the company it belongs to in one governed entry (`opsdir identity`):

```bash
opsdir identity --org exa-air --parent exa --name "Example Aero Air Systems" --change CHG-12
```

- The **org code** and a **record ID** (a UUID made when the identity is first set) can't change once set. The database refuses changing them or removing the entry, whoever connects.
- The **parent** (`--parent`) and the name may change, as when a business leaves the group.
- Once a record has an identity, every new change record is named with the org code as prefix (`exa-air-CHG-13`). The database refuses other names, so change IDs stay unique across the group.
- Exports and evidence packages name the record they came from.
- Starting cloud names with the org code (`exa-air-aws`) keeps environment names unique across the group. `opsdir posture` notes cloud names that don't.

## 4. What one business relies on from another

Businesses in a group usually share some services: the cloud landing zone the parent runs, a corporate certificate authority, a shared federation service, a shared SIEM. A business's record holds these as things it relies on and someone else keeps:

- **Keepers.** A team or organization that keeps infrastructure is a party (`ciamParty`), and each binding it keeps names it (`ciamManagedBy`). The landing zone's owner keeps the landing zone (its identities, guardrails and network plumbing) by default. If the party takes generated infrastructure, its part renders into its own Terraform root. If it doesn't, nothing is written for it: the stack's own root names what it keeps, and the planner drafts the request to it (`requests/<party>.md`).
- **Neighbours.** A cloud-managed identity service someone else runs, which the platform federates with, is a neighbour binding: the integrations it is the partner side of, and its keeper.
- **External systems and trust.** Systems the platform reaches but doesn't run are external hosts with a role. Outside PKIs the platform trusts are trust bundles with their restrictions. Other parties' allowlists that hold the platform's addresses are entries with an owner and a lead time.

So when the parent changes something every business relies on, such as moving the shared cloud to another provider, each business's planner names what that means for its own platform: the requests to draft, the allowlists to update, the keepers to ask.

## 5. Teams inside each business

Inside one record, people work as teams that own their areas:

- **Owners and keepers** are part of the record, so findings, renders and drafted requests reach the team responsible: directory, federation, cloud, network and DNS, security and SIEM, PKI, compliance and application owners.
- **Grants** give people and teams actions (`render`, `plan`, `propose`, `approve`, `apply`, ...) limited to environments and to what given teams own or keep. The database checks them again on every write, so an approver from another team can't approve a change touching what isn't theirs.
- **Risk-tiered approval** can require more approvers for production than for stage (`approvals-required`).
- **'My area'** (`--mine`) focuses reports, plans and fixes on a person's own teams, and `opsdir tickets` drafts one work ticket per owning team for the plan's findings, which the team files with its own ITSM credentials.

## 6. A group-wide move

When the whole group moves, for example from one cloud to another, every business moves its own platform, on its own schedule, with the same tooling:

- The target cloud's adapter is the same package for every business, so it is written and tested once.
- Each business plans its own move in its own record ([`MIGRATIONS.md`](MIGRATIONS.md)): its own workspace, target stack, blockers, actions, owners and dates.
- A business can move its infrastructure and keep its products (a lift-and-shift), change products as part of the move, or both. Each choice is declared in that business's target stack, not imposed by the others.
- What the businesses share (the landing zone, shared services) appears in each plan as keepers and requests, so the dependencies between businesses are named rather than discovered at cutover.

## 7. Mergers, acquisitions and spin-offs

- **A business that leaves the group** takes its own record with it. Its identity's parent is changed or removed; nothing else needs to move.
- **A business that joins** brings its record. Combining two records (`opsdir merge`) is **planned, not built**. The groundwork is in place: record identities that can't change, org-prefixed change IDs, and the cloud-naming convention. The merge will move the incoming company's entries under its own name, propose things both companies record (a shared vendor, partner application or CA) as matches for a person to confirm, carry the history with its original approvals, and apply as one approved change after a preview. Moving the incoming company onto the other's platform is then an ordinary migration.

## 8. What isn't built yet

- **No view across records.** Each record is reported on separately. A group-wide picture today means running the same reports in each business's record.
- **No references between records.** A shared service one business runs is recorded in another business's record as a keeper, neighbour or external host, not as a link into the first business's record.
- **No merge tool** (section 7).

## 9. Questions to settle at the start

- Is identity infrastructure standardized across the businesses, or does each maintain its own stack?
- Which services are shared (cloud landing zone, CA, federation, SIEM, ITSM), and who keeps each?
- Which businesses have their own compliance boundaries, and does each need its own record?
- For a planned move: is it a lift-and-shift of the existing products, or are products and architecture changing too? Does every business move, and on what schedule?

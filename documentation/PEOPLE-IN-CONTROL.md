# People decide, adapters translate, the record checks

*How work is divided in CIAMstack: what engineers decide, what adapters automate, and how the record catches what doesn't fit. It applies to everyday operation and to migrations alike.*

---

## 1. Not an autopilot

CIAMstack doesn't migrate or reconfigure a platform on its own judgment. It gives engineers **one place to model, validate and operate a heterogeneous identity platform**, with adapters translating their decisions into each underlying product and cloud.

The engineers make the decisions and enter them in the record. They choose the target stack, connect each application to the identity service that serves it, decide which secret store holds each credential, and resolve each incompatibility. CIAMstack then does the translation and the checking. It manages how the products, services and protocols connect to each other, and it reports anything that won't work together before it reaches production.

A migration is therefore **operator-directed, with adapter-driven translation**. It also gets easier to manage, because the source and the target are handled through the same interface and the same record.

## 2. Who does what

| | Decides | Does |
|---|---|---|
| **People** | The target stack, bindings, owners; which conflicts take the live value; which fixes to apply; which risks to accept | Enter decisions as governed changes; approve each other's changes; deploy the rendered files; prove behavior in stage |
| **Adapters** | Nothing | Read each product's exports and APIs into the record; render each product's working files from it; declare what their product can and can't express; check what their product requires |
| **The record** | Nothing | Refuses invalid, unapproved or secret-bearing writes and deletions that would break something; keeps history; compares environments; reports every blocker and action with an owner |

## 3. What is automated, and what needs a decision

CIAMstack doesn't sort configuration up front into "translates automatically" and "needs engineering". The line comes from the adapters:

- **What an adapter implements is automated.** Whatever the record holds and the target's adapters can render, they render. Shared intent comes out the same for every environment, and only the target's own bindings differ.
- **What an adapter can't express becomes a finding.** It is never dropped silently. A render note, a planner blocker or action, or a source object says what is missing, and a person decides.
- **Differences between clouds and products always need engineering decisions.** Services one cloud has and another doesn't, products with different capabilities, network designs, and compliance boundaries are surfaced with an owner. A person resolves them in the record.

So adapters automate only the transformations they actually implement, and the rest arrives as a list of decisions with owners and dates.

## 4. How decisions reach people

Each kind of open decision has its own place in the record, and each names who must act:

| What | Where it appears | Who acts |
|---|---|---|
| **The live system and the record disagree** | An import lists each difference as a conflict. An applied import is refused until each is decided: take the live value (`--take`) or keep the record's (`--keep`). Neither side is assumed right. | The operator importing |
| **A planner finding** | `opsdir plan`: blockers and actions, each with an owner and, for actions, a do-by date | The owning team |
| **A known fix** | `opsdir fix list` / `fix show`: the exact record change, the steps outside the record that go with it, and what applying it could hide | Proposed by anyone, approved by someone else |
| **A choice** | A fix offering options, such as the secret role a withheld credential comes from, which is never guessed | A person picks with `--option` |
| **A value only the operator knows** | A fix taking inputs (a provider reference, a DNS name, a bucket), each with an example and the pattern it must match | A person gives it with `--input` |
| **Something a product can't express** | The render's notes (`opsdir check`, `NOTES.md`): blockers and actions | The team owning the product |
| **What a retired product holds** | Source objects, each with an owner and how it is handled (rebuild, re-provision, re-register, replace, retire, review) | Its owner |
| **An open question** | The unknowns register: the question, who must answer it, by when, and whether a move waits for it | The named owner |
| **Infrastructure another team keeps** | Its own Terraform root, or a drafted request to it (`requests/<party>.md`) | The keeping team |
| **Work for each team** | `opsdir tickets`: one drafted work ticket per owning team, for its ITSM | The team files it with its own credentials |

Nothing is applied without an approved change ([who may propose, approve and apply](SECURITY.md#4-what-each-person-may-do)). An AI working through the API or the planned MCP tools can propose changes as the user who asked, never approve them.

## 5. The error checking

Mistakes are caught at each stage, before they reach the platform:

1. **On every write, by the database.** Unknown or missing fields, values of the wrong type, references to entries that don't exist, secret values, deleting something still in use, and changes nobody approved are all refused (rules R1–R6 in [`opsdir/SPEC.md`](../opsdir/SPEC.md)). The approver is never the author (the default; only a one-person install turns this off), and grants are checked again on every write.
2. **On render, by the adapters.** What a product can't express and roles an environment doesn't bind are reported as the render's blockers and actions. `opsdir check` also names every server or workload running a product version outside its adapter's supported range.
3. **On plan, by every applicable check.** Changed contracts, ports the target's firewalls don't open, keys kept wrongly, certificates expiring before cutover, services the target cloud or its authorization doesn't offer, capabilities a managed service lacks, unanswered questions, and other parties' allowlists still pinning old addresses.
4. **On import, by comparison.** Each reading of the live system shows where it disagrees with the record.
5. **After deployment, by collection.** Regular read-only collection turns drift into findings, and `opsdir onboard verify` checks that every environment renders back to what its original exports said.

## 6. One control plane for heterogeneous systems

Because every product and cloud is reached through its adapter and held in one model, the same interface covers all of them:

- one record of what the platform is, whatever mix of products and clouds it runs on;
- one approval process for every change, whichever product it touches;
- one set of questions answered across products (what an application touches, what a certificate's rotation breaks, what drifted);
- one plan for a move, covering the source and the target together.

The engineers' judgment stays where it belongs, in the decisions. The repetitive part (rediscovering the estate, rewriting configuration for each product, finding forgotten dependencies) is what CIAMstack takes over.

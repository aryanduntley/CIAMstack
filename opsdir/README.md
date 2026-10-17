# opsdir: database-first management of an identity platform

opsdir is the system of record an identity platform is operated from. Its servers, bindings, directory configuration, consumers, access rules, federation integrations, claims, certificates, external allowlists, runbooks and changes live as **typed, schema-checked, cross-referenced entries** in an LDAP-modeled PostgreSQL store. Everything else is built on that record: reports and queries, user interfaces, and every working file, which **adapter packages** render from it (and, over time, import back).

- **A change is an entry,** made under an approved change record and kept in history. It is never a hand edit to a file or a console.
- **Questions become queries:** blast radius, expiry, drift, who can read what, which outside parties' allowlists hold our addresses.
- **Moving a platform is one capability, not the point:** declare the target's stack and bindings in a workspace, plan, render, cut over. The intent (directory configuration, access rules, federation) is the same record, rendered for new bindings.

This package is the **core**. It names no cloud, product, vendor or secret store: those are adapter packages (in this repository under [`../packages/`](../packages/)) that the core discovers when they are installed. The standard is in [`SPEC.md`](SPEC.md); a runnable example estate is in [`../examples/showcase/`](../examples/showcase/).

## Install

```bash
scripts/dev-install.sh      # venv in .venv + this core + every package in ../packages, editable
                            # (re-run after changing any pyproject.toml)
```

On a machine whose global pip config sets `user = true`, pip refuses it inside a venv; the script sets `PIP_USER=0` and `--no-cache-dir` (nothing is written to `~/.cache/pip`). The core alone is `pip install -e .`; it runs without any adapter, but then renders nothing.

## Use

`./opsdir.sh` runs the CLI from anywhere against `OPSDIR_DSN` (by default the local dev database, `scripts/dev-env.sh`). Relative paths are relative to where you run it; outputs default to `out/` there.

```bash
./opsdir.sh init                      # DROPS the opsdir schema, then creates it (all migrations, views, registry)
./opsdir.sh upgrade                   # upgrade it in place instead: pending migrations, keeping data and history
./opsdir.sh load FILE.ldif...         # load LDIF content under change BOOTSTRAP
./opsdir.sh check [CLOUD/ENV...]      # each environment's declared stack vs the installed adapters, and its render's
                                      # blockers and actions (render notes)
./opsdir.sh modify --change CHG-… FILE.ldif   # apply LDIF change records under an approved change
./opsdir.sh import [--change CHG-…] ADAPTER[/IMPORTER] PATH [--dry-run] [--at TIME] [--take K|all] [--keep K|all]
                                      # read a product's export into the record (conflicts decided: below)
./opsdir.sh collect [--env CLOUD/ENV] [--adapter A[/I]] [--list] [--dry-run] [--change CHG-…] [--save DIR]
                                      # read the live system for the importers, read-only (below), then import
./opsdir.sh capture --change CHG-… FILE       # hold a config file in the record (settings, whole, or a reference)
./opsdir.sh file NAME [--env CLOUD/ENV]       # rebuild a captured file from the record
./opsdir.sh census --change CHG-… PATH        # where the record's values occur in files (secrets flagged, not stored);
                                              # --replace: PATH is the whole census
./opsdir.sh setting NAME VALUE [--change CHG-…] [--dry-run]   # an estate setting's value (opsdir report settings)
./opsdir.sh search -b BASE 'FILTER' [ATTR...] # RFC 4515 search, as LDIF or a table of attributes
./opsdir.sh report NAME [DN]          # portability, unowned, blast-radius DN, settings, and every domain's reports (consumers,
                                      # keys ENV, drift, ...); dates as of --as-of
./opsdir.sh render CLOUD/ENV [-o DIR] [--target ADAPTER=T[,T]]  # everything the environment's adapters render, plus MANIFEST.json, NOTES.md/.json
            [--keeper PARTY | --kind CLASS... | --binding DN...] [--as REQUESTER]   # or one slice of its infrastructure (below)
./opsdir.sh plan SRC DST [-o DIR]     # what blocks moving SRC to DST, dated actions, request drafts
./opsdir.sh migrate SRC DST [-o DIR] [--as REQUESTER]  # check both stacks, plan, render the target; exit 1 unless ready
./opsdir.sh export [-b BASE]          # entries as LDIF (for review)
./opsdir.sh history [DN]              # governed changes
./opsdir.sh application DN|NAME [--env CLOUD/ENV] [--format text|json]   # everything an entry (an application: NAME) touches,
                                      # in sections, each row naming its entry
./opsdir.sh graph DN|NAME [--direction up|down|both] [--depth N] [--env CLOUD/ENV] [--format text|json|dot]
                                      # what it depends on and what depends on it (by DN and by role)
./opsdir.sh summary [SRC DST] [--format text|json]   # the estate in counts with their evidence (and the plan's)
./opsdir.sh evidence --boundary B [--control C]... [-o DIR] [--change CHG-…] [--kept-at URL]
                                      # a system boundary's compliance evidence package, as of --as-of (below)
./opsdir.sh workspace create|status|diff|cutover     # migration workspaces (below)
./opsdir.sh --workspace COMMAND …     # any command against the workspace instead of the live record
```

An adapter may offer several render targets (`Adapter.render_targets`): PingFederate renders its configuration as
Admin API requests (`admin-api`) and as Terraform for Ping's provider (`terraform`). `--target pingfederate=terraform`
renders one; every target is rendered by default except those an adapter offers only when asked (PingFederate's
`terraform-imports`, import blocks adopting an existing PingFederate's objects), and MANIFEST.json records the targets chosen. An adapter or
target the environment doesn't have is refused, naming those it has. Plans and migrations render every target.

### Open questions (the unknowns register)

What nobody can answer from the record yet is recorded as a question under `ou=unknowns` (`ciamUnknown`, the
governance domain): `ciamQuestion`, `ciamOwner` the party who must answer it, `ciamBlocking` whether a move waits for
it, `ciamConcerns` the environments (or entries inside them) it concerns (none: the estate), `ciamRaisedAt`,
`ciamNeededBy`, and once answered `ciamAnswer` and `ciamAnsweredAt`. Like any entry it is written under an approved
change. `opsdir report unknowns` lists them (open, overdue past their needed-by date, answered). `opsdir plan` counts
the ones concerning the source or the target (area `Unknowns`): an open blocking question is a blocker, so the plan
can't be READY; another open one is an action for its owner, dated by `ciamNeededBy` (else the planned cutover); an
answered one is listed as in place. No fix is offered (an answer is a person's), and an approved risk exception
accepts these findings like any other.

### What a retired product holds (source objects)

A migration away from a product (a web access manager, a legacy federation server) meets what it holds that the
standard model has no equivalent for: its agents' configuration, host registrations, custom sign-on code, keys it
never exports. Its adapter's importer records each as a source object under `ou=<importer>,ou=source-objects`
(`ciamSourceObject`, the governance domain): the product's own type (`ciamSourceClass`) and its facts
(`ciamSourceFact`, `<setting> <value>`, never a secret), the server role that holds it (`ciamTargetRole`), how it is
handled when the product is retired (`ciamHandling`: rebuild, re-provision, re-register, replace, retire, review) and
in words (`ciamHow`), whether a move waits for that (`ciamBlocking`) and the entries it concerns (`ciamConcerns`).
Owners and handling are the record's to change: a re-import keeps them. `opsdir report source-objects` lists them;
`opsdir plan` makes each one held by a role the source runs and the target doesn't an action for its owner (by the
planned cutover), or a blocker when the move waits for it (area `Source objects`); a target still running the role
keeps it in place. A product that only ever appears as a source adds its own planner checks as `source_checks`
(`opsdir.core.contract.Adapter`): the plan runs them when the adapter applies to the source environment. And an
integration registered with an identity service the target doesn't run (`ciamServedBy`, the service's
`ciamTargetRole`) is a blocker until it is re-homed (area `Federation`).

### Compliance evidence

Which record queries show which controls met is recorded under `ou=evidence-queries` (`ciamEvidenceQuery`, the estate
domain): `ciamControlRef` the controls (framework:control), `ciamEvidenceSource` what it runs (a report of `opsdir
report`, `history` for the change history, or `search` for an LDAP search: `ciamEvidenceFilter` and the
`ciamEvidenceAttribute`s it shows), `ciamEvidenceDn` the DN it runs on (the report's DN argument, the entry whose
history it is, the search's base), `ciamEvidenceCadenceDays` how often it is collected again and `ciamManagedBy` who
keeps it. `opsdir evidence --boundary B` writes a system boundary's package as of `--as-of`: for each control that the
authorizations its environments rely on leave to the operator (customer or shared, `ciamControlResponsibility`) and a
query names (`--control` narrows), a `<framework>_<control>/` folder with each query's output as CSV and JSON, and
`MANIFEST.json` (the boundary, the day, the history point: the last governed change and how many history entries there
are, and each file's SHA-256). A report with an `environment` column is cut to the boundary's environments; secret
values are never in the record, so never in a package. With `--change` the run is recorded on the boundary
(`ciamEvidenceRun`, `cn=evidence,<boundary>`: when, each file and its hash, the queries, `--kept-at` where the package
is kept); without it nothing is written. `opsdir report evidence` lists every control and query, when each boundary
last collected it, and whether it is due. `opsdir plan` (area `Evidence`) finds, for the target: a customer or shared
control under its authorization that no query shows met (an action), a query naming no report (a blocker), a boundary
it is inside with no package or one older than its queries' smallest cadence (an action), and a control whose evidence
differs between source and target (a report with an `environment` column, the source's rows against the target's: an
action to collect it again after the cutover); the queries it can't compare are listed once as not compared.

### Secret-store inventories

What a secret store holds is recorded as observed metadata, never a value, under `ou=secret-inventory` (the pki
domain): per container (a PAM safe, a key/value mount, under `ou=<scheme>`) a `ciamSecretInventory` (`ciamInventoryAt`;
`ciamInventoryState` complete, incomplete or denied, with `ciamInventoryProblem`; `ciamInventoryPrefix` when only
part was listed) and a `ciamSecretObject` per object found (`ciamObjectState`; `ciamRotationManaged`,
`ciamRotationStatus`, `ciamManualReason`; `ciamLastRotated` only from a timestamp that means rotation;
`ciamStoreModified`, any write, never rotation; `ciamLastVerified`). The secret-store adapters' importers write them
(`cyberark/accounts`, `hashicorp-vault/kv-metadata`, and their collectors, `--inventory-container` naming containers
beyond those the references name); nothing is written onto the bindings. Each adapter's locator says where a reference
of its scheme points, and the record's secret references (`ciamRefUri` and every `ciamCopyRef`) are reconciled each
time: **present**, **deleted** (deleted, destroyed or disabled in the store), **confirmed-missing** (the container
was listed completely), **inventory-incomplete**, **inaccessible** (the store refused the listing) or
**not-inventoried**; objects nothing references are **unreferenced**. `opsdir report secret-inventory` lists every
placed reference (environment, role, reference, container, state, when inventoried, last rotated, rotate by its
credential's `ciamRotationDays`, what the store says of rotation, problems), then the unreferenced objects. `opsdir
plan` checks the target (area `Secrets`; nothing when the record holds no inventory of the target's schemes): a
reference confirmed missing or deleted is a blocker; one that can't be confirmed is an action saying what to grant or
collect; so are rotation overdue, a failed rotation, a binding saying its store rotates it (`ciamAutoRotate`) when the
store doesn't manage it, and the objects in the target's containers nothing references (one action per container);
a container whose inventory can't show rotation (Vault KV metadata) is said once.

### ITSM tickets (change evidence)

A change record names the ITSM ticket its change management tracks it by: `ciamTicketRef` `<add-on>:<number>`
(`servicenow:CHG0030101`, `jira-sm:ITOPS-42`, `bmc-helix:CRQ000000001201`), the operator's link. An ITSM add-on's
importer (`servicenow/change-requests`, `jira-sm/change-requests`, `bmc-helix/change-requests`, and their read-only
collectors) reads the linked tickets into their own entries, `ciamTicket` at `cn=<number>,ou=<add-on>, ou=tickets`
(the governance domain): the state in neutral terms (`ciamTicketState`, only when the add-on knows the ticket's state
model; `ciamTicketNativeState` keeps what the system said), the overall approval (`ciamTicketApproval`; where the
system approves by steps, as Jira Service Management and BMC Helix ITSM do, the add-on derives it from the steps' own
decisions, kept in `ciamTicketApprovalStep`), the kind of change (`ciamTicketChangeType`: standard, normal or
emergency), the planned and actual windows, each approval record as detail only (`ciamTicketApprover`, identifiers,
never names), other fields raw (`ciamTicketFact`), the system's id (`ciamProviderRef`) and address (`ciamDocUrl`). All
of it is EVIDENCE: nothing is written under
`ou=changes`, a ticket never changes a change's status or approver, and the store's rule that every write needs an
approved change record is untouched (a ticket can't authorize anything). Each import replaces only the tickets it
read; a linked ticket the export lacks is never removed. `opsdir report tickets` lists every linked change with its
drift: **in-step**, **not-imported** (while tickets of the same system were read), **rejected** or **cancelled** (ITSM
says so while the record approves the change), **unapproved** (approval still requested, or never), **closed-pending**
(ITSM closed it while the record has it proposed or approved), **live-but-rejected**, **window-differs** (the record's
planned UTC day is outside the ticket's planned window), **outside-window** (ITSM's own work times outside its
planned window, exact), **applied-outside-window** (the record's own writes under the change, as its history holds
them, landed before the ticket's planned start or after its planned end, exact; the bootstrap load and the change's own
change record don't count) and **after-read** (the ticket says work started or ended, an approval step was created or
completed, or an approver record was updated later than its export was read: evidence from after the read; planned
times never count). The report's `applied` column shows the first and last of those writes. Writes count up to the
end of the day the report or plan is run as of (`--as-of`): a plan as of a day sees the writes landed by then.
`opsdir plan` (area `Change tickets`; nothing while the record holds no ticket) blocks on rejected and cancelled and
gives the rest as actions for the change's owner (else the operator), naming only the ticket's window for
applied-outside-window, never the write times; no fix is offered: a change's status is a person's.

### Cloud-managed identity services

An environment that runs one of the platform's identity services on a cloud-managed service (a user pool, an external
tenant) records it as a `ciamManagedIdentity` binding (`ciamManagedService`: the service as the cloud's adapter names
it, in that adapter's vocabulary; `ciamRealizes`: the identity service's name; `ciamProviderRef` its resource;
`ciamFqdn` the sign-in host it serves at, a custom domain presenting `ciamTlsCertificate`): a **target**. A managed
service someone else runs that the platform federates with is a **neighbour**: `ciamPartnerOf` names the integrations
it is the partner side of, `ciamManagedBy` its keeper. Whether a binding is the issuer or the relying party is never
stored: a target issues to the `oidc-client` and `saml2-sp` integrations its identity service serves and relies on the
`saml2-idp` ones; a neighbour relies on the platform for an `oidc-client` or `saml2-sp` integration and issues to it
for a `saml2-idp` one. `opsdir report managed-identity` lists every binding that way. A binding may say where the
service keeps its users' data (`ciamDataGeography`, in the adapter's vocabulary: an external tenant's residency). A
target's own configuration that has no standard base lives beneath its binding, as the cloud's importer reads it: its
sign-in flows (`ciamSignInFlow`: `ciamFlowApplications` the integrations it signs users in to, `ciamSignInMethod`
`email-password`/`email-otp`/`sign-up`/`federated`, `ciamUpstreamProvider`, `ciamCollectedAttribute`,
`ciamFlowExtension`) and custom authentication extensions (`ciamAuthExtension`: `ciamExtensionEvent`, the
application it authenticates to its API as `ciamExtensionResource`, the claims it returns `ciamExtensionClaim`; never
its endpoint). A cloud inventory read of the binding keeps what is beneath it.

Each cloud adapter declares what its vendor documents of the services it knows (`Adapter.managed_identity`, a
`ManagedService` each: where it exists by partition, its capabilities as supported, unsupported or neither, each with
its source and date). `opsdir plan` checks the target's bindings (area `Managed identity`): a capability a served
integration needs (its protocol, grants, client authentication, DPoP, PKCE), the identity service's signing algorithms
and the hosts it publishes (its base URL and entity ID by a custom domain, its issuer by a custom issuer) are a
blocker when the vendor documents it can't, with no way out but changing the record; a capability no documentation
establishes either way is a blocker too, until the operator records the vendor's confirmation as the answer to the
unknowns-register question the finding names (`confirm-<cloud>-<env>-<binding>-<capability>`; its fix proposes the
question, blocking, owned by the integration's owners), and while that question is open the register counts it. A
service its partition doesn't have is a blocker; one on a condition (an add-on), per-application MFA it can't express,
claim transformations it can't express or expresses only on a condition (an extension), what a target in its partition
must know and how users move onto it are actions.
An identity service the target runs on a managed service is left to this check by the service-name check. A
neighbour in the target must exist there and play the part its integrations give it.

### Cloud-managed directory services

A managed Active Directory (AWS Managed Microsoft AD, Microsoft Entra Domain Services, Google Cloud's Managed Service
for Microsoft AD) is recorded as a `ciamManagedDirectory` binding (directory domain; `ciamManagedService` in its
cloud adapter's vocabulary): a **target** holds the platform's user directory there (`ciamRealizes ds`); a
**neighbour** is a directory the platform binds to or syncs from (`ciamPartnerOf` its `ldap` integrations,
`ciamManagedBy` its keeper). The binding records its domain (`ciamFqdn`, `ciamNetbiosName`), edition
(`ciamDirectoryEdition`, the adapter's vocabulary), regions (`ciamRegion`, `ciamReplicaRegion`) and domain controllers
per region (`ciamReplicaCount`), the OU the platform writes in (`ciamWritableBase`), secure LDAP (`ciamLdapsMode`
`off`/`private`/`internet`, presenting `ciamTlsCertificate`), where it is placed (`ciamSubnetRole`, a reserved range
`ciamCidr`) and the secret role of its administrator's password (`ciamCredentialRole`). Its trusts are entries beneath
it (`ciamDirectoryTrust`: the other domain `ciamFqdn`, `ciamTrustType` `forest`/`external`, `ciamTrustDirection`
`one-way-incoming`/`one-way-outgoing`/`two-way` from the managed domain's side, `ciamSelectiveAuth`, the other
domain's DNS servers `ciamForwardTarget`, its keeper). `opsdir report managed-directory` lists every binding.

Each cloud adapter declares what its vendor documents (`Adapter.managed_directory`, a `ManagedDirectory` each: what a
`ManagedService` says, read the same way (`core.managed_services`), plus limits, the editions a capability needs, the
OU the service gives the customer, and what a partition's documentation leaves open). `opsdir plan` (area `Managed
directory`) reads what the record needs of a target: a schema extension for the attribute types and object classes it
defines with OIDs of its own, fine-grained password policies for more than one policy (or one for a population),
secure LDAP (to the internet), further regions, each trust (`trust:<type>:<direction>`); a neighbour needs LDAP for its
partner integrations and its trusts. Documented unsupported blocks; not established blocks until the unknowns-register
question it names is answered (`connectors.managed_service`, shared with the managed identity check); a limit exceeded
or an edition that lacks a capability blocks. The record's base DNs moving under the writable OU (naming the consumers
whose binds or searches change), its ACIs (re-created as delegation), consumers that connect only with TLS where secure
LDAP is off, what a target in its partition must know and how users and passwords move are actions. Renders keep every
secret out of Terraform state: trusts and secure LDAP certificates are actions, and AWS's directory is a CloudFormation
stack whose administrator password is a Secrets Manager dynamic reference.

### Protected web applications (the neutral web access layer)

What an access gateway or agent protects is held in neutral terms under `ou=protected-applications` (domain
`webaccess`), whatever product enforces it:
- **Applications** (`ciamProtectedApp`) record:
  - the base path (`ciamBasePath`) and the service-name roles they are published as (`ciamPublishedAs`);
  - the server role enforcing them (`ciamEnforcedByRole`, overridable per environment);
  - the application behind a gateway (`ciamBackendRole`, port, TLS; none: an agent in the application's own web
    server);
  - how users sign in (`ciamSignOn`: oidc, token, form, basic, certificate, federated, custom, none);
  - the integration the enforcer signs users in as (`ciamSignInAs`), its identity service (`ciamServedBy`) and its
    client's secret role (`ciamCredentialRole`);
  - session idle and maximum limits;
  - the header contracts it sets (`ciamSetsHeader`) and the access rules every resource applies (`ciamRuleRef`).
- **Path resources** (`ciamPathResource`, below their application) record patterns relative to the base path, a match
  kind (prefix, wildcard with `*` across `/`, regex), methods, an access mode (standard, anonymous, unprotected), an
  order (none: most specific first) and their own rules.
- **Access rules** (`ciamAccessRule`, `ou=access-rules`) record an effect (allow, deny, or custom for a product rule
  with no neutral form), who they are about (`ciamWho`: `authenticated`, `user`, `group`, `filter`, `attribute
  <name>=<value>`, `scope`, `network`), and any or all of those and of the rules they include.

The applications' rules apply first, then the resource's; every rule must admit; a denial beats an allowance.
`opsdir report protected-applications` lists them.

Product importers project their own objects onto the layer and name the product entry (`ciamProjectedFrom`):
PingAccess applications, resources and rules; SiteMinder realms, rules and policies; PingGateway routes (each
adapter's README).
- An importer writes only what it projected. It replaces what it says, keeps what the record adds (a published or
  backend role the product can't name, owners, the credential role) and sets the enforcing role only where none is
  recorded.
- It never changes another product's projection or an operator's entry; it names the differences instead.
- A governed edit of a product entry doesn't change its projection: edit the neutral entry with it, or import again.

**Moving an application to another product**: an environment overrides `ciamEnforcedByRole` (and, for a header the
application trusts, the contract's `ciamSetByRole`, now overridable). The target's product renders the application
from the neutral layer, and the product it leaves no longer renders it there. `opsdir plan` (area `Web access`)
reports:
- a blocker for an application the source enforces whose enforcing role the target doesn't run (fixes
  `protect:<adapter>/<application>`, offered by each product the target runs);
- on a move to another product, a blocker for the service names, the application behind the gateway, and the sign-in
  integration the new product needs;
- an action for a header still set by another role (fix `enforcer-header:<contract>`).

What the new product can't express (`webaccess.express`: each product declares its capabilities as data) reaches the
plan as its render's notes. A rule it can't render is a blocker: the render would admit more than the record says.

### Certification authorities and issued certificates

The CAs the record's certificates come from are `ciamCertAuthority` entries under `ou=certificate-authorities` (cn: the
CA's name; `ciamProviderRef` how its product names it, an AD CS CA's `HOST\CA`; `ciamTemplateName` the templates it
issues from; `ciamCaCertificate`, the operator's, its own certificates in `ou=certificates`), each with its
revocation endpoints as children (`ciamRevocationEndpoint`: `ciamRevocationKind` crl, delta-crl, ocsp or ca-issuers,
`ciamEndpointUrl`, the CA's own template in `description` when a variable couldn't be filled). The hierarchy runs
certificate by certificate: `ciamIssuedBy` names the certificate of the CA that issued one. What a CA's product says of
the CA itself, when its importer reads it (cloud private CAs), is observed on the CA: `ciamCaType` (root or
subordinate), `ciamCaState` (active, disabled, pending, expired, deleted, failed), `ciamCaKeyAlgorithm`,
`ciamCaKeyStorage`, `ciamCaKeyRef` (a customer-managed signing key's name, a reference), `ciamParentAuthority`
(the CA above it) and, for a deleted CA, `ciamCaRestorableUntil` (until when its product can still restore it); the
`certificate-authorities` report shows them (state, key; issued by falls back to the parent). Templates are
`ciamCertTemplate` under `ou=certificate-templates` (display name in `description`, `ciamTemplateOid`,
`ciamMaxValidityDays`, `ciamExtendedKeyUsage`: what it issues; what it lets requesters do and who may request from
it, as its importer reads them: `ciamSubjectFromRequest`, `ciamApprovalRequired`, `ciamRequiredSignatures`,
`ciamTemplateVersion`, `ciamEnrollee` and `ciamEnrollmentScope` (broad, restricted or unknown); the operator's
`ciamCertPurpose` and `ciamRenewalOwner`: who renews what the template issues that the record holds no certificate
for). A template is either one a directory shares with every CA it serves (AD CS's forest templates, which its
importer replaces as a whole) or one CA's own (`ciamTemplateAuthority`: the CA; a Vault PKI role, cn `<CA>/<role>`),
which only that CA's importer replaces; each kind of import keeps the other's. What a CA's database says it issued is
observed
metadata, never a key, under `ou=issued-certificates`: per CA a `ciamCertInventory` (`ciamInventoryAt`,
`ciamInventoryState`, `ciamInventoryProblem`) and a `ciamIssuedCertificate` per issued or revoked certificate (cn: the
request id, or the serial for a CA that keeps none; `ciamSerialNumber`, `ciamFingerprint`, `ciamSubject`, validity,
`ciamTemplateName`, `ciamRequester`; once revoked `ciamRevokedAt`, the effective time, and `ciamRevocationReason`, the
RFC 5280 name or the CA's value). The PKI adapters' importers write them (`adcs/inventory`, `hashicorp-vault/pki`,
`ejbca/inventory`); nothing is written onto the record's certificates.

A record certificate's CA is the one listing its `ciamIssuedBy` certificate as its own, else the one whose own
certificate's subject is its `ciamIssuer`, else the one its issuer's CN names; it is found in the inventories by
SHA-256 fingerprint, else by serial number, else by subject and validity, and is **present**, **revoked**,
**revocation-scheduled** (effective after the day evaluated), **superseded** (its CA issued its subject a newer
certificate from the same template), **confirmed-missing**, **inventory-incomplete**, **inaccessible** or
**not-inventoried**; a certificate no CA is found for (public, self-signed) isn't judged. Every active certificate an
inventory holds that no record certificate matches is **untracked**. `opsdir report certificate-authorities` lists each
CA (its configuration string, who issued its own certificates, templates, endpoints, last inventory, owners); `opsdir
report issued-certificates` each judged record certificate and then every untracked one, with its renewal owner (the
record certificate's owners, else the template's `ciamRenewalOwner`). `opsdir plan` checks the whole estate (area
`Certificate`; nothing when the record holds no CA inventory): a revoked certificate the record still uses is a
blocker; one revoked but unused, revoked from a later date (an action due that day), superseded, confirmed missing or
not confirmable is an action; so is each (CA, template) whose active certificates the record holds none of, for the
templates the record cares about (a renewal owner or a purpose recorded, or a record certificate issued from it),
owned by the renewal owner and due when the first expires; and each inventoried CA that publishes no CRL or OCSP
endpoint. A certificate (not revoked or expired) whose CA, or a CA above it (`ciamParentAuthority`), its product says
isn't active (disabled, pending, expired, deleted or failed) can't be renewed there, and once a deleted or expired CA's
last CRL lapses whatever checks revocation refuses it: a blocker when the target relies on it (a binding of the target
or of a base it inherits from, or a shared entry that applies there uses it), else an action owned by who renews it
and due by the earlier of the CA's `ciamCaRestorableUntil` and the certificate's expiry; the finding names the CA's
CRL and its owner (who can restore, re-enable or activate it). An untracked set from such a CA says so too. CAs whose
product reports no state (AD CS, Vault, EJBCA) are never judged.

Template risk (`domains/pki/templates.py`, ESC1-style after the published research on certificate template abuse): a
template that takes the subject from the request, issues certificates that authenticate their holder (no extended key
usage, any purpose, client authentication, PKINIT client authentication or smart card logon), and needs no CA manager
approval or authorized signature lets whoever may enroll obtain a certificate in any account's name. `opsdir plan`
makes one a broad group may enroll from an action (area `Certificate`), as it does one whose enrollment isn't known
(collect its access rights); owned by its `ciamRenewalOwner`, else the owners of the CAs issuing from it. One only
named accounts may enroll from, or that no recorded CA issues from (where the CAs list their templates), is counted.
An exception under `ou=exceptions` accepts the finding. Any-purpose and enrollment-agent templates, who may change a
template, and the other published template weaknesses aren't judged yet.

Revocation endpoints observed (`domains/pki/revocation.py`): what each CA's CRL distribution points, delta CRLs and OCSP
responders answered when last observed is kept apart from the endpoints, under `ou=revocation-observations`: per CA a
`ciamRevocationObservation` (cn: the CA's name; `ciamInventoryAt`, `ciamInventoryState` complete when every endpoint
was observed, `ciamInventoryProblem`) and per endpoint a `ciamEndpointObservation` (cn: the endpoint's; the URL
observed; `ciamEndpointAnswer` answered, http-error, unreachable, unreadable or not-observed; `ciamThisUpdate`,
`ciamNextUpdate`, `ciamCrlNumber`, a delta's `ciamBaseCrlNumber`; `ciamSignatureCheck` valid, invalid, other-issuer,
unauthorized-responder, no-ca-certificate or unsupported, through `ciamSignedBy`, the record's CA certificate; an OCSP
responder's `ciamOcspStatus` for the certificate it was asked about, `ciamSerialNumber`). A CA-neutral adapter observes
them (`opsdir-adapter-x509`: `opsdir collect x509/revocation`, an operator-run, read-only fetch of every http(s)
endpoint whose variables were all filled, then its importer checks each answer against the CA certificates the record
holds); the core makes the requests (a collector's observing `Request`: whatever an endpoint answers, an error status
or nothing at all, is what the export keeps, never a failed collection). `opsdir report revocation-endpoints` lists
every CRL, delta CRL and OCSP endpoint of every CA with what it answered (outdated: its nextUpdate is before the day
evaluated: observe it again). `opsdir plan` (area `Certificate`; nothing when no observation is recorded) makes each
endpoint with a problem an action for the CA's owners: it couldn't be reached, answered an error or something that
isn't a CRL or OCSP response, served what the CA certificate the record holds doesn't verify (or another issuer's, or
an OCSP responder the CA didn't authorize), the record holds no CA certificate to check it with, what it served had
expired or was within `revocation-freshness-margin-hours` (an estate setting, default 12) of its nextUpdate when
observed, a CRL without nextUpdate, a delta CRL building on a newer CRL than the distribution points serve, an OCSP
responder that refused, doesn't know the certificate or contradicts the CA's inventory, or an endpoint the last
observation missed.

Certificate managers' inventories (`domains/pki/managed.py`): what a certificate manager (Venafi / CyberArk Certificate
Manager, Self-Hosted and SaaS, first; a key vault's certificates later) says it holds is recorded under `ou=managed-certificates`, metadata
only: per collection source a `ciamManagedInventory` (cn: the source's name; `ciamInventoryAt`, `ciamInventoryState`
complete, incomplete or denied for the folders it lists, `ciamInventoryPrefix`, `ciamProviderRef` the manager's
address, `ciamInventoryProblem`) and per certificate a `ciamManagedCertificate` (cn: the manager's id; serial,
`ciamFingerprint` or the SHA-1 `ciamThumbprint`, subject, issuer, validity, `ciamCertificateName` (the names it names,
wildcards kept), `ciamManagerPath`, `ciamManagement` unassigned, monitored, enrolled or provisioned, `ciamObjectState`,
`ciamManagedOrigin` discovered or added, `ciamManagerContact`, `ciamInstalledAt`, `ciamManagedAuthority`,
`ciamManagerProblem`, `ciamManagerAction` (what the manager is set to do on its own: a renewal or notification
trigger), once revoked as the manager says `ciamRevokedAt` and `ciamRevocationReason`, and for an earlier version the
manager links `ciamRenewedAs`, the cn of the certificate that replaced it). A manager is
never a CA's issuance record: it holds what it discovered, was given or enrolls, so a record certificate it doesn't hold
is **not-managed**, never confirmed missing, even when its inventory is complete. A record certificate is found by its
SHA-256 fingerprint, else by the SHA-1 thumbprint of the PEM the record holds of it, else by serial and issuer (subject
when either records no issuer), else by subject and validity, and is **managed**, **renewed** (the manager holds a newer
certificate for it that the record doesn't: exactly the one an earlier version found names (`ciamRenewedAs`), else
inferred: a newer one for the same subject and issuer), **revoked**, **disabled** (its management is) or **in-error**
(the manager reports a problem now). Certificates in service (an earlier version never is) no record certificate is
found or renewed as are **unrecorded**. `opsdir report managed-certificates` lists every record certificate with its state, how it is
managed, who is notified and where it is installed, then every unrecorded one. `opsdir plan` (area `Certificate`;
nothing when no manager inventory is recorded) blocks on a certificate the manager says was revoked that the record
still uses; the same unused, a renewal the record doesn't hold, a manager's problem, management disabled on a
certificate the record uses, unrecorded certificates for host names the record holds (a record certificate's
alternative name, a service name; owned by whoever owns the name), and an inventory incomplete or refused (what to
grant) are actions. What a CA's inventory already says of a certificate (revoked, superseded) isn't said again.

### Who keeps what, and where it renders

Infrastructure the stack doesn't keep itself names its keeper: a binding's `ciamManagedBy` (a `ciamParty`), and for what
is the landing zone's by nature (its identities and guardrails, the network's plumbing) the landing zone's owner. Each
party records whether it takes the infrastructure opsdir generates for what it keeps (`ciamTakesGeneratedInfra`, on
`ciamParty`). The default render of an environment writes:

- the stack's own root (`terraform/`);
- a complete root for each keeper that takes generated infrastructure: `terraform/landing-zone/` for the landing
  zone's owner (also when no party is recorded for it), `terraform/landing-zone/<party>/` for any other party. A
  reference from one root to another becomes an input of the root that reads it and an output of the root that
  writes it; the input says which root it comes from, applied first;
- for a keeper that doesn't (the setting absent or FALSE), nothing: one comment per entry in the stack's root names
  what they keep and its addresses, and the planner drafts the request to them (`requests/<party>.md`).

Every kept kind follows this, on every cloud: network plumbing, the landing zone, databases, object stores, volumes,
snapshot policies, backups, audit trails, monitors (alarms, log destinations, canaries), security services,
suppressions, data discovery and budgets (`opsdir.domains.governance.keepers` decides; each cloud adapter places).

### Scoped renders

A render can be asked for one slice of an environment's infrastructure, complete in its own root:

- `--keeper PARTY` (a party's cn or DN): everything that party keeps, in its root, whatever its setting says (so a
  keeper who is asked can still be handed its root);
- `--kind CLASS` (repeatable): the entries of those object classes, in `terraform/slice/`;
- `--binding DN` (repeatable): those bindings, in `terraform/slice/`.

The rest of the environment isn't written; the slice reads what it needs from it through inputs. A scoped render
holds the provider adapters' infrastructure only (no product configuration, no captured files). It is refused for a
party the record doesn't have, bindings the environment doesn't bind, or a scope that selects nothing (the refusal
lists the kinds a render places by entry, which are the ones a slice can hold).

Every render's NOTES.md and NOTES.json list what it could not do or leaves to a person: what, where (file:line), who
(the owners of what it concerns, else the environment's) and how, as a blocker, an action or a note; the files' `NOTE`
comments not yet classified are listed to review. `opsdir render` prints the counts and each blocker; `opsdir check`
lists every environment's render blockers and actions (without rendering it), and the plan raises the target's as
findings. `opsdir report canary-coverage` shows, per environment, which synthetic checks it renders and why not, and
which CA certificates a check is given to trust. An adapter that renders synthetic checks declares it
(`renders_synthetic_checks`): an environment none of whose adapters does has every canary it could run as a note of its
own. A check of a service whose certificate chains to CA certificates the record holds (`pki.chain`) is given their
recorded PEMs (`ciamCertificatePem`), added to its runtime's trust store: a CA's certificate is public material (R4
covers keys and secrets), so a CA rotation is a record change and a re-render; when none of those PEMs is recorded, the
check isn't rendered and its render note says which CA certificate to record.

Every render's MANIFEST.json records who asked (`requester`: `--as`, default the database login) and, for a scoped
render, its `scope` (kind and value). A migration's target render records them too: its scope is the whole
environment and its requester whoever runs `migrate` (`--as`).

Before a render or a migration runs, the operations layer asks an authorization policy whether the requester may do
it over that area (environment, scope, and for a migration its source), and stops with a message naming all three if
not, before the record is loaded (`operations.authorize`, `opsdir.domains.governance.authorization`). Every front end
goes through it. The default policy allows everyone; people, teams and their grants come with milestone 7.7 as the
policy it asks.


## Collecting from the live system

`opsdir collect` reads the live system for the installed adapters' importers instead of you gathering their exports,
read-only, and imports the result exactly as `opsdir import` would (preview, conflicts to take or keep, applied only
under an approved change). Each adapter declares collectors (`core.contract.Collector`): the exact calls that produce
its importers' files, in rounds (a list, then each item's details), and a check that your provider login is the
account, subscription or project the record names (nothing is read when it isn't). A collector also declares the
options it takes (`core.contract.CollectOption`: flag, metavar, help, order): `opsdir collect` offers the installed
adapters' options as its own flags (`--terraform-dir`, `--amster-key`, `--ldapsearch`, `--ldap-truststore`, `--ldap-ca`,
`--inventory-container` with today's adapters) and passes each value given, with or without `--env`; the core names none of them.

- Credentials are never stored. Clouds use your own CLI login. What needs more (a product's admin API, a directory, a
  Terraform state object) is declared per environment as a collection source (`ciamCollectionSource`: the importer,
  the URL or object, the role of the binding holding the credential's reference, the login name, the role of the CA
  certificate its endpoint is trusted by): the reference is resolved through its secret store when collecting, held
  in memory for the run, and reaches a tool only on its standard input or opsdir's own HTTP GET (`live.py`); a failing
  call's error output is shown with resolved values masked. The source's `ciamCredentialScheme` says how the GET sends
  it: `basic` (with `ciamLoginName`; the default), `bearer` (`Authorization: Bearer`), `token` (a session token a
  product's own logon issued, sent as the whole `Authorization` value: opsdir never logs on itself, a logon being a
  POST), `api-key` (the secret alone in the header the collector names, no login) or `client-certificate` (mutual
  TLS: the reference resolves to a PEM holding the client certificate, its chain and private key, loaded into the
  connection through an anonymous in-memory file, Linux memfd, never a file on disk, and presented in the TLS handshake
  with no `Authorization` header; without memfd the call fails and says why); each collector says which its API takes.
  Calls carrying provider debug switches are never run.
- A collector reads with GETs, and posts only a read-only query: a search whose criteria don't fit a URL (EJBCA's
  certificate search). It declares the URL paths it may post to (`Collector.queries`, regular expressions), and a POST
  to any other URL is refused and never made, which leaves the collection incomplete. The query's body (JSON, never a
  credential) is in the evidence beside its URL.
- A collection is complete or not imported: an import makes the record's subtrees exactly what the export holds, so a
  failed call (or a collector asking for more than 8 rounds or 2000 calls, or saying why it must stop) leaves the record as it is and says why.
- An applied collection records how it was collected on its import run (its `ciamImportRun` entry): the identity the
  provider saw, each call (command, or URL and a query's body, never a credential) with the SHA-256 of what it returned, and the
  credential references resolved. `--save DIR` also keeps the raw export and its manifest: it may hold sensitive
  configuration, keep it on encrypted storage.
- Every collection run under a change records its **attempt**, whatever the outcome (its `ciamCollectionAttempt`
  entry under `ou=imports`, one per importer and environment, replaced by the next attempt; history keeps the earlier
  ones): complete, incomplete (a call failed or was refused: nothing imported) or skipped (the identity check failed
  or the collector couldn't start), when it ran, the change, the identity seen, the calls made (each with the hash of
  what it returned, `absent` or `failed`) and the problems, credentials masked. A failed collection is never
  imported, but it is not forgotten: `opsdir report collections` lists the last attempt of each. A dry run or a run
  without `--change` records nothing (it says how many failed collections went unrecorded).
- Without `--env`, `collect` reads provider-wide data (region lists, quota limits): the same calls `import --run` makes.
- `--list` shows the calls each collector starts with and runs nothing.

### Configuration sources: Git, Kubernetes, SSH

Any importer's collection can also read configuration kept in a Git repository, a Kubernetes ConfigMap or files on a
host (PingGateway routes, PingFederate node files, DS configuration directories, crontabs, CI repositories): a
collection source for that importer whose `ciamSourceRef` names it. Each kind is read only once its estate setting
allows it; all three are off until an approved change turns them on (`opsdir setting collect-from-ssh TRUE --change
CHG-…`), and a declared source of a kind that's off makes the collection say which setting would allow it.

| `ciamSourceRef` | What runs | Becomes |
|---|---|---|
| `git+https://host/org/repo.git?ref=main&dir=gateway&prefix=routes/` (or `git+ssh://git@host/...`) | `git clone --depth 1 --single-branch [--branch REF]` into a private work directory | the files under `dir` (else all) placed under `prefix`; `.git` is never read |
| `k8s://CONTEXT/NAMESPACE/configmap/NAME?prefix=routes/` | `kubectl --context CONTEXT -n NAMESPACE get configmap NAME -o json` | each data key a file under `prefix` (Secrets are never read) |
| `k8s://CONTEXT/NAMESPACE/workloads?prefix=` | `kubectl --context CONTEXT -n NAMESPACE get statefulsets,deployments,daemonsets,cronjobs,services,ingresses,networkpolicies,serviceaccounts -o json` and `kubectl --context CONTEXT get namespace NAMESPACE -o json` | manifests (`kubernetes/workloads`): `CONTEXT/NAMESPACE/objects.json` and `namespace.json` under `prefix` (`prefix=CLOUD/ENV/` records that environment's workload bindings); Secrets are never listed, and literal env values, `managedFields` and the last-applied annotation are dropped before anything is hashed, saved or imported |
| `ssh://user@host[:port]/BASE?dir=config&match=*.json` | `ssh -o BatchMode=yes -o StrictHostKeyChecking=yes` running `find BASE/dir -type f [-name MATCH]`, then `cat --` each (`zcat --` for `.gz`, saved without `.gz`) | each file under `prefix` (default `host/`), `dir` kept in its path |
| `ssh://user@host/BASE?files=bin/run.properties,data/x.xml` | `cat --` each listed file | the same |

What they read is your own access: your Git credentials, kubectl context, SSH agent and known hosts; nothing is held.
An unknown or changed host key fails (add the host to `known_hosts` first). SSH runs only those fixed commands, on paths
that must look like paths (letters, digits, `_./@+=,:-`, no `..`) and are quoted, and hosts, users and object names
can't pose as options. A file kept that isn't regular UTF-8 text (a link, a binary) fails the collection.

## Database

One PostgreSQL server and one role, `opsdir`. For local development and tests there are four databases:

| Database | Used by | Its `opsdir` schema |
|---|---|---|
| `opsdir` | the live record for local use (`OPSDIR_DSN`, default in `scripts/dev-env.sh`) | upgraded in place by `upgrade`; `init` rebuilds it |
| `opsdir_workspace` | its migration workspace (`OPSDIR_WORKSPACE_DSN`, default in `scripts/dev-env.sh`) | rebuilt by `workspace create` and after every cutover |
| `opsdir_test` | the integration tests (`OPSDIR_TEST_DSN`) | dropped and rebuilt by every test run |
| `opsdir_test_workspace` | the workspace integration tests (`OPSDIR_TEST_WORKSPACE_DSN`) | dropped and rebuilt by every test run |

The tests never use `OPSDIR_DSN`. One-time setup (the role needs no special privileges; the password is for local development only):

```bash
sudo -u postgres psql -c "create role opsdir login password 'testpass'"
sudo -u postgres createdb -O opsdir -T template0 opsdir
sudo -u postgres createdb -O opsdir -T template0 opsdir_workspace
sudo -u postgres createdb -O opsdir -T template0 opsdir_test
sudo -u postgres createdb -O opsdir -T template0 opsdir_test_workspace
```

### Schema upgrades

- **Migrations** (`opsdir/store/sql/migrations/NNNN_name.sql`) create and change what holds data: tables, the rule functions and their triggers. Each is applied once, in order, and recorded with its checksum in `opsdir.schema_migration`. **Never edit an applied migration**; add the next number. `upgrade` refuses a database whose applied migrations were edited, that has migrations this code doesn't know, or that was created before versioning (`init` rebuilds those).
- **Definitions** (`opsdir/store/sql/definitions/`, and every domain's and connector's `sql/`) hold no data: views and report functions. Every `upgrade` drops the views and re-applies all definitions, so they are edited in place.
- Every `upgrade` also syncs the **schema registry** from the registered schema fragments (the core's, the domains' and each installed adapter's), the **reference schemes** the installed adapters own, and the **vocabulary** (below). A definition no installed part defines any more (an uninstalled adapter's) is removed; the upgrade is refused while entries still use it. Everything runs in one transaction, one upgrade at a time.

## Stacks and vocabulary

Each environment declares its **stack** under `ou=stack`: one `ciamStackComponent` per role, naming the adapter that fills it (as its package registers it), the adapter versions it accepts (a PEP 440 range) and where to get it. When an environment declares a stack, exactly those adapters render it, and rendering refuses a declared adapter that isn't installed; without one, adapters are chosen from the data (each adapter's `applies`). `opsdir check` reports, per component: not installed (and where to get it), a version outside the range, installed but not matching the environment's data, or an adapter that applies to the data but isn't declared.

Some attributes take values no core schema can list: the cloud provider, its partition, server and target roles. Their value type is `vocab`: each installed domain or adapter declares the values it defines, `upgrade` syncs them, and the store rejects any other value. Uninstalling an adapter whose values entries still use is refused at `upgrade`.

## Custom fields and record types

The record can't foresee every fact, so operators add their own as governed entries under `ou=custom-schema`: a `ciamFieldDefinition` (a field any listed record type may carry) or a `ciamRecordTypeDefinition` (a new kind of record). Names start with `x`. The metadata covers what it is and why (description, purpose, owner, sensitivity, status, documentation and runbook links), its values (type, one or many, unit, example, default, min/max, pattern, max length), which records carry it, where the value lives in real systems and which adapters use it, and its portability in a migration (and whether an environment may override it).

```bash
./opsdir.sh modify --change CHG-… define-and-use.ldif   # one change can define a field and set it on entries
./opsdir.sh report custom                               # every custom field and record type, and how many entries use it
```

The store composes the definitions into its schema in the same transaction (and on every `upgrade`), enforces the value rules on every write, and refuses a change that would leave stored entries invalid or delete a definition entries still use.

## Migration workspaces

The live record is what you operate from. To prepare a move without touching it, copy it into a workspace and declare the target there:

```bash
./opsdir.sh workspace create                               # copy the live record into the workspace
./opsdir.sh --workspace modify --change CHG-… target.ldif  # declare the target's stack and bindings (governed)
./opsdir.sh --workspace migrate CLOUD/ENV CLOUD2/ENV       # check, plan and render from the workspace
./opsdir.sh workspace status                               # what changed; did the live record move on?
./opsdir.sh workspace diff                                 # the workspace's changes as LDIF change records
./opsdir.sh workspace cutover --change CHG-…               # apply them to the live record, then re-copy
```

The workspace remembers the live snapshot it was copied from. At cutover, if the live record changed other entries meanwhile, the workspace's changes still apply (a three-way merge); if both changed the same entry, the cutover is refused and names it. The changes are applied in one transaction under the approved change, through every rule of the store.

## Imports and conflicts

An importer reads a product's export or a cloud's inventory and turns it into change records (`--dry-run` lists them and applies nothing: that is how drift is read). Adding what the record lacks, such as an entry, an attribute, a value or an object class, just goes in. An import that would replace or remove something the record holds means the live system and the record disagree. Neither side is assumed to be right. Each such disagreement is a **conflict**, listed with a key, the record's value and the live value:

```
conflict cn=key-disk,ou=bindings,env=prod,cloud=source,…|ciamAutoRotate: record TRUE -> live FALSE
```

An applied import is refused until every conflict is decided. `--take KEY` lets the live value in. `--keep KEY` keeps the record's: that change is left out, so the record still renders its own value and the next import shows the conflict again. Either flag also takes `all`.

Every applied import also records an **import run** under `ou=imports` for the scopes it read in each environment (and one for what environments share): the importer, the scopes (subtree roots, kept even when the export held nothing under one), when the export was taken (`--at`, default now) and the change. A run is named by its importer, environment and **scope set** (`cn=<adapter>.<importer>.<environment or shared>.s1-<16 hex>`: the first 16 hex digits of the SHA-256 of `s1`, a newline and the set's sorted, normalized DNs as compact JSON, so the scopes' order, case and spacing don't matter). The next import of the same set replaces its run (history keeps the earlier one); an import of another set (fewer scopes, more, others) records its own run beside it, so what an earlier import proved it read stays. A dry run records nothing. `opsdir report imports` lists each run with its set, newest export first within an importer and environment; `opsdir report import-scopes` lists the scopes of each set. Fixes that must not act on a stale picture of the live system check these runs: the newest one covering every entry the fix changes.

Runs recorded before runs were named by their scope set (by importer and environment only) are an action in the plan (`check_import_runs`, for the party operating the platform) with the fix `imports/scope-set-names`: it moves each to its scope-set name with its scopes, export time, change and evidence as they were, under an approved change (`opsdir fix propose`, then `opsdir fix approved`). Where a run already holds that set under the new name, the newer export is kept. An import of the same set does it too, under its own change.

**Firewall rules as they run.** A network-firewall add-on's importer reads a firewall manager's running configuration back (PAN-OS/Panorama first: `opsdir-adapter-panos`, importer `panos/running-config`). What a rule can hold (sources, ports, protocol, target role) is read into it, so a change made out of band is a conflict like any other; the rest is observed (infrastructure schema): `ciamRunningState` (committed on a manager, its delivery to the firewalls unconfirmed; deployed on a firewall; disabled; missing), `ciamRunningFact` (`<key> <value>`: what the record owns that the rule runs otherwise, such as `action deny` or `log-end no`, and the network team's settings that limit what it admits, such as `negate-source yes`), `ciamUnrecordedRule` on the appliance (rules carrying the environment's marker that the record lacks, unmarked allows to its servers), and an external allowlist's `ciamRecordedCidr` when its `ciamAllowlistRef` names an object the read holds (its request status stays a person's). `opsdir report firewall-running` lists them; the planner's `check_firewall_running` makes each an action for the source and the target (nothing when nothing was read back).

## Assisted fixes

When a planner check knows the exact record change that resolves a finding, the finding offers it as a fix: the LDIF change records, the steps outside the record that go with it (a deploy, a live change, a party's confirmation) and what applying it could hide. `PLAN.md` lists the fixes offered; nothing is applied without a change.

```bash
opsdir fix list FROM TO                          # the fixes the plan offers
opsdir fix show FROM TO KEY                      # one fix: change records, manual steps, risks
opsdir fix propose FROM TO KEY --change CHG-… [--option O] [--input K=V …]   # record it as a proposed change, for a person to approve
opsdir fix apply FROM TO KEY --change CHG-… [--option O] [--input K=V …]     # apply it under an approved change
opsdir fix approved --change CHG-…               # once a proposed change is approved: apply its records, mark it applied
```

The fixes offered so far, each the exact record change for its finding:

| Finding | Fix |
|---|---|
| A service name changes between the environments (R9) | the target binds the stable name (and its zone) |
| Server roles can't reach each other's ports in the target (ports matrix) | exactly the uncovered ranges, on the matching firewall rule or a new one |
| A product isn't told about the target's explicit egress proxy | the captured file's settings, linked to the proxy binding's derived values |
| The target's directory servers don't join the source's replication | `ciamJoinsDeploymentOf` on the target environment |
| Private DNS, endpoint-service principals (same provider), flow-log or log-route retention, metadata tokens, compute group size weaker in the target | the source's (or the obligation's) value on the target binding |
| A firewall rule opens ports nothing listens on | the stray ports dropped (the rule deleted when all are) |
| An endpoint service anyone may connect to unaccepted | acceptance required |
| A private endpoint reaches a role its environment doesn't bind | that role dropped from it |

Some fixes are a choice, and offer options instead of one change (`fix show` lists them; `propose` and `apply` need `--option`): the secret role a withheld credential comes from (PingFederate data stores, plugins, resources and nodes; PingIDM connectors: one option per secret role the target binds, those whose name matches the object's first, never picked for anyone), which entry keeps a PingFederate id several claim, and an override that makes the environments differ (run the source's value, or the shared one; only the target's own overrides are changed, an inherited one gets a target override instead).

Some fixes take inputs: values only the operator knows, such as a provider reference, a DNS name or a bucket. `fix show` shows each input in the records as `<key>` and lists it with an example (the source's value, where there is one), any default, and the pattern its values must match. `propose` and `apply` refuse until every input without a default is given with `--input KEY=VALUE`. Repeat a key to give it several values; `KEY=` leaves the attribute out. An input is a reference or a name, never a secret, and the proposal holds the records with the values filled in.

| Finding | Fix (inputs) |
|---|---|
| A role the source binds isn't bound in the target | the source's bindings of the role copied under the target's bindings. Intent and meta values are copied. Binding and secret-reference values, and DNs inside the source environment, are inputs (the source's value as the example, never as a default: copied, it would point at the source's resources). Contract values, and references to something outside the environment (a consumer), default to the source's. Dates and observed facts are left out. With several bindings of the role, each input's key starts with the binding's name (`backup-a.ciamStorageRef`). |
| A product reaches a fixed host from every environment (a PingFederate data store with one host, a PingIDM connector's `host`, a PingGateway route's base URI) | the host recorded as the source's `ciamExternalHost` (a system the platform reaches but doesn't run) of a role the operator gives (`role`, never guessed; the port too for a route). Importing the product again names the role instead of the host, and the target then gets the core's binding fix for the role |
| PingFederate's cluster discovery isn't recorded, uses a protocol the adapter doesn't render, or lacks what its protocol needs | the `pf-cluster-discovery` binding: an option per rendered protocol (the source's: the one its nodes run, when they all agree). NATIVE_S3_PING takes the bucket (`ciamStorageRef`, `s3://…`) and DNS_PING the DNS name (`ciamFqdn`); TCPPING takes nothing. A binding of another class (an object store) is replaced by a `pingfedClusterDiscovery` binding of the same name. |

Some fixes wait for something to happen first, and `fix show` lists it under "First". Pinning firewall priorities is one: rules a provider orders by number (Azure network security groups, Google Cloud firewall rules and policy rules) render a free slot when they have no pinned `ciamRulePriority`. A slot free in the record may already be held by a live rule the record lacks. So the planner's action for unpinned rules offers a fix (`priorities:<environment>`) that pins the slots the render assigns, but `propose` and `apply` refuse it until an import run covers those rules from an export taken after their last change. Changes under `BOOTSTRAP` don't count, and neither do changes made by that import itself. The refusal says what to import.

Some fixes change the record ahead of the live system. The record then says something the live system doesn't do yet, so such a fix also marks the value as awaiting verification (`ciamVerifyPending`: the attribute, and the adapter whose import confirms it). The check that offered the fix keeps reporting the value until an import by that adapter covers the entry. If the live value matches, the import clears the mark. If it differs, that's a conflict: taking the live value clears the mark, and keeping the record's leaves it. The first such fix lowers a changing name's TTL in the source to 60 s (`ttl:<name>`).

Proposing writes only the change record (status `proposed`, its records in `ciamChangeRecords`), which is what an AI may do through the operations layer; the store refuses the records themselves under a change nobody approved. With `--workspace` the fixes are the workspace's and reach the live record at cutover. Fixes never carry secret values, never edit observed facts or attestations (grants read from a cloud, test results, review dates), and a fix to a captured file links its settings to bindings (`ciamValueFrom`), since the file is shared by every environment with the role.

## Architecture

```
opsdir/                      the package (names no platform, product, vendor or secret store)
  core/                      technology-neutral records and pure functions: directory snapshot and lookups, RFC 4515
                             search, environment model (bindings by role, declared stack), contracts (Domain,
                             Adapter, Report, Services, PlanContext), the standard (value types, OID arc, schema
                             fragments), the standard LDAP schema (ldap_schema: RFC 4519/4524/2798/... definitions,
                             the one source for both opsdir's schema and the user directories it manages),
                             findings, manifest, change sets, interchange (LDIF, RFC 4512, export)
  store/                     PostgreSQL: postgres.py (connect, load, governed changes, snapshot read), migrations.py
                             (init, upgrade), workspace.py (workspace base), queries.py, sql/migrations, sql/definitions
  domains/                   vendor-neutral parts of the stack, each with naming, schema fragment, checks, reports and
    infrastructure/          SQL views: clouds, environments, servers, bindings, stacks, external allowlists
    directory/               the LDAP user directory: its schema (attributes and object classes, standard or
                             defined in the record), declared/observed configuration and drift, consumers, ACIs,
                             cloud-managed directories (ciamManagedDirectory: target or neighbour; managed.py)
    federation/              SAML/OIDC integrations and claim maps, the platform's own identity services, the
                             protocols' standard vocabulary (grant types, auth methods, bindings, NameID formats), and
                             cloud-managed identity services (ciamManagedIdentity: target or neighbour; managed.py)
    pki/                     certificates and their expiry
    governance/              owners (including the operator), changes, incidents, runbooks, keepers (who keeps an
                             entry and which root it renders in, scopes), authorization (the policy asked first)
    configuration/           config files held setting by setting, bundles, the string census
    automation/              jobs: cron, timers, scheduled tasks, functions, pipelines (what runs, when, where, owner)
    compute/                 host baselines per server role, compute groups, clusters and workload bindings per environment, workloads
                             (server roles run as containers)
    messaging/               external services (mail relays, SMS, MFA vendors, CAPTCHA), mail senders and sending
                             identities, identity event streams
    custom/                  fields and record types operators define as entries, composed into the store's schema
  connectors/                the only code that joins parts: registry (discovers domains and adapters through entry
                             points), schema (the store's schema: code fragments + the record's custom definitions),
                             stack (declared stacks vs installed adapters), render, plan (migration planner),
                             migration (runner), workspace (copy, diff, cutover), reports, collecting (live
                             read-only collection: rounds, completeness, evidence), sql (cross-domain views)
  live.py                    the effects of collecting: provider commands, HTTP GETs and read-only query POSTs,
                             credentials resolved in memory
  cli.py                     thin orchestrator
schema/ciam-ops.schema.ldif  the published RFC 4512 schema of the core and its domains (scripts/gen-schema.py)
scripts/                     dev-install.sh, dev-env.sh (local defaults), gen-schema.py, test.sh, fetch-tools.sh,
                             validate-terraform.sh, validate-kubernetes.sh
tests/                       core tests: unit (no database) and integration; mini_estate.py = a two-environment
                             estate and a fake provider adapter, so the core is tested without any real adapter
```

Dependencies point one way. Adapter packages depend on the core, never the reverse; the registry discovers them. Inside the core, `connectors → domains → core` and `connectors → store → core`; domains depend on `core` only (their reports are data: SQL text or a pure function of the snapshot). The code is Modular, Functional and Procedural: immutable records, pure functions, effects (database, files, printing) at the edges.

## Writing an adapter package

An adapter is one cloud provider, product or secret store. It lives in its own installable package:

1. A module that defines `ADAPTER = Adapter(...)` (`opsdir.core.contract`): its name and kind (`provider`, `platform` (a container platform such as Kubernetes), `product`, `host`, `delivery`, `secret-store`, `pki` (a certification authority's records, such as AD CS), `compliance` or `itsm` (an IT service management system whose change tickets are read as evidence)), `applies(m)` decided from directory data only (or `None` for a generic adapter of a standard, which every compliant server would match: it renders only where an environment's stack declares it), the roles it requires, its renderers (environment-neutral and environment-specific), its planner checks, the reference schemes it owns and their resolvers, how its outputs are described, and the `vocab` values it defines.
2. Its `pyproject.toml` depends on `opsdir` and registers it:

   ```toml
   [project.entry-points."opsdir.adapters"]
   example = "opsdir_adapter_example.adapter:ADAPTER"
   ```
3. Tests in the package's `tests/` (the repository-root `pytest.ini` collects them).
4. The format of every file it renders, `formats=(("ds/*.ldif", "ldif"), ...)`, and the product versions it supports, `products=(("SomeProduct", ">=7,<9"),)`, with what changes between them, `version_changes=(VersionChange(">=8.0", "what changed", "what it affects", "blocker", "the fix", touches),)` (the planner names the ones a move's upgrade crosses that apply to the record). When one of its importers reads what it renders, it says which files: `reads_back=(ReadBack("importer", "prefix/*", "prefix/"),)` (`place="{environment}/"` for an importer reading an environment's files from its `<cloud>/<env>/` folder, `opsdir.core.environment.environment_at`; `optional=True` for files rendered only for some environments; `prepare=` when the importer reads something built from the render, a cloud's Terraform state; `intent=True` when the render is the record's intent, so the guarantee is no copies and a fixed point, `roundtrip.fixed_point`), and its tests check with `opsdir.connectors.roundtrip.read_back` that reading its own render back changes nothing. A format the core doesn't register (a product's own syntax, HCL, ...) is registered by the package that brings it, as a `Format` (`opsdir.core.contract`) under `[project.entry-points."opsdir.formats"]`. For workloads on Kubernetes, a provider adapter says how a service account assumes its cloud's identity (`workload_identity(m, identity binding) -> K8sIdentity`) and an adapter owning a reference scheme how the External Secrets Operator and the Secrets Store CSI driver read it (`secret_delivery={scheme: SecretDelivery}`); renderers reach them, and the products' listeners, through `Services`.
5. Optionally, schema definitions of its own: `schema=fragment(attributes, classes, arc, origin)` (`opsdir.core.standard`), numbered under an OID arc the package owns, so packages written independently never collide. The store composes them on `upgrade`; the core's published schema file holds only the core and its domains.
6. Shared helpers instead of its own copies. Before writing a helper, look for it in the core:

   | Need | Use |
   |---|---|
   | Parse an imported file without raising (a file that isn't the format is named, not an error) | `opsdir.core.sources`: `json_document(text, kind)`, `parsed(loader, text, errors, kind)` for any other parser (a YAML loader: the core depends on none) |
   | Parse an imported XML file, refusing a DOCTYPE or entity declaration | `opsdir.core.sources`: `xml_document(text)` -> `(root, None)` or `(None, why not)` |
   | An import's files by folder (one per server, repository, project) | `opsdir.core.sources`: `by_folder(files)`, `folders(files, roots)`, `under(files, root)` |
   | A collector's earlier outputs as its steps name them (the environment's `<cloud>/<env>/` folder taken off, its own work files kept) | `opsdir.core.sources`: `env_relative(m, files)` |
   | What fronts a service name on a cloud: a note (role only on Kubernetes without a gateway, exposure not recorded), its cluster's gateway, or its role's servers and their subnets | `opsdir.domains.edge.gateways`: `front_choice(m, svc)` |
   | A container entry, a DN's RDN value, a DN at or below a base | `opsdir.core.directory`: `ou_entry(dn)`, `rdn_of(dn)`, `within(dn, base)` |
   | Times as the record holds them (GeneralizedTime, UTC) | `opsdir.core.directory`: `gtime(datetime)`, `gtime_of_iso(text)` |
   | JSON written as files, JSON an attribute holds, values that may be secret | `opsdir.core.jsondata`: `indented`, `canonical`, `held_json(entry, attr)`, `without_secrets`, `with_values`, `rendered_in_place` |
   | YAML written as files (manifests, Helm values, kustomizations): deterministic block style, strings quoted where any YAML reader could take them for something else | `opsdir.core.interchange.yaml_text`: `dump(value)`, `documents(values)` (the registered `yaml` format writes with `dump`; the core reads no YAML) |
   | Entries an importer re-imports (owned attributes replaced, the rest kept) | `opsdir.core.directory`: `merged_attrs(existing, owned, names)` |
   | A product's config file kept as captured settings | `opsdir.domains.configuration.record`: `captured_file(fmt, prefix, folder, path, text, patterns, role)` |
   | Cloud inventory: resources, role tags, role map, layout | `opsdir.core.inventory`: `resource`, `tagged_role(tags)`, `of_types(found, *types)`, `layout_import` (provider `None`: a source beside the clouds, such as a SIEM, read into any environment), `read_together`, `merge_reads` |
   | Log shipments a provider adapter ships itself; detections a SIEM renders and their condition | `opsdir.domains.observability.sources.own_shipments(m, found, services.siem_keeper, "<adapter>")` (leaves a SIEM index another adapter keeps to it); `opsdir.domains.observability.alarms`: `alarm_specs(m)` (detections left out), `detection_specs(m)`, `detection_condition(rule)` (a count per window, `gt`/`ge`, every window of the period breaching); `opsdir.domains.observability.siem`: `described(rule)` / `realized_in(description)` (a rendered detection's description, read back) |
   | Another product's roles (its server roles, keystore, service name, cluster discovery), for a kit deploying it: by product, never by name | the product's adapter declares `roles=(("server", ("am",)), ("keystore", ("am-keystore",)))` (kinds: `opsdir.core.contract.ROLE_KINDS`); a kit reads `opsdir.core.environment.roles_for(m, "PingAM", "server")` (models from `connectors.registry.environment` carry them; `product_roles(adapters)` and `with_product_roles(m, roles)` attach them to one built otherwise) |
   | A run-time option a collector takes (`opsdir collect --FLAG VALUE`) | `Collector(..., options=(CollectOption("--flag", "METAVAR", "help", order),))` (`opsdir.core.contract`); the collector reads the value as `options["flag"]` (dashes as underscores: `connectors.registry.option_key`). An option several adapters read is declared once by the library that reads it and reused (`opsdir_format_terraform.state.TERRAFORM_DIR`, `opsdir_base_ds.collect.LDAPSEARCH` / `LDAP_TRUSTSTORE`); two different declarations of one flag are refused when the registry loads |
   | What a kit's chart answers for a product's cluster discovery, for the product's own check | the kit declares `cluster_discovery=` a callable `(EnvModel) -> (DiscoveryAnswer(product, namespace, DNS name, kit, setting), ...)` (`opsdir.core.contract`); the product's check reads `opsdir.core.environment.discovery_answers(m, product)` (models from `connectors.registry.environment` carry them; `with_cluster_discovery(m, adapters)` attaches them to one built otherwise) |
   | A kit's logs derived from its products' declared ones | `logs=` a callable `(installed adapters' LogSources, product roles) -> LogSources`, resolved once when the registry loads the adapters (`opsdir.connectors.registry.resolved_logs`); at render, `Services.installed_logs` holds every installed adapter's |
   | CI pipelines as jobs | `opsdir.domains.automation.pipelines`: `FoundPipeline`, `ReadRepository` (a repository the import read, for removing what it no longer defines), `pipeline_groups(d, pipelines, read)` (groups and removal notices), `gone_pipelines`, `environment_name` |
   | A planner check's findings, with its one line saying all it looked at holds when nothing is a blocker or an action | `opsdir.core.findings`: `all_clear(parts, ok_line)`, `each_checked(items, judge, ok_line)` (no findings when there are no items) |
   | The binding of the role an entry's attribute names (where findings or results go, the channel a budget alerts, a backup vault, a snapshot policy, a login secret) | `opsdir.core.environment.role_named(m, entry, "ciamFindingsRole")`: the environment's binding of that role, or `None` when the entry names none or the environment binds none |
   | The system boundaries an environment is inside; the control responsibilities recorded under an authorization | `opsdir.domains.estate.authorizations`: `boundaries_holding(d, env_dn)`, `responsibilities_under(d, auth)` |
   | The controls the operator must show met under the authorizations environments rely on; a table as evidence (cut to environments, CSV, JSON) and a text's SHA-256 | `opsdir.domains.estate.evidence`: `controls_covered(d, env_dns)`, `scoped_rows(headers, rows, labels)`, `table_csv(headers, rows)`, `table_json(headers, rows)`, `sha256(text)` |
   | What a firewall manager's running configuration, read back, shows beyond a rule's own attributes (its state and facts, the appliance's unrecorded rules, an external allowlist's addresses) | `opsdir.domains.infrastructure.running`: `observed_rule(e, state, facts)`, `observed_appliance(a, unrecorded)`, `allowlist_refs(d, adapter)` (the allowlists an adapter's importer reads, with the path after `<adapter>:`), `recorded_allowlist(xa, cidrs)`, `running_facts(e)` (owned, access); the vocabulary in `opsdir.domains.infrastructure.naming` (`RUNNING_STATES`, `OWNED_FACTS`, `ACCESS_FACTS`) |
   | Who keeps an entry the stack doesn't (the party `ciamManagedBy` names) | `opsdir.domains.governance.keepers`: `managed_by(d, e)` (the party entry or `None`), `managed_by_name(d, e, default)` (its name as reports show it); `keeper(m, e)` for where its keeper's root is |
   | How long a destination keeps what it is sent, and a report's yes/no | `opsdir.domains.observability.retention`: `retention_days(b)` (searchable), `total_days(b)` (in all: `ciamTotalRetentionDays`, else `retention_days`), `days_text(days)` (a report's cell: `forever` for `INDEFINITE`), `longest_retention(days)`, `INDEFINITE` (forever), `yes_no(e, attr)` |
   | A secret store's inventory (what a safe or mount holds, metadata only) and where a reference points in it | the adapter declares `inventory_locator={"scheme": locate}` (`locate(rest) -> (container, object)` or `None`); its importer builds entries with `opsdir.domains.pki.inventory`: `inventory_entry(d, scheme, container, at, state, problems, prefixes, endpoint)`, `object_entry(d, scheme, container, name, facts)`, `inventory_group(inventory, objects)`; its collector lists `wanted_containers(d, scheme, locate, options.get("inventory_container"))` and declares the shared `CONTAINER_OPTION` (`--inventory-container`) |
   | Send a collection source's credential the way its API takes it | `Request(url, headers, credential, ca)` with `credential` `(s.scheme, s.credential, s.login)` for `basic`, `bearer` and `token` (the whole `Authorization` value: a session token obtained outside opsdir), `("headers", ref, login, (login header, secret header))`, or `("api-key", ref, None, "X-PAN-KEY")` (the secret alone in the header named), or `("client-certificate", ref, None)` (mutual TLS: the PEM loaded in memory, no header) |
   | What a source product holds with no standard equivalent, carried for the plan; planner checks for a product only a migration's source runs | `opsdir.domains.governance.source_objects`: `source_objects(d)`, `check_source_objects(ctx)`, `source_object_rows(d)`; the vocabulary `opsdir.domains.governance.schema.HANDLINGS`, the branch `opsdir.domains.governance.naming.SOURCE_OBJECTS` (an importer's own below it); the adapter declares `source_checks=` (`opsdir.core.contract.Adapter`: run when it applies to the source) |
   | A cloud-managed identity service: what its vendor documents, whether a binding is a target or a neighbour, whom it issues to and relies on | the cloud adapter declares `managed_identity=(ManagedService(...),)` (`opsdir.core.contract`: `name` (its `ciamManagedService` value, also in the adapter's vocabulary), `title`, `partition(m)`, `available` / `absent` by partition, `supported` / `unsupported` / `partition_unsupported` capabilities each with its source, `conditions`, `notes`, `users`); `opsdir.domains.federation.managed`: `managed_identities(m)`, `is_target(b)`, `realized_service(d, b)`, `realizing(m, service)`, `partners(d, b)`, `roles(d, b)` (issuer to, relying party of), `integration_needs(i, as_partner)`, `service_needs(service)`, `status(spec, partition, capability)`, `availability(spec, partition)`, `words(capability)`; the planner's check is `opsdir.connectors.managed_identity` (`question_name(m, b, capability)`: the unknowns-register question that confirms a capability no documentation establishes) |
   | SIEM indexes and the detections searching them; which adapter keeps a SIEM index | `opsdir.domains.observability.siem`: `SIEM_INDEX`, `is_siem(b)`, `siem_destinations(m)`, `detections(m)`, `detection_index(m, b)`, `detection_for(m, rule)`; a SIEM adapter declares `siem_indexes=` `(EnvModel, destination) -> bool` (`opsdir.core.contract.Adapter`), and a provider adapter leaves a destination another adapter keeps to it: `Services.siem_keeper(m, destination)` (the keeper's name, or `None`) |

   Anything two packages would write alike belongs in the core (or an `opsdir-base-*` library), public and tested. Module-level tables are read-only (`MappingProxyType`, tuples, `frozenset`).

Installing the package is all it takes: nothing in the core changes. Products build on the standard bases rather than repeat them: a directory adapter renders the standard LDAP files (`opsdir-adapter-ldap`) and a DS-lineage product the lineage's files (`opsdir-base-ds`); a federation adapter renders SAML metadata and OIDC documents at its own endpoint paths (`opsdir-base-saml`, `opsdir-base-oidc`) and maps the standard vocabulary to its API's names. Packages that register an adapter are named `opsdir-adapter-*`, libraries `opsdir-base-*`, formatters `opsdir-format-*`. A new vendor-neutral part of the stack is added the same way as a `Domain` (schema fragment with new, never-reused OID numbers, SQL views, checks, reports, vocabulary, an `order`), registered under `[project.entry-points."opsdir.domains"]`.

## Tests

From the repository root (one `pytest.ini` collects the core, every package and the showcase):

```bash
opsdir/scripts/test.sh                                   # everything: unit + integration, databases required
opsdir/.venv/bin/python -m pytest                        # unit tests only, no database
opsdir/.venv/bin/python -m pytest -m integration         # integration tests only (skipped if unreachable)
opsdir/.venv/bin/python -m pytest opsdir/tests           # the core alone
opsdir/scripts/fetch-tools.sh                            # once: Terraform, Helm, Kustomize, kubeconform into tools/, verified
opsdir/.venv/bin/python -m pytest -m terraform           # rendered Terraform checked by terraform fmt + validate
opsdir/scripts/validate-terraform.sh [tree ...]          # the same on any render output (default: the golden renders)
packages/opsdir-adapter-forgeops/scripts/fetch-forgeops.sh   # once: the pinned ForgeOps release into tools/forgeops/, verified
packages/opsdir-adapter-ping-devops/scripts/fetch-ping-devops.sh   # once: the pinned ping-devops chart into tools/ping-devops/, verified
opsdir/.venv/bin/python -m pytest -m kubernetes          # rendered Kubernetes output checked by kustomize, helm, kubeconform
opsdir/.venv/bin/python -m pytest -m ansible             # rendered Ansible checked by ansible-inventory, --syntax-check, ansible-lint
opsdir/scripts/validate-kubernetes.sh [--helm CHART VALUES]... [tree ...]   # the same on any render output
opsdir/scripts/validate-ansible.sh tree [tree ...]                         # every ansible/ folder in the trees
```

Line length is the one lint rule: no line of the repository's Python over 120 characters (`ruff.toml` at the root, E501 only; the layout is the code's own, never `ruff format`). `opsdir/tests/unit/test_line_length.py` runs the `ruff` the `test` extras pin, so the default `pytest` run and `scripts/test.sh` enforce it; `opsdir/.venv/bin/ruff check .` lists offenders.

`PYTHONPATH` comes before the venv's own packages, so a folder a shell exports there would shadow them: another version than the packages require, or a dependency the venv lacks found there by luck. `scripts/dev-install.sh` installs with it unset, and `scripts/test.sh`, `opsdir.sh`, the showcase's `demo.sh` and `scripts/snapshot-outputs.sh` run with it unset; run pytest the same way when your shell sets it: `env -u PYTHONPATH opsdir/.venv/bin/python -m pytest`.

Third-party tools the tests run on rendered output live in `tools/` at the repository root: one gitignored folder per machine, fetched by `scripts/fetch-tools.sh` (Terraform's zip checked against HashiCorp's signed checksums; Helm 4.3.0, Kustomize 5.8.2 and kubeconform 0.8.0 checked against SHA-256 digests pinned in the script, Linux amd64 and arm64) and removed by deleting it. `scripts/validate-kubernetes.sh` builds every kustomization, renders each chart given with its values file, and checks the result and every other manifest with kubeconform `-strict` against the Kubernetes schemas (default 1.36.0, `KUBERNETES_VERSION` to change) and, for custom resources, the CRDs-catalog at a pinned commit; a resource no schema describes fails, it is never passed. Schemas are cached in `tools/kubeconform-cache`. Given no folder and no chart, it checks the showcase's golden renders' `kubernetes/` folders; a deployment kit's output needs the kit's charts and bases, which the kit's own tests and the showcase's `tests/kubernetes/` fetch and use (`packages/opsdir-adapter-forgeops/scripts/fetch-forgeops.sh`, `packages/opsdir-adapter-ping-devops/scripts/fetch-ping-devops.sh`). The `kubernetes` tests (`tests/tools/`, the kit packages', the showcase's) are skipped without the tools. The `terraform` tests check every Terraform root of the showcase's golden renders and a sample with every kind of network plumbing on each cloud (`examples/showcase/tests/terraform/`); they are skipped when `tools/bin/terraform` is absent and run by `scripts/test.sh` when it is there (the first run downloads the providers into `tools/`).

The core's tests use a mini estate and a fake adapter, and pass with no adapter package installed. The integration tests create, upgrade and refuse schemas against Postgres (they drop and rebuild the `opsdir` schema in the test databases). End-to-end behaviour with real adapters and golden outputs is tested by the showcase.
